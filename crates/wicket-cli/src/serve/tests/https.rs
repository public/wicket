//! The console's own HTTPS: protocol and cipher policy, HSTS, certificate files, TLS-ALPN-01, and a
//! whole ACME order against a mock CA (no real ACME server is contacted).

use super::*;
use crate::serve::acme::{self, AcmeConfig, HttpFactory};
use crate::serve::tls::{self as wtls, CertResolver, FileCert, ACME_TLS_ALPN};
use http_body_util::BodyExt;
use instant_acme::{BodyWrapper, BytesResponse, HttpClient};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::future::Future;
use std::pin::Pin;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn ring() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A self-signed certificate for `name`: (chain PEM, key PEM, DER).
fn self_signed(name: &str) -> (String, String, CertificateDer<'static>) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec![name.to_string()]).unwrap().self_signed(&key).unwrap();
    (cert.pem(), key.serialize_pem(), cert.der().clone())
}

fn tmpdir(tag: &str) -> TmpDir {
    TmpDir::new(&format!("wicket-tls-{tag}"))
}

/// Serves the console over TLS on a free loopback port, as `https://localhost:PORT`; the console's
/// directory lives as long as the returned guard.
async fn start_tls(tag: &str, resolver: Arc<CertResolver>, acme: bool) -> (SocketAddr, TmpDir) {
    let mut t = setup(tag);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    t.state.rp.origin = format!("https://localhost:{}", addr.port());
    t.state.authority = format!("localhost:{}", addr.port());
    t.state.hsts = true;
    t.state.limits.conn_lifetime = Duration::from_secs(2);
    let acceptor = tokio_rustls::TlsAcceptor::from(wtls::server_config(resolver, acme).unwrap());
    tokio::spawn(net::run(listener, Some(acceptor), Arc::new(t.state)));
    (addr, t._tmp)
}

fn client(roots: &[CertificateDer<'static>], versions: &[&'static rustls::SupportedProtocolVersion], alpn: &[&[u8]]) -> Arc<ClientConfig> {
    let mut store = RootCertStore::empty();
    for r in roots {
        store.add(r.clone()).unwrap();
    }
    let mut c = ClientConfig::builder_with_provider(ring())
        .with_protocol_versions(versions)
        .unwrap()
        .with_root_certificates(store)
        .with_no_client_auth();
    c.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    Arc::new(c)
}

/// Accepts any server certificate and keeps it (what an ACME validator does with the challenge).
#[derive(Debug, Default)]
struct Grab(Mutex<Option<Vec<u8>>>);

impl ServerCertVerifier for Grab {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.0.lock().unwrap() = Some(end_entity.to_vec());
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &ring().signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // By the raw key: webpki won't parse a certificate with the critical acmeIdentifier
        // extension, which real validators (and browsers never shown it) don't mind.
        let (_, cert) = x509_parser::parse_x509_certificate(c.as_ref()).map_err(|e| rustls::Error::General(e.to_string()))?;
        let spki = rustls::pki_types::SubjectPublicKeyInfoDer::from(cert.tbs_certificate.subject_pki.raw);
        rustls::crypto::verify_tls13_signature_with_raw_key(m, &spki, d, &ring().signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        ring().signature_verification_algorithms.supported_schemes()
    }
}

/// What an ACME validator sees: a TLS-ALPN-01 handshake to `addr` for `name`. Returns the
/// certificate presented, or None if the handshake failed; and whether HTTP got any answer.
async fn alpn_probe(addr: SocketAddr, name: &str) -> (Option<Vec<u8>>, String) {
    let grab = Arc::new(Grab::default());
    let mut c = ClientConfig::builder_with_provider(ring())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(grab.clone())
        .with_no_client_auth();
    c.alpn_protocols = vec![ACME_TLS_ALPN.to_vec()];
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let Ok(mut s) = tokio_rustls::TlsConnector::from(Arc::new(c)).connect(ServerName::try_from(name.to_string()).unwrap(), tcp).await
    else {
        return (None, String::new());
    };
    assert_eq!(s.get_ref().1.alpn_protocol(), Some(ACME_TLS_ALPN));
    let _ = s.write_all(b"GET / HTTP/1.1\r\nhost: localhost\r\n\r\n").await;
    let out = read_all(&mut s).await;
    let cert = grab.0.lock().unwrap().clone();
    (cert, out)
}

async fn read_all<S: tokio::io::AsyncRead + Unpin>(s: &mut S) -> String {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => out.extend_from_slice(&buf[..n]),
            _ => break,
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// GET / over TLS; returns the negotiated version, cipher suite and ALPN, and the response.
async fn https_get(
    addr: SocketAddr,
    cfg: Arc<ClientConfig>,
) -> Result<(rustls::ProtocolVersion, rustls::CipherSuite, Option<Vec<u8>>, String), std::io::Error> {
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let mut s = tokio_rustls::TlsConnector::from(cfg).connect(ServerName::try_from("localhost").unwrap(), tcp).await?;
    let (version, suite, alpn) = {
        let c = s.get_ref().1;
        (c.protocol_version().unwrap(), c.negotiated_cipher_suite().unwrap().suite(), c.alpn_protocol().map(|a| a.to_vec()))
    };
    s.write_all(format!("GET / HTTP/1.1\r\nhost: localhost:{}\r\nconnection: close\r\n\r\n", addr.port()).as_bytes()).await?;
    Ok((version, suite, alpn, read_all(&mut s).await))
}

/// The acmeIdentifier extension's value, if the certificate has it critical.
fn acme_identifier(der: &[u8]) -> Option<Vec<u8>> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let ext = cert.extensions().iter().find(|e| e.oid.to_id_string() == "1.3.6.1.5.5.7.1.31")?;
    assert!(ext.critical, "acmeIdentifier must be critical");
    // An OCTET STRING of the 32-byte digest.
    (ext.value.len() == 34 && ext.value[..2] == [0x04, 0x20]).then(|| ext.value[2..].to_vec())
}

#[tokio::test]
async fn https_uses_tls13_or_strong_tls12_http1_only_and_sends_hsts() {
    let (chain, key, der) = self_signed("localhost");
    let resolver = Arc::new(CertResolver::default());
    resolver.set(Arc::new(wtls::certified_key_from_pem(chain.as_bytes(), key.as_bytes()).unwrap()));
    let (addr, _tmp) = start_tls("https", resolver, false).await;
    let roots = [der];
    let (v, _, alpn, out) =
        https_get(addr, client(&roots, &[&rustls::version::TLS13, &rustls::version::TLS12], &[b"h2", b"http/1.1"])).await.unwrap();
    assert_eq!((v, alpn.as_deref()), (rustls::ProtocolVersion::TLSv1_3, Some(&b"http/1.1"[..])), "h2 is not offered");
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    assert!(out.contains(&format!("strict-transport-security: {}", web::HSTS)), "{out}");
    // TLS 1.2 is ECDHE with AEAD.
    let (v, suite, _, out) = https_get(addr, client(&roots, &[&rustls::version::TLS12], &[])).await.unwrap();
    assert_eq!(v, rustls::ProtocolVersion::TLSv1_2);
    let name = format!("{suite:?}");
    assert!(name.starts_with("TLS_ECDHE_") && (name.contains("_GCM_") || name.contains("CHACHA20")), "{name}");
    assert!(out.starts_with("HTTP/1.1 200"));
    // A client that speaks only h2 finds no protocol in common.
    assert!(https_get(addr, client(&roots, &[&rustls::version::TLS13], &[b"h2"])).await.is_err());
    // Plain HTTP to the TLS port gets no HTTP answer.
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nhost: localhost\r\n\r\n").await.unwrap();
    assert!(!read_all(&mut s).await.contains("HTTP/1.1 200"));
    // An ACME validation handshake is refused when this console isn't doing ACME.
    assert!(alpn_probe(addr, "localhost").await.0.is_none());
}

#[test]
fn certificate_files_must_match_their_key() {
    let (chain, _, _) = self_signed("console.example.com");
    let (_, other_key, _) = self_signed("console.example.com");
    let e = wtls::certified_key_from_pem(chain.as_bytes(), other_key.as_bytes()).unwrap_err().to_string();
    assert!(e.contains("does not match"), "{e}");
    assert!(wtls::certified_key_from_pem(b"", other_key.as_bytes()).is_err());
    assert!(wtls::certified_key_from_pem(chain.as_bytes(), b"").is_err());
}

#[tokio::test]
async fn certificate_files_are_reloaded_when_they_change() {
    let tmp = tmpdir("reload");
    let dir = &tmp.0;
    let (c1, k1, d1) = self_signed("console.example.com");
    std::fs::write(dir.join("cert.pem"), &c1).unwrap();
    std::fs::write(dir.join("key.pem"), &k1).unwrap();
    let fc = FileCert { cert: dir.join("cert.pem"), key: dir.join("key.pem") };
    let resolver = Arc::new(CertResolver::default());
    resolver.set(Arc::new(fc.load().unwrap()));
    fc.watch(resolver.clone(), Duration::from_millis(50));
    let leaf = |r: &CertResolver| r.current().unwrap().end_entity_cert().unwrap().to_vec();
    assert_eq!(leaf(&resolver), d1.to_vec());
    // A half-written replacement (new certificate, old key) keeps the old one in service.
    tokio::time::sleep(Duration::from_millis(20)).await;
    let (c2, k2, d2) = self_signed("console.example.com");
    std::fs::write(dir.join("cert.pem"), &c2).unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(leaf(&resolver), d1.to_vec());
    std::fs::write(dir.join("key.pem"), &k2).unwrap();
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if leaf(&resolver) == d2.to_vec() {
            return;
        }
    }
    panic!("the new certificate was not picked up");
}

#[tokio::test]
async fn tls_alpn_01_handshakes_get_the_challenge_certificate_and_no_http() {
    let (chain, key, _) = self_signed("localhost");
    let resolver = Arc::new(CertResolver::default());
    resolver.set(Arc::new(wtls::certified_key_from_pem(chain.as_bytes(), key.as_bytes()).unwrap()));
    let (addr, _tmp) = start_tls("alpn", resolver.clone(), true).await;
    // No order in flight: the handshake fails rather than showing the real certificate.
    assert!(alpn_probe(addr, "console.example.com").await.0.is_none());
    let digest = sha2::Sha256::digest(b"token.thumbprint");
    resolver.set_challenge("Console.Example.com", Arc::new(wtls::challenge_cert("console.example.com", &digest).unwrap()));
    let (cert, http) = alpn_probe(addr, "console.example.com").await;
    let cert = cert.expect("the challenge certificate");
    assert_eq!(acme_identifier(&cert).as_deref(), Some(&digest[..]));
    assert_eq!(http, "", "an ACME validation connection carries no HTTP");
    // Only for the name being validated.
    assert!(alpn_probe(addr, "other.example.com").await.0.is_none());
    resolver.clear_challenge("console.example.com");
    assert!(alpn_probe(addr, "console.example.com").await.0.is_none());
}

// ---- a mock ACME CA ----

const CA: &str = "https://ca.test";

#[derive(Default)]
struct CaState {
    nonce: u64,
    thumbprint: String,
    token: String,
    validated: bool,
    chain: Option<String>,
    validations: usize,
}

/// Answers instant-acme's requests like an RFC 8555 CA would (without checking JWS signatures), and
/// validates TLS-ALPN-01 by connecting to the console's listener as a real CA does.
struct MockCa {
    state: Arc<Mutex<CaState>>,
    domain: String,
    target: SocketAddr,
    issuer: Arc<(rcgen::Certificate, rcgen::KeyPair)>,
}

fn b64(v: &Value, k: &str) -> Vec<u8> {
    unb64u(v[k].as_str().unwrap_or("")).unwrap_or_default()
}

impl MockCa {
    async fn answer(&self, method: ::http::Method, url: String, body: Bytes) -> (StatusCode, Vec<(String, String)>, String) {
        let path = url.strip_prefix(CA).unwrap_or(&url).to_string();
        let mut headers = vec![];
        {
            let mut s = self.state.lock().unwrap();
            s.nonce += 1;
            headers.push(("replay-nonce".to_string(), format!("nonce-{}", s.nonce)));
        }
        let order = |s: &CaState| {
            let status = if s.chain.is_some() {
                "valid"
            } else if s.validated {
                "ready"
            } else {
                "pending"
            };
            json!({
                "status": status, "identifiers": [{ "type": "dns", "value": self.domain }],
                "authorizations": [format!("{CA}/authz/1")], "finalize": format!("{CA}/finalize/1"),
                "certificate": s.chain.as_ref().map(|_| format!("{CA}/cert/1")),
            })
        };
        if method == ::http::Method::GET && path == "/directory" {
            let d = json!({ "newNonce": format!("{CA}/nonce"), "newAccount": format!("{CA}/acct"), "newOrder": format!("{CA}/new-order") });
            return (StatusCode::OK, headers, d.to_string());
        }
        if path == "/nonce" {
            return (StatusCode::OK, headers, String::new());
        }
        let jws: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        let protected: Value = serde_json::from_slice(&b64(&jws, "protected")).unwrap_or(Value::Null);
        let payload: Value = serde_json::from_slice(&b64(&jws, "payload")).unwrap_or(Value::Null);
        match path.as_str() {
            "/acct" => {
                let k = &protected["jwk"];
                let canonical = format!(
                    r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
                    k["crv"].as_str().unwrap(),
                    k["kty"].as_str().unwrap(),
                    k["x"].as_str().unwrap(),
                    k["y"].as_str().unwrap()
                );
                self.state.lock().unwrap().thumbprint = b64u(&sha2::Sha256::digest(canonical.as_bytes()));
                assert_eq!(payload["termsOfServiceAgreed"], true);
                headers.push(("location".into(), format!("{CA}/acct/1")));
                (StatusCode::CREATED, headers, json!({ "status": "valid" }).to_string())
            }
            "/new-order" => {
                assert_eq!(payload["identifiers"], json!([{ "type": "dns", "value": self.domain }]));
                headers.push(("location".into(), format!("{CA}/order/1")));
                (StatusCode::CREATED, headers, order(&self.state.lock().unwrap()).to_string())
            }
            "/order/1" => (StatusCode::OK, headers, order(&self.state.lock().unwrap()).to_string()),
            "/authz/1" => {
                let s = self.state.lock().unwrap();
                let st = if s.validated { "valid" } else { "pending" };
                let a = json!({
                    "status": st, "identifier": { "type": "dns", "value": self.domain },
                    "challenges": [
                        { "type": "http-01", "url": format!("{CA}/chall/0"), "token": "unused", "status": "pending" },
                        { "type": "tls-alpn-01", "url": format!("{CA}/chall/1"), "token": s.token, "status": st },
                    ],
                });
                (StatusCode::OK, headers, a.to_string())
            }
            "/chall/1" => {
                // Validate as RFC 8737 says: connect, offer only acme-tls/1, check the extension.
                let (cert, _) = alpn_probe(self.target, &self.domain).await;
                let mut s = self.state.lock().unwrap();
                s.validations += 1;
                let want = sha2::Sha256::digest(format!("{}.{}", s.token, s.thumbprint).as_bytes()).to_vec();
                s.validated = cert.as_deref().and_then(acme_identifier) == Some(want);
                let st = if s.validated { "valid" } else { "invalid" };
                let c = json!({ "type": "tls-alpn-01", "url": format!("{CA}/chall/1"), "token": s.token, "status": st });
                (StatusCode::OK, headers, c.to_string())
            }
            "/finalize/1" => {
                let csr = b64(&payload, "csr");
                let params = rcgen::CertificateSigningRequestParams::from_der(&csr.into()).unwrap();
                let cert = params.signed_by(&self.issuer.0, &self.issuer.1).unwrap();
                let mut s = self.state.lock().unwrap();
                s.chain = Some(format!("{}{}", cert.pem(), self.issuer.0.pem()));
                (StatusCode::OK, headers, order(&s).to_string())
            }
            "/cert/1" => {
                headers.push(("content-type".into(), "application/pem-certificate-chain".into()));
                (StatusCode::OK, headers, self.state.lock().unwrap().chain.clone().unwrap_or_default())
            }
            _ => (StatusCode::NOT_FOUND, headers, json!({ "type": "urn:ietf:params:acme:error:malformed", "detail": path }).to_string()),
        }
    }
}

impl HttpClient for MockCa {
    fn request(
        &self,
        req: ::http::Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>> {
        let me = MockCa { state: self.state.clone(), domain: self.domain.clone(), target: self.target, issuer: self.issuer.clone() };
        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let body = body.collect().await.unwrap().to_bytes();
            let (status, headers, text) = me.answer(parts.method, parts.uri.to_string(), body).await;
            let mut r = ::http::Response::builder().status(status);
            for (k, v) in headers {
                r = r.header(k, v);
            }
            Ok(BytesResponse::from(r.body(Full::new(Bytes::from(text))).unwrap()))
        })
    }
}

fn issuer() -> Arc<(rcgen::Certificate, rcgen::KeyPair)> {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    p.distinguished_name.push(rcgen::DnType::CommonName, "mock ACME CA");
    let cert = p.self_signed(&key).unwrap();
    Arc::new((cert, key))
}

#[tokio::test]
async fn an_acme_order_validates_over_tls_alpn_01_and_puts_the_certificate_in_service() {
    // The console's listener, with no certificate yet (as at first start with ACME).
    let resolver = Arc::new(CertResolver::default());
    let (addr, _tmp) = start_tls("acme", resolver.clone(), true).await;
    let tmp = tmpdir("acme");
    let dir = &tmp.0;
    let domain = "localhost.example";
    let cfg = AcmeConfig {
        domain: domain.into(),
        contact: vec!["mailto:ops@example.com".into()],
        directory: format!("{CA}/directory"),
        cache: dir.join("acme"),
    };
    let ca_state = Arc::new(Mutex::new(CaState { token: "tok-123".into(), ..Default::default() }));
    let issuer = issuer();
    let http: HttpFactory = {
        let (ca_state, issuer) = (ca_state.clone(), issuer.clone());
        Arc::new(move || {
            Box::new(MockCa { state: ca_state.clone(), domain: domain.into(), target: addr, issuer: issuer.clone() }) as Box<dyn HttpClient>
        })
    };
    assert!(resolver.current().is_none());
    let poll = instant_acme::RetryPolicy::new().initial_delay(Duration::from_millis(10)).timeout(Duration::from_secs(10));
    acme::order(&cfg, &resolver, &http, poll).await.unwrap();
    {
        let s = ca_state.lock().unwrap();
        assert!(s.validated && s.validations == 1, "validated once, over TLS-ALPN-01");
    }
    // In service: a client trusting the mock CA connects with the issued certificate.
    let leaf = resolver.current().unwrap().end_entity_cert().unwrap().to_vec();
    let (_, issued) = x509_parser::parse_x509_certificate(&leaf).unwrap();
    assert_eq!(issued.issuer().to_string(), "CN=mock ACME CA");
    let names: Vec<String> = issued
        .subject_alternative_name()
        .unwrap()
        .unwrap()
        .value
        .general_names
        .iter()
        .filter_map(|n| match n {
            x509_parser::extensions::GeneralName::DNSName(d) => Some(d.to_string()),
            _ => None,
        })
        .collect();
    assert_eq!(names, vec![domain.to_string()]);
    // The challenge is gone once validated.
    assert!(alpn_probe(addr, domain).await.0.is_none());
    // Stored privately, and reused at the next start; the account too.
    use std::os::unix::fs::PermissionsExt;
    for p in [cfg.cert_path(), cfg.key_path()] {
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600, "{}", p.display());
    }
    assert_eq!(std::fs::metadata(&cfg.cache).unwrap().permissions().mode() & 0o777, 0o700);
    let accounts: Vec<_> = std::fs::read_dir(&cfg.cache)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("account-"))
        .collect();
    assert_eq!(accounts.len(), 1);
    assert_eq!(cfg.cached().unwrap().end_entity_cert().unwrap().to_vec(), leaf);
    // A fresh certificate isn't due for renewal; a nearly expired one is.
    let fresh = Arc::new(CertResolver::default());
    acme::run(cfg.clone(), fresh.clone(), http.clone(), Duration::from_secs(3600));
    assert_eq!(fresh.current().unwrap().end_entity_cert().unwrap().to_vec(), leaf, "the cached certificate is served at once");
    let not_after = wtls::not_after(&fresh.current().unwrap()).unwrap();
    assert!(!acme::due(&fresh, not_after - acme::RENEW_BEFORE - 60));
    assert!(acme::due(&fresh, not_after - acme::RENEW_BEFORE + 60));
    assert!(acme::due(&CertResolver::default(), 0), "no certificate at all: order one");
}
