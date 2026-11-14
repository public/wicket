//! In-process costs of the candidate kernels, median of rounds, ns per operation.
//!
//!   cursed-micro http      httparse::Request::parse vs fbparse.h (SSE2 baseline and AVX2 builds)
//!   cursed-micro ed25519   ed25519-dalek verify / verify_strict vs cursed-jwt's Ed25519 (per-key tables)
//!   cursed-micro sha256    sha2 SHA-256 over audit-row-sized inputs (the audit chain's hash)
//!
//! Prints one JSON object per line.
use std::hint::black_box;
use std::time::Instant;

#[repr(C)]
#[derive(Clone, Copy)]
struct FbHeader {
    name: *const u8,
    name_len: usize,
    value: *const u8,
    value_len: usize,
}

type FbFn = unsafe extern "C" fn(
    *const u8,
    usize,
    *mut *const u8,
    *mut usize,
    *mut *const u8,
    *mut usize,
    *mut i32,
    *mut FbHeader,
    *mut usize,
) -> i32;

extern "C" {
    fn fb_sse2(b: *const u8, l: usize, m: *mut *const u8, ml: *mut usize, p: *mut *const u8, pl: *mut usize, mi: *mut i32, h: *mut FbHeader, nh: *mut usize) -> i32;
    fn fb_avx2(b: *const u8, l: usize, m: *mut *const u8, ml: *mut usize, p: *mut *const u8, pl: *mut usize, mi: *mut i32, h: *mut FbHeader, nh: *mut usize) -> i32;
}

/// Request heads of the shapes a box sends through the proxy (inside TLS, after interception).
fn corpus() -> Vec<(&'static str, Vec<u8>)> {
    let v: Vec<(&str, &str)> = vec![
        ("cargo-index", "GET /se/rd/serde HTTP/1.1\r\nhost: index.crates.io\r\nuser-agent: cargo/1.91.0 (a3b4c5d 2026-10-01)\r\naccept: */*\r\naccept-encoding: gzip\r\nif-none-match: \"0x8DC9B1A2F3E4D5C\"\r\n\r\n"),
        ("cargo-crate", "GET /crates/serde/serde-1.0.228.crate HTTP/1.1\r\nhost: static.crates.io\r\nuser-agent: cargo/1.91.0 (a3b4c5d 2026-10-01)\r\naccept: */*\r\naccept-encoding: gzip\r\n\r\n"),
        ("curl", "GET /1k HTTP/1.1\r\nHost: origin.test\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n"),
        ("npm", "GET /@types%2fnode HTTP/1.1\r\nuser-agent: npm/10.9.2 node/v22.12.0 linux x64 workspaces/false\r\nnpm-command: install\r\npacote-version: 18.0.6\r\npacote-req-type: packument\r\npacote-pkg-id: registry:@types/node\r\naccept: application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*\r\nnpm-auth-type: web\r\nnpm-command: install\r\naccept-encoding: gzip,deflate\r\nHost: registry.npmjs.org\r\nConnection: keep-alive\r\n\r\n"),
        ("git-upload-pack", "POST /owner/repo.git/git-upload-pack HTTP/1.1\r\nHost: github.com\r\nUser-Agent: git/2.43.0\r\nAccept-Encoding: deflate, gzip, br, zstd\r\nContent-Type: application/x-git-upload-pack-request\r\nAccept: application/x-git-upload-pack-result\r\nGit-Protocol: version=2\r\nContent-Length: 1532\r\n\r\n"),
        ("chrome", "GET /api/v1/items?page=2&sort=recent HTTP/1.1\r\nHost: app.example.com\r\nConnection: keep-alive\r\nsec-ch-ua: \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"\r\nsec-ch-ua-mobile: ?0\r\nsec-ch-ua-platform: \"Linux\"\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8\r\nSec-Fetch-Site: same-origin\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-User: ?1\r\nSec-Fetch-Dest: document\r\nReferer: https://app.example.com/api/v1/items?page=1\r\nAccept-Encoding: gzip, deflate, br, zstd\r\nAccept-Language: en-GB,en;q=0.9\r\nCookie: session=0123456789abcdef0123456789abcdef; theme=dark; _ga=GA1.1.123456789.1700000000\r\n\r\n"),
        ("model-call", "POST /v1/messages HTTP/1.1\r\nhost: api.anthropic.com\r\nanthropic-version: 2023-06-01\r\ncontent-type: application/json\r\naccept: application/json\r\nuser-agent: claude-cli/2.1.0 (external, cli)\r\nx-app: cli\r\nanthropic-beta: interleaved-thinking-2025-05-14\r\ncontent-length: 48211\r\n\r\n"),
    ];
    v.into_iter()
        .map(|(n, s)| {
            let mut b = s.as_bytes().to_vec();
            b.extend_from_slice(&[0u8; 64]); // fbparse.h: 64 readable bytes after the head
            (n, b)
        })
        .collect()
}

fn med(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

/// Median over `rounds` of the mean ns per call of `f`, `iters` calls a round.
fn time(rounds: usize, iters: usize, mut f: impl FnMut()) -> f64 {
    for _ in 0..iters / 10 + 1 {
        f();
    }
    med((0..rounds)
        .map(|_| {
            let t = Instant::now();
            for _ in 0..iters {
                f();
            }
            t.elapsed().as_nanos() as f64 / iters as f64
        })
        .collect())
}

fn http() {
    for (name, buf) in corpus() {
        let len = buf.len() - 64;
        let head = &buf[..len];
        let bp: &[u8] = &buf;
        let hp = || {
            let mut h = [httparse::EMPTY_HEADER; 64];
            let mut r = httparse::Request::new(&mut h);
            let n = match r.parse(black_box(head)).unwrap() {
                httparse::Status::Complete(n) => n,
                _ => panic!(),
            };
            black_box((n, r.headers.len()));
        };
        let fb = |f: FbFn| {
            move || {
                let mut h = [FbHeader { name: std::ptr::null(), name_len: 0, value: std::ptr::null(), value_len: 0 }; 64];
                let (mut m, mut ml, mut p, mut pl, mut mi, mut nh) = (std::ptr::null(), 0, std::ptr::null(), 0, 0, 64usize);
                // SAFETY: buf has 64 readable bytes after len; every out-pointer is a live local.
                let n = unsafe { f(black_box(bp.as_ptr()), len, &mut m, &mut ml, &mut p, &mut pl, &mut mi, h.as_mut_ptr(), &mut nh) };
                assert_eq!(n as usize, len);
                black_box((n, nh));
            }
        };
        let (r, i) = (15, 200_000);
        let a = time(r, i, hp);
        let b = time(r, i, fb(fb_sse2));
        let c = time(r, i, fb(fb_avx2));
        println!(
            "{{\"bench\":\"http\",\"req\":\"{name}\",\"bytes\":{len},\"httparse_ns\":{a:.1},\"fbparse_sse2_ns\":{b:.1},\"fbparse_avx2_ns\":{c:.1}}}"
        );
    }
}

fn ed25519() {
    use ed25519_dalek::{Signer, SigningKey, Verifier};
    let sk = SigningKey::from_bytes(&[42; 32]);
    let vk = sk.verifying_key();
    // JWS-sized and Biscuit-block-sized messages.
    for size in [200usize, 1200] {
        let msgs: Vec<Vec<u8>> = (0..64).map(|i| (0..size).map(|j| (i * 31 + j * 7) as u8).collect()).collect();
        let sigs: Vec<[u8; 64]> = msgs.iter().map(|m| sk.sign(m).to_bytes()).collect();
        let dsigs: Vec<ed25519_dalek::Signature> = sigs.iter().map(ed25519_dalek::Signature::from_bytes).collect();
        let mut k = 0usize;
        let (r, i) = (9, 2_000);
        let dv = time(r, i, || {
            k = (k + 1) % 64;
            assert!(vk.verify(black_box(&msgs[k]), &dsigs[k]).is_ok());
        });
        let ds = time(r, i, || {
            k = (k + 1) % 64;
            assert!(vk.verify_strict(black_box(&msgs[k]), &dsigs[k]).is_ok());
        });
        let ck = cursed_jwt::Ed25519Key::new(vk.as_bytes()).unwrap();
        let c1 = time(r, i, || {
            k = (k + 1) % 64;
            let mut ok = [false];
            ck.verify_signatures(&[black_box(&msgs[k][..])], &[&sigs[k][..]], &mut ok);
            assert!(ok[0]);
        });
        let mrefs: Vec<&[u8]> = msgs.iter().map(|m| &m[..]).collect();
        let srefs: Vec<&[u8]> = sigs.iter().map(|s| &s[..]).collect();
        let c16 = time(r, i / 16, || {
            k = (k + 16) % 48;
            let mut ok = [false; 16];
            ck.verify_signatures(black_box(&mrefs[k..k + 16]), &srefs[k..k + 16], &mut ok);
            assert!(ok.iter().all(|x| *x));
        }) / 16.0;
        let setup = time(5, 20, || {
            black_box(cursed_jwt::Ed25519Key::new(black_box(vk.as_bytes())).unwrap());
        });
        let dalek_setup = time(5, 2000, || {
            black_box(ed25519_dalek::VerifyingKey::from_bytes(black_box(vk.as_bytes())).unwrap());
        });
        println!(
            "{{\"bench\":\"ed25519\",\"msg_bytes\":{size},\"dalek_verify_ns\":{dv:.0},\"dalek_verify_strict_ns\":{ds:.0},\"cursed_b1_ns\":{c1:.0},\"cursed_b16_ns\":{c16:.0},\"cursed_key_setup_ns\":{setup:.0},\"dalek_key_decode_ns\":{dalek_setup:.0}}}"
        );
    }
}

fn sha256() {
    use sha2::{Digest, Sha256};
    for size in [300usize, 1000] {
        let m: Vec<u8> = (0..size).map(|j| j as u8).collect();
        let t = time(9, 100_000, || {
            black_box(Sha256::digest(black_box(&m)));
        });
        println!("{{\"bench\":\"sha256\",\"bytes\":{size},\"sha2_ns\":{t:.0}}}");
    }
}

fn main() {
    let what = std::env::args().nth(1).unwrap_or_else(|| "all".into());
    if what == "http" || what == "all" {
        http();
    }
    if what == "ed25519" || what == "all" {
        ed25519();
    }
    if what == "sha256" || what == "all" {
        sha256();
    }
}
