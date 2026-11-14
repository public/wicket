//! Images delivered over the control channel (#191): the node takes an OCI image layout archive
//! as it arrives, keeps only what it has verified against the pin ([`crate::oci`]), and has its
//! runtime import that; the box then starts from it by digest as any pinned box does (#192).

use super::*;

/// The most an image archive may be.
const IMAGE_MAX: u64 = 64 << 30;
/// How often the node acknowledges what it has taken of an image.
const ACK_EVERY: u64 = 1 << 20;

/// Images being received, by stream: the connection, the next offset, and where the bytes go.
#[derive(Default)]
pub(super) struct Incoming(Mutex<HashMap<u64, (u64, u64, std::sync::mpsc::Sender<Option<Vec<u8>>>)>>);

fn spool(root: &std::path::Path) -> PathBuf {
    root.join("images")
}

/// Removes what a previous `serve` left of images it was receiving.
pub(super) fn clear_spool(root: &std::path::Path) {
    let _ = std::fs::remove_dir_all(spool(root));
}

/// `Msg::ImageHave`.
pub(super) fn have(node: &Arc<Node>, gen: u64, id: u64, digest: String) {
    let n = node.clone();
    tokio::spawn(async move {
        let (out, error) = match n.docker.image_identity(&digest).await {
            Ok(i) => (Some(if i.is_some_and(|i| i.is(&digest)) { "present" } else { "absent" }.to_string()), None),
            Err(e) => (None, Some(format!("{e:#}"))),
        };
        n.send_to(gen, Frame::Msg(Msg::BoxCtlDone { id, out, error }));
    });
}

/// `Msg::PutImage`: takes the archive on `stream` from connection `gen`.
pub(super) fn put(node: &Arc<Node>, gen: u64, stream: u64, digest: String, name: Option<String>) {
    if stream & TUNNEL_BIT == 0 || stream & chan::CONTROL_TUNNEL_BIT == 0 {
        return;
    }
    let refuse = |e: String| {
        node.send_to(gen, Frame::Msg(Msg::TunnelOpened { stream, error: Some(e) }));
    };
    match wicket_core::image::parse(&digest) {
        Ok(r) if r.name.is_empty() && r.pin.is_some() => {}
        _ => return refuse(format!("{digest:?} is not an image digest")),
    }
    if let Some(n) = &name {
        if !wicket_core::image::parse(n).is_ok_and(|r| !r.name.is_empty() && r.pin.as_deref() == Some(digest.as_str())) {
            return refuse(format!("{n:?} is not a name pinned to {digest}"));
        }
    }
    let dir = spool(&node.paths.root).join(format!("in-{:x}-{}", stream & !(TUNNEL_BIT | chan::CONTROL_TUNNEL_BIT), ulid::Ulid::new()));
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return refuse(format!("making {}: {e}", dir.display()));
    }
    let (tx, rx) = std::sync::mpsc::channel();
    node.images.0.lock().expect("images").insert(stream, (gen, 0, tx));
    node.send_to(gen, Frame::Msg(Msg::TunnelOpened { stream, error: None }));
    let n = node.clone();
    tokio::spawn(async move {
        let r = receive(&n, gen, stream, rx, &dir, &digest, name.as_deref()).await;
        let _ = std::fs::remove_dir_all(&dir);
        let (kind, error) = match &r {
            Ok(_) => ("image.received", None),
            Err(e) => ("image.refused", Some(format!("{e:#}"))),
        };
        let mut body = serde_json::json!({ "digest": digest, "name": name, "via": "channel" });
        match &r {
            Ok(u) => body["bytes"] = u.bytes.into(),
            Err(e) => body["why"] = format!("{e:#}").into(),
        }
        if let Some(e) = &error {
            eprintln!("[node] image {digest} refused: {e}");
        } else {
            eprintln!("[node] image {digest} received and imported");
        }
        let _ = n.audit.lock().expect("audit").audit(&wicket_core::TenantId::single(), None, kind, &body);
        n.send_to(gen, Frame::Msg(Msg::ImagePut { stream, error }));
    });
}

async fn receive(
    node: &Arc<Node>,
    gen: u64,
    stream: u64,
    rx: std::sync::mpsc::Receiver<Option<Vec<u8>>>,
    dir: &std::path::Path,
    digest: &str,
    name: Option<&str>,
) -> Result<crate::oci::Unpacked> {
    let (n, d, pin, nm) = (node.clone(), dir.to_path_buf(), digest.to_string(), name.map(String::from));
    let unpacked = tokio::task::spawn_blocking(move || {
        let mut last = 0u64;
        let mut reader = crate::oci::ChunkReader::new(rx, |taken| {
            if taken - last >= ACK_EVERY {
                last = taken;
                n.send_to(gen, Frame::Msg(Msg::Ack { stream, upto: taken }));
            }
        });
        let r = crate::oci::unpack_verified(&mut reader, &d, &pin, nm.as_deref(), IMAGE_MAX);
        // Past the archive's end there is only its padding. A refusal reads no further: the
        // sender stops on the verdict.
        if r.is_ok() {
            let _ = std::io::copy(&mut std::io::Read::take(&mut reader, 1 << 20), &mut std::io::sink());
        }
        r
    })
    .await
    .context("verifying the image");
    // Nothing more is taken for it.
    node.images.0.lock().expect("images").remove(&stream);
    let unpacked = unpacked??;
    node.docker.import_layout(dir).await.context("importing the image")?;
    match node.docker.image_identity(digest).await? {
        Some(i) if i.is(digest) => Ok(unpacked),
        _ => bail!("the runtime does not report {digest} after importing it"),
    }
}

/// `Msg::PullImage`: pulls image `digest` from registry `from` for `run`, host-side, and imports
/// it once verified; answers on connection `gen`.
pub(super) fn pull(node: &Arc<Node>, gen: u64, id: u64, run: String, digest: String, name: Option<String>, from: crate::registry::Source) {
    let n = node.clone();
    tokio::spawn(async move {
        let dir = spool(&n.paths.root).join(format!("pull-{id:x}-{}", ulid::Ulid::new()));
        let r = pull_into(&n, gen, &run, &digest, name.as_deref(), &from, &dir).await;
        let _ = std::fs::remove_dir_all(&dir);
        let mut body = serde_json::json!({ "digest": digest, "name": name, "via": "registry", "registry": from.host, "repository": from.repository });
        let error = match &r {
            Ok(u) => {
                body["bytes"] = u.bytes.into();
                eprintln!("[node] image {digest} pulled from {} and imported", from.host);
                None
            }
            Err(e) => {
                body["why"] = format!("{e:#}").into();
                eprintln!("[node] pulling image {digest} from {} failed: {e:#}", from.host);
                Some(format!("{e:#}"))
            }
        };
        let kind = if error.is_none() { "image.received" } else { "image.refused" };
        let _ = n.audit.lock().expect("audit").audit(&wicket_core::TenantId::single(), Some(&wicket_core::RunId(run.clone())), kind, &body);
        n.send_to(gen, Frame::Msg(Msg::ImagePulled { id, error }));
    });
}

async fn pull_into(
    node: &Arc<Node>,
    gen: u64,
    run: &str,
    digest: &str,
    name: Option<&str>,
    from: &crate::registry::Source,
    dir: &std::path::Path,
) -> Result<crate::oci::Unpacked> {
    crate::run::check_run_id(run)?;
    if let Some(n) = name {
        if !wicket_core::image::parse(n).is_ok_and(|r| !r.name.is_empty() && r.pin.as_deref() == Some(digest)) {
            bail!("{n:?} is not a name pinned to {digest}");
        }
    }
    // The registry's credential, fetched for the run like any secret (#152), held only for the pull.
    let cred = match &from.secret {
        None => None,
        Some(s) => Some(fetch_for_pull(node, gen, run, s).await?),
    };
    std::fs::create_dir_all(dir)?;
    let unpacked = crate::registry::pull(from, digest, name, cred.as_ref().map(|f| f.value.as_str()), dir, IMAGE_MAX).await?;
    drop(cred);
    node.docker.import_layout(dir).await.context("importing the image")?;
    match node.docker.image_identity(digest).await? {
        Some(i) if i.is(digest) => Ok(unpacked),
        _ => bail!("the runtime does not report {digest} after importing it"),
    }
}

/// A secret for a pull, from the control host over connection `gen` (the box isn't started yet,
/// so it has no owner connection).
async fn fetch_for_pull(node: &Arc<Node>, gen: u64, run: &str, name: &str) -> Result<crate::nodesecrets::Fetched> {
    let id = node.id();
    let (tx, rx) = oneshot::channel();
    node.asks.lock().expect("asks").insert(id, tx);
    let sent = node.send_to(gen, Frame::Msg(Msg::SecretFetch { id, run: run.into(), name: name.into() }));
    let reply = match sent {
        true => tokio::time::timeout(std::time::Duration::from_secs(10), rx).await.ok().and_then(|r| r.ok()),
        false => None,
    };
    node.asks.lock().expect("asks").remove(&id);
    match reply {
        Some(Msg::SecretFetched { secret: Some(f), .. }) => Ok(*f),
        Some(Msg::SecretFetched { error: Some(e), .. }) => bail!("the registry's credential {name} was refused by the control host: {e}"),
        _ => bail!("the control host did not release the registry's credential {name}"),
    }
}

/// Bytes for an image being received; given back if `stream` isn't one. Out-of-order bytes end it.
pub(super) fn data(node: &Node, stream: u64, offset: u64, bytes: Vec<u8>) -> Option<Vec<u8>> {
    let mut m = node.images.0.lock().expect("images");
    let Some((_, next, tx)) = m.get_mut(&stream) else { return Some(bytes) };
    if offset != *next {
        // Dropping the sender cuts the delivery off: the receiver refuses it.
        m.remove(&stream);
        return None;
    }
    *next += bytes.len() as u64;
    if tx.send(Some(bytes)).is_err() {
        m.remove(&stream);
    }
    None
}

/// The sender is done with `stream`; false if it isn't an image.
pub(super) fn end(node: &Node, stream: u64) -> bool {
    match node.images.0.lock().expect("images").remove(&stream) {
        Some((_, _, tx)) => {
            let _ = tx.send(None);
            true
        }
        None => false,
    }
}

/// Connection `gen` is gone: the images it was sending are cut off.
pub(super) fn gone(node: &Node, gen: u64) {
    node.images.0.lock().expect("images").retain(|_, (g, _, _)| *g != gen);
}

#[cfg(test)]
mod tests {
    use super::super::tests::{connect, test_node};
    use super::*;
    use crate::nodeauth::testkit::Install;
    use crate::oci::testkit::{archive, image_with, sha};

    /// A runtime that keeps what it loads in a directory: `load` takes a layout archive and checks
    /// it names one image whose blobs are all there; `image inspect` reports it by digest or name.
    const FAKE_RUNTIME: &str = r#"#!/usr/bin/env python3
import io, json, os, sys, tarfile
store = os.environ["FAKE_STORE"]
a = sys.argv[1:]
if a[:1] == ["load"]:
    t = tarfile.open(fileobj=io.BytesIO(sys.stdin.buffer.read()))
    names = set(t.getnames())
    idx = json.load(t.extractfile("index.json"))
    assert names >= {"oci-layout", "index.json"} and "manifest.json" not in names, names
    (d,) = idx["manifests"]
    assert "blobs/sha256/" + d["digest"][7:] in names
    rec = {"Id": d["digest"], "RepoDigests": [], "RepoTags": []}
    n = d.get("annotations", {}).get("io.containerd.image.name")
    if n:
        rec["RepoDigests"].append(n)
    open(os.path.join(store, d["digest"][7:]), "w").write(json.dumps(rec))
    sys.exit(0)
if a[:2] == ["image", "inspect"]:
    ref = a[-1]
    for f in os.listdir(store):
        rec = json.load(open(os.path.join(store, f)))
        if ref == rec["Id"] or ref in rec["RepoDigests"]:
            print(json.dumps(rec))
            sys.exit(0)
    sys.exit(1)
sys.exit(2)
"#;

    /// The control host's end of a connection: frames in go through `calls`.
    fn pump(s: UnixStream, calls: Arc<crate::nodecall::Calls>) {
        let (mut rd, mut wr) = s.into_split();
        let (tx, mut rx) = mpsc::unbounded_channel::<Frame>();
        calls.set_out(Some(tx));
        calls.set_proto(chan::PROTOCOL);
        tokio::spawn(async move {
            while let Some(f) = rx.recv().await {
                if wr.write_all(&f.encode()).await.is_err() {
                    break;
                }
            }
        });
        tokio::spawn(async move {
            while let Ok(Some(f)) = chan::read_frame(&mut rd).await {
                let _ = calls.handle(f);
            }
        });
    }

    fn kinds(node: &Node) -> Vec<(String, serde_json::Value)> {
        let l = node.audit.lock().unwrap();
        l.audit_records_after(0, 1000).unwrap().into_iter().map(|r| (r.kind, serde_json::from_str(&r.body).unwrap())).collect()
    }

    #[tokio::test]
    async fn an_image_comes_over_the_channel_verified_and_a_tampered_one_is_refused() {
        let inst = Install::new("nodesrv-images");
        let store = inst.dir.join("store");
        std::fs::create_dir_all(&store).unwrap();
        let fake = inst.dir.join("fake-runtime");
        std::fs::write(&fake, FAKE_RUNTIME).unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut node = test_node(&inst);
        Arc::get_mut(&mut node).unwrap().docker =
            Docker::with_command(vec!["env".into(), format!("FAKE_STORE={}", store.display()), fake.display().to_string()]);
        let calls = Arc::new(crate::nodecall::Calls::default());
        pump(connect(&node, 1, &inst).await, calls.clone());

        // Larger than the sender's window, so it waits on the node's acknowledgements.
        let layer: Vec<u8> = (0..40u32 << 20).map(|i| (i.wrapping_mul(2654435761) >> 24) as u8).collect();
        let img = image_with(&layer);
        let name = crate::oci::import_name("example/agent:1", &img.index).unwrap();
        assert!(!calls.has_image(&img.index).await.unwrap());
        let sent = calls.put_image(&img.index, Some(&name), archive(&img.entries).as_slice()).await.unwrap();
        assert!(sent > 40 << 20);
        assert!(calls.has_image(&img.index).await.unwrap());
        let ident = node.docker.image_identity(&name).await.unwrap().unwrap();
        assert!(ident.is(&img.index));

        // Another image, one byte of its layer changed on the way: refused, and not imported.
        let other = image_with(b"another layer");
        let mut entries = other.entries.clone();
        let l = entries.iter_mut().find(|(p, _)| p.ends_with(&sha(b"another layer")[7..])).unwrap();
        l.1[0] ^= 1;
        let e = calls.put_image(&other.index, None, archive(&entries).as_slice()).await.unwrap_err();
        assert!(format!("{e:#}").contains("does not match its digest"), "{e:#}");
        assert!(!calls.has_image(&other.index).await.unwrap());
        // A name pinned to another digest is refused before anything is sent.
        let e = calls.put_image(&other.index, Some(&name), archive(&other.entries).as_slice()).await.unwrap_err();
        assert!(format!("{e:#}").contains("not a name pinned to"), "{e:#}");

        let k = kinds(&node);
        assert!(k.iter().any(|(k, b)| k == "image.received" && b["digest"] == img.index.as_str()), "{k:?}");
        assert!(k.iter().any(|(k, b)| k == "image.refused" && b["digest"] == other.index.as_str()), "{k:?}");
        // Nothing is left in the spool.
        assert_eq!(std::fs::read_dir(spool(&node.paths.root)).map(|d| d.count()).unwrap_or(0), 0);
    }

    /// Removes a test's own image from the real runtime, whatever the test did.
    struct Rmi(Vec<String>, String);
    impl Drop for Rmi {
        fn drop(&mut self) {
            let _ = std::process::Command::new(&self.0[0]).args(&self.0[1..]).args(["rmi", "-f", &self.1]).output();
        }
    }

    /// With a real Docker (`WICKET_TEST_DOCKER=1`, and `WICKET_DOCKER` if it needs one; the
    /// containerd image store): a scratch image built here, exported by digest and removed, comes
    /// back over the channel as exactly that image, and a copy with one layer byte changed doesn't.
    #[tokio::test]
    async fn a_real_runtime_imports_a_delivered_image() {
        if std::env::var_os("WICKET_TEST_DOCKER").is_none() {
            eprintln!("skipped: set WICKET_TEST_DOCKER=1 to run it against this host's Docker");
            return;
        }
        let inst = Install::new("nodesrv-images-docker");
        let cmd: Vec<String> =
            std::env::var("WICKET_DOCKER").unwrap_or_else(|_| "docker".into()).split_whitespace().map(String::from).collect();
        let ctx = inst.dir.join("ctx");
        std::fs::create_dir_all(&ctx).unwrap();
        std::fs::write(ctx.join("f"), ulid::Ulid::new().to_string()).unwrap();
        std::fs::write(ctx.join("Dockerfile"), "FROM scratch\nCOPY f /f\n").unwrap();
        let tag = format!("wicket-test/delivered:{}", ulid::Ulid::new().to_string().to_lowercase());
        let docker = Docker::from_env();
        docker.build_image(&tag, &ctx).await.unwrap();
        let id = docker.image_identity(&tag).await.unwrap().unwrap().id;
        let _rm = Rmi(cmd.clone(), id.clone());
        let mut save = docker.export_image(&id).unwrap();
        let mut bytes = vec![];
        save.stdout.take().unwrap().read_to_end(&mut bytes).await.unwrap();
        assert!(save.wait().await.unwrap().success());
        let rmi = |r: &str| std::process::Command::new(&cmd[0]).args(&cmd[1..]).args(["rmi", "-f", r]).output().unwrap();
        rmi(&id);
        assert!(docker.image_identity(&id).await.unwrap().is_none());

        let node = test_node(&inst);
        let calls = Arc::new(crate::nodecall::Calls::default());
        pump(connect(&node, 1, &inst).await, calls.clone());
        let name = crate::oci::import_name(&tag, &id).unwrap();
        calls.put_image(&id, Some(&name), bytes.as_slice()).await.unwrap();
        assert!(calls.has_image(&id).await.unwrap());
        let ident = docker.image_identity(&format!("wicket-test/delivered@{id}")).await.unwrap().unwrap();
        assert_eq!(ident.id, id);
        // Docker lists the pinned name with its tags: no `name:tag` is made or moved.
        assert!(ident.tags.iter().all(|t| t.contains('@')), "no tag moves: {:?}", ident.tags);

        // The same archive, its layer changed by a byte (the manifest names it: a pin of a
        // manifest, as a local build's is).
        rmi(&id);
        let mut entries: Vec<(String, Vec<u8>)> = vec![];
        let mut ar = tar::Archive::new(bytes.as_slice());
        for e in ar.entries().unwrap() {
            let mut e = e.unwrap();
            if e.header().entry_type().is_file() {
                let p = e.path().unwrap().to_string_lossy().into_owned();
                let mut b = vec![];
                std::io::Read::read_to_end(&mut e, &mut b).unwrap();
                entries.push((p, b));
            }
        }
        let blob =
            |entries: &[(String, Vec<u8>)], d: &str| entries.iter().position(|(p, _)| p == &format!("blobs/sha256/{}", &d[7..])).unwrap();
        let manifest: serde_json::Value = serde_json::from_slice(&entries[blob(&entries, &id)].1).unwrap();
        let at = blob(&entries, manifest["layers"][0]["digest"].as_str().unwrap());
        let layer = &mut entries[at];
        let last = layer.1.len() - 1;
        layer.1[last] ^= 1;
        let e = calls.put_image(&id, Some(&name), archive(&entries).as_slice()).await.unwrap_err();
        assert!(format!("{e:#}").contains("does not match its digest"), "{e:#}");
        assert!(!calls.has_image(&id).await.unwrap());
    }
}
