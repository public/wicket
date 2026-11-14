//! Root's own copies of wicket (#261).
//!
//! The versions root (`/var/lib/wicket-versions`) is the `wicket` user's: wicketd stages, switches
//! and rolls back versions there as that user. So root must never run a file in it: anything that
//! compromised wicketd could have replaced it first. Root runs only its own copies:
//!
//! - `/usr/local/lib/wicket/<build id>/wicket` (root's, 0755), each made by a root process from
//!   an artifact root itself named (`sudo wicket self update ARTIFACT`, `sudo wicket self admit
//!   ARTIFACT`, or `deploy/install.sh` from the release archive). It is copied first, and only the
//!   copy is hashed and run: never a path the `wicket` user could write ([`writable_by`]).
//! - `/usr/local/bin/wicket`, root's link to one of them: what `sudo wicket …`, the root
//!   `wicket-follow` service, and the host's operators run. After a forwarded update, rollback or
//!   follow succeeds, root points it at its copy of the versions root's `current`, if it has one
//!   ([`relink`]). Root reads only the build id from the versions root, to choose among its own
//!   copies: what the `wicket` user wrote never decides which bytes root runs.
//!
//! The `wicket` user's services run `/var/lib/wicket-versions/current/wicket` directly (their units
//! say so), so wicketd's switch and rollback, and #165's unit check, work as before.
//!
//! While the `wicket` user is in the `docker` group it can still become root through Docker: this
//! closes the path through root running its binaries, not that one.

use anyhow::{bail, Context, Result};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Root's copies.
pub const COPIES: &str = "/usr/local/lib/wicket";
/// Root's link to one of them, on `PATH`.
pub const LINK: &str = "/usr/local/bin/wicket";
/// The installed versions root (the `wicket` user's).
pub const VERSIONS: &str = "/var/lib/wicket-versions";
/// The system user wicketd runs as.
pub const WICKET_USER: &str = "wicket";

/// A user, and the groups it is in.
#[derive(Clone, Debug)]
pub struct Account {
    pub uid: u32,
    pub groups: Vec<u32>,
}

impl Account {
    /// The `wicket` system user, if this host has one.
    pub fn wicket() -> Option<Account> {
        let name = std::ffi::CString::new(WICKET_USER).ok()?;
        let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = vec![0 as libc::c_char; 16384];
        let mut out: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: getpwnam_r fills `pw` with pointers into `buf`, which outlives their use here.
        let r = unsafe { libc::getpwnam_r(name.as_ptr(), &mut pw, buf.as_mut_ptr(), buf.len(), &mut out) };
        if r != 0 || out.is_null() {
            return None;
        }
        let mut groups = vec![0 as libc::gid_t; 256];
        let mut n = groups.len() as libc::c_int;
        // SAFETY: getgrouplist writes at most `n` gids and sets `n` to how many there are.
        if unsafe { libc::getgrouplist(name.as_ptr(), pw.pw_gid, groups.as_mut_ptr(), &mut n) } < 0 {
            groups.resize(n.max(0) as usize, 0);
            // SAFETY: as above, with room for all of them.
            unsafe { libc::getgrouplist(name.as_ptr(), pw.pw_gid, groups.as_mut_ptr(), &mut n) };
        }
        groups.truncate(n.max(0) as usize);
        if !groups.contains(&pw.pw_gid) {
            groups.push(pw.pw_gid);
        }
        Some(Account { uid: pw.pw_uid, groups })
    }
}

/// Why `acct` could change what `path` names (None: it can't), judged by owners and modes: the
/// file, or any directory above it, is its own, or writable by it (a sticky directory protects
/// entries it doesn't own, which the next component's owner then decides). `path` is resolved
/// first; ACLs aren't read (wicket sets none).
pub fn writable_by(path: &Path, acct: &Account) -> Option<String> {
    let path = match std::fs::canonicalize(path) {
        Ok(p) => p,
        Err(e) => return Some(format!("{} can't be resolved: {e}", path.display())),
    };
    let mut p = Some(path.as_path());
    while let Some(cur) = p {
        let m = match std::fs::metadata(cur) {
            Ok(m) => m,
            Err(e) => return Some(format!("{}: {e}", cur.display())),
        };
        if let Some(why) = mode_writable(cur, &m, acct) {
            return Some(why);
        }
        p = cur.parent();
    }
    None
}

fn mode_writable(p: &Path, m: &std::fs::Metadata, acct: &Account) -> Option<String> {
    let mode = m.mode();
    let sticky = m.is_dir() && mode & 0o1000 != 0;
    if m.uid() == acct.uid {
        return Some(format!("{} is owned by the {WICKET_USER} user", p.display()));
    }
    if sticky {
        return None;
    }
    if mode & 0o002 != 0 {
        return Some(format!("{} is writable by everyone", p.display()));
    }
    if mode & 0o020 != 0 && acct.groups.contains(&m.gid()) {
        return Some(format!("{} is writable by group {}, which the {WICKET_USER} user is in", p.display(), m.gid()));
    }
    None
}

/// Where root's copies, its link and the versions root are.
pub struct Layout {
    pub copies: PathBuf,
    pub link: PathBuf,
    pub versions: PathBuf,
    /// The account root must not trust (None: there is none, nothing is checked).
    pub untrusted: Option<Account>,
}

fn valid_id(id: &str) -> bool {
    id.len() == 12 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Layout {
    /// An installed host's.
    pub fn installed() -> Layout {
        Layout { copies: COPIES.into(), link: LINK.into(), versions: VERSIONS.into(), untrusted: Account::wicket() }
    }

    /// Root's copy of build `id`.
    pub fn copy(&self, id: &str) -> PathBuf {
        self.copies.join(id).join("wicket")
    }

    /// The build id of the copy root's link points at.
    pub fn linked(&self) -> Option<String> {
        let t = std::fs::read_link(&self.link).ok()?;
        let dir = t.parent()?;
        if dir.parent()? != self.copies || t.file_name()? != "wicket" {
            return None;
        }
        let id = dir.file_name()?.to_str()?.to_string();
        valid_id(&id).then_some(id)
    }

    /// The build id of the versions root's `current` or `previous` (only an id: which of root's
    /// own copies to run).
    pub fn versions_pointer(&self, name: &str) -> Option<String> {
        let t = std::fs::read_link(self.versions.join(name)).ok()?;
        let id = t.file_name()?.to_str()?.to_string();
        valid_id(&id).then_some(id)
    }

    /// Makes root's copy of the wicket binary in `artifact` (a binary, or a release archive's
    /// `wicket-…/wicket`), refusing an artifact the `wicket` user could have written. The artifact
    /// is opened once, checked through that open file, and copied; only the copy is hashed and
    /// unpacked. Returns the build id.
    pub fn admit(&self, artifact: &Path) -> Result<String> {
        let f = std::fs::File::open(artifact).with_context(|| format!("reading {}", artifact.display()))?;
        let m = f.metadata()?;
        if !m.is_file() {
            bail!("{} is not a file", artifact.display());
        }
        if let Some(acct) = &self.untrusted {
            let opened = std::fs::read_link(format!("/proc/self/fd/{}", f.as_raw_fd())).unwrap_or_else(|_| artifact.to_path_buf());
            if let Some(why) = mode_writable(&opened, &m, acct).or_else(|| opened.parent().and_then(|d| writable_by(d, acct))) {
                bail!(
                    "refused: root makes its copy only from an artifact the {WICKET_USER} user can't write, and {why}. Use the artifact as you got it (the release archive, or the build), not a copy of wicket's"
                );
            }
        }
        std::fs::create_dir_all(&self.copies).with_context(|| self.copies.display().to_string())?;
        std::fs::set_permissions(&self.copies, std::fs::Permissions::from_mode(0o755))?;
        if let Some(why) = self.untrusted.as_ref().and_then(|a| writable_by(&self.copies, a)) {
            bail!("refused: root's copies must be root's alone, and {why}");
        }
        let stage = self.copies.join(format!(".admit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&stage);
        std::fs::create_dir(&stage)?;
        std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o700))?;
        let _clean = Remove(stage.clone());
        let copy = stage.join("artifact");
        {
            let mut out = std::fs::OpenOptions::new().write(true).create_new(true).open(&copy)?;
            std::io::copy(&mut &f, &mut out).with_context(|| format!("copying {}", artifact.display()))?;
        }
        let bin = crate::update::binary_in(&copy, &stage.join("bin"))?;
        let sha = crate::update::sha256_file(&bin)?;
        let id = sha[..12].to_string();
        let dest = self.copy(&id);
        if dest.is_file() && crate::update::sha256_file(&dest)? == sha {
            return Ok(id);
        }
        let tmp = self.copies.join(format!(".{id}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir(&tmp)?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
        std::fs::copy(&bin, tmp.join("wicket"))?;
        std::fs::set_permissions(tmp.join("wicket"), std::fs::Permissions::from_mode(0o755))?;
        if crate::update::sha256_file(&tmp.join("wicket"))? != sha {
            let _ = std::fs::remove_dir_all(&tmp);
            bail!("root's copy of {} changed while it was made", artifact.display());
        }
        let _ = std::fs::remove_dir_all(self.copies.join(&id));
        std::fs::rename(&tmp, self.copies.join(&id))?;
        Ok(id)
    }

    /// Points root's link at its copy of `id`, atomically.
    pub fn link_to(&self, id: &str) -> Result<()> {
        let target = self.copy(id);
        if !target.is_file() {
            bail!("root has no copy of {id} in {}", self.copies.display());
        }
        let dir = self.link.parent().context("the link has no directory")?;
        let tmp = dir.join(format!(".wicket.{}.new", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        std::os::unix::fs::symlink(&target, &tmp)?;
        std::fs::rename(&tmp, &self.link).with_context(|| self.link.display().to_string())?;
        Ok(())
    }

    /// After an update, rollback or follow: root's link moves to root's copy of the versions root's
    /// `current`, if root has one; old copies are pruned. Says what it did, or why root's link
    /// stays where it is.
    pub fn relink(&self) -> Result<()> {
        let Some(cur) = self.versions_pointer("current") else { return Ok(()) };
        let was = self.linked();
        if was.as_deref() == Some(cur.as_str()) {
            return Ok(());
        }
        if !self.copy(&cur).is_file() {
            println!(
                "[self] root has no copy of {cur}: {} still runs {}. To run it as root, from its artifact (for a CI build, its release archive): sudo wicket self admit ARTIFACT",
                self.link.display(),
                was.as_deref().unwrap_or("what it ran")
            );
            return Ok(());
        }
        self.link_to(&cur)?;
        println!("[self] {} now runs root's copy of {cur} ({})", self.link.display(), self.copy(&cur).display());
        let mut keep = vec![cur];
        keep.extend(was);
        keep.extend(self.versions_pointer("previous"));
        self.prune(&keep);
        Ok(())
    }

    /// Removes root's copies other than `keep`.
    fn prune(&self, keep: &[String]) {
        let Ok(rd) = std::fs::read_dir(&self.copies) else { return };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if valid_id(&name) && !keep.contains(&name) {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }
}

struct Remove(PathBuf);
impl Drop for Remove {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

/// Root never runs a binary the `wicket` user could have replaced: as root, this build refuses to
/// run from such a path (a replaced binary wouldn't check, which is why nothing documented runs
/// one; this catches running an honest one by hand, as #165's message once said to).
pub fn refuse_untrusted_exe() -> Result<()> {
    if !is_root() {
        return Ok(());
    }
    let Some(acct) = Account::wicket() else { return Ok(()) };
    let exe = std::env::current_exe().context("finding this binary")?;
    if let Some(why) = writable_by(&exe, &acct) {
        bail!(
            "refusing to run as root from {}: {why}. Root runs only its own copies: {LINK} (`sudo wicket …`) or {COPIES}/<build id>/wicket. On a host installed before #261, make them once: run deploy/install.sh from the release archive, as root",
            exe.display()
        );
    }
    Ok(())
}

/// What root's process does around a forwarded command (#261): before `self update ARTIFACT`, it
/// makes its own copy of the artifact's build; after an update, rollback or follow succeeds, it
/// moves its link ([`Layout::relink`]). Only as root, on a host with root's copies.
pub struct Around {
    layout: Option<Layout>,
}

impl Around {
    pub fn before(cmd: &crate::Cmd) -> Result<Around> {
        use crate::{Cmd, SelfCmd};
        let layout = Layout::installed();
        let relinks = matches!(
            cmd,
            Cmd::Itself { cmd: SelfCmd::Update { only_nodes: false, .. } | SelfCmd::Rollback { only_nodes: false, .. } | SelfCmd::Follow }
        );
        if !relinks || !is_root() || !layout.copies.is_dir() {
            return Ok(Around { layout: None });
        }
        if let Cmd::Itself { cmd: SelfCmd::Update { artifact: Some(a), .. } } = cmd {
            let id = layout.admit(a)?;
            println!("[self] root's copy of {id}: {}", layout.copy(&id).display());
        }
        Ok(Around { layout: Some(layout) })
    }

    pub fn after(self, code: i32) {
        if code != 0 {
            return;
        }
        if let Some(l) = self.layout {
            if let Err(e) = l.relink() {
                eprintln!("[self] moving {} to root's copy of the new build: {e:#}", l.link.display());
            }
        }
    }
}

/// `wicket self admit ARTIFACT`: root's copy of the artifact's build; root's link moves to it if it
/// is the versions root's `current`.
pub fn admit_cmd(artifact: &Path) -> Result<()> {
    if !is_root() {
        bail!("root's copies of wicket are root's to make: sudo wicket self admit {}", artifact.display());
    }
    let l = Layout::installed();
    let id = l.admit(artifact)?;
    println!("[self] root's copy of {id}: {}", l.copy(&id).display());
    match l.versions_pointer("current") {
        Some(c) if c == id => {
            if l.linked().as_deref() != Some(id.as_str()) {
                l.link_to(&id)?;
                println!("[self] {} now runs it", l.link.display());
            }
        }
        c => println!(
            "[self] {} keeps running {} (the versions root's current is {}); to apply this build's systemd units: sudo {} self apply-units",
            l.link.display(),
            l.linked().as_deref().unwrap_or("what it ran"),
            c.as_deref().unwrap_or("not set"),
            l.copy(&id).display()
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn me() -> Account {
        // SAFETY: plain getters.
        Account { uid: unsafe { libc::geteuid() }, groups: vec![unsafe { libc::getegid() }] }
    }

    /// Someone else: what root's own files look like to the untrusted account.
    fn nobody() -> Account {
        Account { uid: u32::MAX - 1, groups: vec![u32::MAX - 1] }
    }

    fn tmp(name: &str) -> (PathBuf, Remove) {
        let d = std::env::temp_dir().join(format!("wicket-rootcopy-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        (d.clone(), Remove(d))
    }

    /// A root-owned file outside any directory this test's user owns, to admit.
    fn roots_binary() -> PathBuf {
        ["/usr/bin/true", "/bin/true"].iter().map(PathBuf::from).find(|p| p.is_file()).expect("a true binary")
    }

    #[test]
    fn what_the_untrusted_user_owns_is_writable() {
        let (d, _c) = tmp("writable");
        let f = d.join("wicket");
        std::fs::write(&f, "x").unwrap();
        let why = writable_by(&f, &me()).unwrap();
        assert!(why.contains("owned by the wicket user"), "{why}");
        // A root file in root's directories isn't.
        if unsafe { libc::geteuid() } != 0 {
            assert_eq!(writable_by(&roots_binary(), &me()), None);
        }
        // Writable by everyone, or by the user's group.
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(writable_by(&f, &nobody()).unwrap().contains("writable by everyone"));
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o664)).unwrap();
        let gid = std::fs::metadata(&f).unwrap().gid();
        let member = Account { uid: u32::MAX - 1, groups: vec![gid] };
        assert!(writable_by(&f, &member).unwrap().contains("writable by group"));
        // A sticky, world-writable directory (as /tmp) protects what others own in it.
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o1777)).unwrap();
        let m = std::fs::metadata(&d).unwrap();
        assert_eq!(mode_writable(&d, &m, &nobody()), None);
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(mode_writable(&d, &std::fs::metadata(&d).unwrap(), &nobody()).unwrap().contains("everyone"));
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// The versions root, root's copies and root's link, under `d`: version `id` staged with
    /// `bin`'s bytes and current.
    fn layout(d: &Path, untrusted: Option<Account>) -> Layout {
        let l = Layout { copies: d.join("copies"), link: d.join("bin/wicket"), versions: d.join("versions"), untrusted };
        std::fs::create_dir_all(d.join("bin")).unwrap();
        std::fs::create_dir_all(&l.versions).unwrap();
        l
    }

    fn stage(l: &Layout, bytes: &[u8]) -> String {
        let id = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(bytes))[..12].to_string();
        std::fs::create_dir_all(l.versions.join(&id)).unwrap();
        std::fs::write(l.versions.join(&id).join("wicket"), bytes).unwrap();
        let tmp = l.versions.join(".current.new");
        let _ = std::fs::remove_file(&tmp);
        std::os::unix::fs::symlink(&id, &tmp).unwrap();
        std::fs::rename(&tmp, l.versions.join("current")).unwrap();
        id
    }

    #[test]
    fn root_refuses_to_copy_a_binary_the_wicket_user_planted() {
        let (d, _c) = tmp("planted");
        let l = layout(&d, Some(me()));
        let bytes = std::fs::read(roots_binary()).unwrap();
        let id = stage(&l, &bytes);
        // The wicket user replaces its staged version.
        std::fs::write(l.versions.join(&id).join("wicket"), b"\x7fELF planted").unwrap();
        let e = l.admit(&l.versions.join(&id).join("wicket")).unwrap_err().to_string();
        assert!(e.contains("refused") && e.contains("owned by the wicket user"), "{e}");
        assert!(!l.copy(&id).exists());
        // Nor into copies the wicket user can write.
        let e = l.admit(&roots_binary()).unwrap_err().to_string();
        if unsafe { libc::geteuid() } != 0 {
            assert!(e.contains("root's copies must be root's alone"), "{e}");
        }
        // And through a link to it, from a directory it doesn't own.
        std::os::unix::fs::symlink(l.versions.join(&id).join("wicket"), d.join("bin/innocent")).unwrap();
        assert!(l.admit(&d.join("bin/innocent")).is_err());
    }

    #[test]
    fn root_runs_its_own_copy_whatever_the_versions_root_holds() {
        if unsafe { libc::geteuid() } == 0 {
            return; // root owns everything here: the "root's" binary test needs another owner
        }
        let (d, _c) = tmp("own");
        // The untrusted account is someone else here: this test's user stands for root.
        let l = layout(&d, Some(nobody()));
        let bytes = std::fs::read(roots_binary()).unwrap();
        // Root admits the artifact it names (a file root, not this user, owns), then the update
        // stages the same build as the wicket user's current.
        let id = l.admit(&roots_binary()).unwrap();
        assert_eq!(stage(&l, &bytes), id);
        assert_eq!(std::fs::metadata(l.copy(&id)).unwrap().permissions().mode() & 0o777, 0o755);
        l.relink().unwrap();
        assert_eq!(l.linked().as_deref(), Some(id.as_str()));
        assert_eq!(std::fs::canonicalize(&l.link).unwrap(), std::fs::canonicalize(l.copy(&id)).unwrap());
        // The wicket user plants another binary in its version: root's link still runs root's bytes.
        std::fs::write(l.versions.join(&id).join("wicket"), b"\x7fELF planted").unwrap();
        l.relink().unwrap();
        assert_eq!(std::fs::read(&l.link).unwrap(), bytes);
        // A current root has no copy of (a CI build the wicket user downloaded): the link stays.
        let other = stage(&l, b"\x7fELF another build");
        l.relink().unwrap();
        assert_eq!(l.linked().as_deref(), Some(id.as_str()));
        assert!(!l.copy(&other).exists());
        // Admitting again is a no-op; a stale copy is pruned once the link moves past it.
        assert_eq!(l.admit(&roots_binary()).unwrap(), id);
        std::fs::create_dir_all(l.copies.join("0123456789ab")).unwrap();
        std::fs::write(l.copy("0123456789ab"), "old").unwrap();
        let back = l.versions.join(".current.new");
        std::os::unix::fs::symlink(&id, &back).unwrap();
        std::fs::rename(&back, l.versions.join("current")).unwrap();
        std::fs::remove_file(&l.link).unwrap();
        l.relink().unwrap();
        assert!(!l.copies.join("0123456789ab").exists());
        assert!(l.copy(&id).is_file());
    }

    #[test]
    fn an_archive_gives_its_wicket() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let (d, _c) = tmp("archive");
        let l = layout(&d, None);
        let src = d.join("src/wicket-0.0.0-x86_64-linux");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::copy(roots_binary(), src.join("wicket")).unwrap();
        let st = std::process::Command::new("tar")
            .args(["-czf", d.join("a.tar.gz").to_str().unwrap(), "-C", d.join("src").to_str().unwrap(), "wicket-0.0.0-x86_64-linux"])
            .status()
            .unwrap();
        assert!(st.success());
        let id = l.admit(&d.join("a.tar.gz")).unwrap();
        assert_eq!(std::fs::read(l.copy(&id)).unwrap(), std::fs::read(roots_binary()).unwrap());
        // No stage left behind.
        let left: Vec<_> = std::fs::read_dir(&l.copies).unwrap().flatten().map(|e| e.file_name()).collect();
        assert_eq!(left, vec![std::ffi::OsString::from(&id)]);
    }
}
