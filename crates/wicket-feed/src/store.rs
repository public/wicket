//! Durable file writes: atomic replace (write, fsync, rename, fsync the directory) and fsynced appends.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

/// Replaces `path` with `data` atomically and durably.
pub(crate) fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    sync_dir(path)
}

/// Appends one line (adding the newline) and fsyncs before returning.
pub(crate) fn append_line(path: &Path, line: &str) -> io::Result<()> {
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    let mut buf = Vec::with_capacity(line.len() + 1);
    buf.extend_from_slice(line.as_bytes());
    buf.push(b'\n');
    f.write_all(&buf)?;
    f.sync_data()
}

/// fsyncs the directory holding `path`, so a create or rename survives a crash.
pub(crate) fn sync_dir(path: &Path) -> io::Result<()> {
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => File::open(dir)?.sync_all(),
        _ => Ok(()),
    }
}

/// Reads a file, `None` if it doesn't exist.
pub(crate) fn read_opt(path: &Path) -> io::Result<Option<String>> {
    match std::fs::read(path) {
        Ok(b) => String::from_utf8(b)
            .map(Some)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, format!("{} is not UTF-8", path.display()))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Splits a line log into complete lines. A final line without its newline is a torn write (never
/// fsynced in full, so never published or relied on): it is returned separately so the caller can
/// drop it.
pub(crate) fn lines(text: &str) -> (Vec<&str>, Option<&str>) {
    let mut out: Vec<&str> = text.split('\n').collect();
    let torn = out.pop().filter(|l| !l.is_empty());
    (out, torn)
}
