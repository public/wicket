//! A run's transcript on the control host (#160): the box's stdout, line by line, in
//! `transcript.jsonl`, kept only up to the zone's `limits.output`, the newest kept. When the current
//! file reaches half the cap it becomes `transcript.1.jsonl` (replacing the one before) and a new one
//! starts, so at most the cap (plus one line) is kept.
//!
//! Where the stdout it holds starts is kept in `ctl/transcript.json`, so a re-attached run (#151)
//! still resumes exactly where the last supervisor got to: the start of the current file plus its
//! length. A supervisor killed between rotating and saving that is told apart by the previous file's
//! inode (the saved one is the file rotated before).

use anyhow::Result;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub const FILE: &str = "transcript.jsonl";
pub const PREVIOUS: &str = "transcript.1.jsonl";
const STATE: &str = "ctl/transcript.json";

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct State {
    /// Where the current file starts in the box's stdout.
    cur: u64,
    /// Where the previous file starts: everything before it is gone (dropped).
    prev: u64,
    /// The previous file's inode, as of the last save.
    prev_ino: u64,
}

pub struct Transcript {
    dir: PathBuf,
    f: std::fs::File,
    half: u64,
    len: u64,
    state: State,
}

impl Transcript {
    /// Opens a run's transcript: a fresh one, or (`resume`) the one a previous supervisor left.
    pub fn open(dir: &Path, cap: u64, resume: bool) -> Result<Transcript> {
        let state = match resume {
            true => resumed(dir),
            false => {
                let _ = std::fs::remove_file(dir.join(PREVIOUS));
                let _ = std::fs::remove_file(dir.join(STATE));
                State::default()
            }
        };
        let f = std::fs::OpenOptions::new().create(true).append(true).open(dir.join(FILE))?;
        if !resume {
            f.set_len(0)?;
        }
        let len = f.metadata()?.len();
        Ok(Transcript { dir: dir.to_path_buf(), f, half: (cap / 2).max(1), len, state })
    }

    /// Appends one line of the box's stdout, rotating at half the cap.
    pub fn line(&mut self, l: &str) -> Result<()> {
        writeln!(self.f, "{l}")?;
        self.len += l.len() as u64 + 1;
        if self.len >= self.half {
            self.rotate()?;
        }
        Ok(())
    }

    fn rotate(&mut self) -> Result<()> {
        std::fs::rename(self.dir.join(FILE), self.dir.join(PREVIOUS))?;
        let ino = std::fs::metadata(self.dir.join(PREVIOUS))?.ino();
        self.state = State { cur: self.state.cur + self.len, prev: self.state.cur, prev_ino: ino };
        std::fs::create_dir_all(self.dir.join("ctl"))?;
        crate::run::write_json(&self.dir.join(STATE), &self.state)?;
        self.f = std::fs::OpenOptions::new().create(true).append(true).open(self.dir.join(FILE))?;
        self.f.set_len(0)?;
        self.len = 0;
        Ok(())
    }

    /// How much of the box's stdout this transcript has taken (bytes).
    pub fn offset(&self) -> u64 {
        self.state.cur + self.len
    }

    /// How much of it is no longer kept (bytes).
    pub fn dropped(&self) -> u64 {
        self.state.prev
    }
}

/// What a previous supervisor left: where the current file starts, whether or not it rotated just
/// before it died without saving.
fn resumed(dir: &Path) -> State {
    let mut s: State = crate::run::read_json(&dir.join(STATE)).unwrap_or_default();
    if let Ok(m) = std::fs::metadata(dir.join(PREVIOUS)) {
        if m.ino() != s.prev_ino {
            // Rotated, not saved: the previous file is the one that was current, and the current one
            // was never started.
            s = State { cur: s.cur + m.len(), prev: s.cur, prev_ino: m.ino() };
            // Saved, so lines written after this aren't taken for the rotation's again.
            let _ = std::fs::create_dir_all(dir.join("ctl"));
            let _ = crate::run::write_json(&dir.join(STATE), &s);
        }
    }
    s
}

/// Where a re-attached run's stdout resumes (bytes), from its transcript.
pub fn resume_offset(dir: &Path) -> u64 {
    resumed(dir).cur + std::fs::metadata(dir.join(FILE)).map(|m| m.len()).unwrap_or(0)
}

/// The absolute offset after the transcript's last byte, as a reader sees it (repairs nothing).
pub fn end_offset(dir: &Path) -> u64 {
    resumed_readonly(dir).cur + std::fs::metadata(dir.join(FILE)).map(|m| m.len()).unwrap_or(0)
}

/// The transcript's last non-empty line (from the previous file if the current one is empty).
pub fn last_line(dir: &Path) -> Option<String> {
    [FILE, PREVIOUS]
        .iter()
        .find_map(|f| std::fs::read_to_string(dir.join(f)).ok()?.lines().rev().find(|l| !l.trim().is_empty()).map(String::from))
}

/// The newest `cap` bytes of a stream kept in memory (whole lines), and how many there were in all.
#[derive(Default)]
pub struct Newest {
    pub text: String,
    pub total: u64,
    cap: usize,
}

impl Newest {
    pub fn new(cap: u64) -> Newest {
        Newest { text: String::new(), total: 0, cap: cap.max(1) as usize }
    }

    pub fn line(&mut self, l: &str) {
        self.total += l.len() as u64 + 1;
        self.text.push_str(l);
        self.text.push('\n');
        if self.text.len() > self.cap {
            // Drop at least what's over, up to a line's end (never inside a character).
            let over = self.text.len() - self.cap;
            let cut = self.text[over..].find('\n').map(|p| over + p + 1).unwrap_or(self.text.len());
            self.text.drain(..cut);
        }
    }

    pub fn dropped(&self) -> u64 {
        self.total - self.text.len() as u64
    }
}

/// What wicket itself said to an ACP agent (#327), next to the transcript of what the agent said:
/// `acp-client.jsonl`, one entry per line, each with `at`, the transcript offset (in the box's stdout)
/// it was written at, so a reader can put both sides back in order. Entries are either `msg` (a
/// JSON-RPC message wicket wrote to the agent's stdin) or `queued` (a prompt handed to wicket's ACP
/// client, with who it is from and the operator message it came from, if any; the client sends its
/// queued prompts in order, one `session/prompt` each). Kept up to a cap, then no longer written.
///
/// A harness that doesn't speak ACP keeps it too (#364): its first entry is then `format`, naming
/// how the session view reads both sides (`wicket_agent::harness::session_view`), and `msg` is what
/// wicket wrote to it in its own protocol (stream-json for Claude Code).
pub const ACP_LOG: &str = "acp-client.jsonl";

pub struct AcpLog {
    f: Option<std::fs::File>,
    len: u64,
    cap: u64,
}

impl AcpLog {
    /// Opens the log of a fresh run (emptied) or a re-attached one (appended to).
    pub fn open(dir: &Path, cap: u64, resume: bool) -> AcpLog {
        let f = std::fs::OpenOptions::new().create(true).append(true).open(dir.join(ACP_LOG)).ok();
        if let (Some(f), false) = (&f, resume) {
            let _ = f.set_len(0);
        }
        let len = f.as_ref().and_then(|f| f.metadata().ok()).map(|m| m.len()).unwrap_or(0);
        AcpLog { f, len, cap }
    }

    fn entry(&mut self, e: serde_json::Value) {
        let line = e.to_string();
        if self.len + line.len() as u64 + 1 > self.cap {
            self.f = None;
        }
        if let Some(f) = self.f.as_mut() {
            if writeln!(f, "{line}").is_ok() {
                self.len += line.len() as u64 + 1;
            }
        }
    }

    /// wicket wrote `lines` (JSON-RPC, newline-separated) to the agent at transcript offset `at`.
    pub fn wrote(&mut self, at: u64, lines: &str) {
        for l in lines.lines().filter(|l| !l.trim().is_empty()) {
            if let Ok(msg) = serde_json::from_str::<serde_json::Value>(l) {
                self.entry(serde_json::json!({ "at": at, "msg": msg }));
            }
        }
    }

    /// The log is of a harness that doesn't speak ACP: how to read it. The first entry of a fresh log.
    pub fn format(&mut self, format: &str) {
        self.entry(serde_json::json!({ "at": 0, "format": format }));
    }

    /// A prompt was queued in wicket's ACP client: from `by`, for operator message `op`.
    pub fn queued(&mut self, at: u64, by: &str, op: Option<i64>) {
        self.entry(serde_json::json!({ "at": at, "queued": { "by": by, "op": op } }));
    }
}

/// The whole lines of a run's transcript from absolute offset `pos` (in the box's stdout), each with
/// the offset it starts at, at most about `max` bytes of them, and the offset after the last one.
/// What is no longer kept is skipped (the returned lines then start later than `pos`).
pub fn read_since(dir: &Path, pos: u64, max: usize) -> (Vec<(u64, String)>, u64) {
    let s = resumed_readonly(dir);
    let mut out = Vec::new();
    let mut pos = pos.max(s.prev);
    let mut budget = max;
    let files = [(PREVIOUS, s.prev, s.cur), (FILE, s.cur, u64::MAX)];
    for (name, start, end) in files {
        if pos >= end || budget == 0 {
            continue;
        }
        let Ok(b) = std::fs::read(dir.join(name)) else { continue };
        let from = (pos.saturating_sub(start)) as usize;
        if from > b.len() {
            continue;
        }
        let mut at = from;
        while let Some(n) = b[at..].iter().position(|&c| c == b'\n') {
            let line = String::from_utf8_lossy(&b[at..at + n]).into_owned();
            out.push((start + at as u64, line));
            at += n + 1;
            budget = budget.saturating_sub(n + 1);
            if budget == 0 {
                break;
            }
        }
        pos = start + at as u64;
        if name == PREVIOUS && at == b.len() {
            pos = pos.max(s.cur);
        }
    }
    (out, pos)
}

/// Where the transcript's files start, as saved (a reader never repairs the state, as [`resumed`] does).
fn resumed_readonly(dir: &Path) -> State {
    crate::run::read_json(&dir.join(STATE)).unwrap_or_default()
}

/// What a run's [`ACP_LOG`] is a log of: None if it has none; `Some(None)` for an ACP agent's;
/// `Some(Some(format))` for a harness read through a session view.
pub fn log_format(dir: &Path) -> Option<Option<String>> {
    use std::io::{BufRead, Read};
    let f = std::fs::File::open(dir.join(ACP_LOG)).ok()?;
    let mut first = String::new();
    let _ = std::io::BufReader::new(f).take(4096).read_line(&mut first);
    let v: serde_json::Value = serde_json::from_str(first.trim()).unwrap_or_default();
    Some(v.get("format").and_then(|f| f.as_str()).map(String::from))
}

/// The whole lines of the run's [`ACP_LOG`] from byte `pos`, and the byte after the last one.
pub fn read_acp_log(dir: &Path, pos: u64, max: usize) -> (Vec<serde_json::Value>, u64) {
    let Ok(b) = std::fs::read(dir.join(ACP_LOG)) else { return (vec![], pos) };
    let mut at = (pos as usize).min(b.len());
    let mut out = Vec::new();
    while let Some(n) = b[at..].iter().position(|&c| c == b'\n') {
        if let Ok(v) = serde_json::from_slice(&b[at..at + n]) {
            out.push(v);
        }
        at += n + 1;
        if out.len() >= max {
            break;
        }
    }
    (out, at as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> PathBuf {
        let d = std::env::temp_dir().join(format!("wicket-transcript-test-{}-{}", std::process::id(), wicket_core::new_request_id()));
        std::fs::create_dir_all(d.join("ctl")).unwrap();
        d
    }

    fn kept(d: &Path) -> u64 {
        [FILE, PREVIOUS].iter().map(|f| std::fs::metadata(d.join(f)).map(|m| m.len()).unwrap_or(0)).sum()
    }

    /// #160: a flood keeps at most the cap, the newest, and the offset stays exact.
    #[test]
    fn a_flood_keeps_the_newest_within_the_cap() {
        let d = scratch();
        let mut t = Transcript::open(&d, 64 << 10, false).unwrap();
        let mut total = 0u64;
        for k in 0..100_000 {
            let l = format!("line {k:08} {}", "x".repeat(40));
            total += l.len() as u64 + 1;
            t.line(&l).unwrap();
            assert!(kept(&d) <= (64 << 10) + 64);
        }
        assert_eq!(t.offset(), total);
        assert_eq!(t.dropped() + kept(&d), total);
        assert!(last_line(&d).unwrap().starts_with("line 00099999"));
        // A new supervisor resumes at the same byte.
        drop(t);
        assert_eq!(resume_offset(&d), total);
        let t = Transcript::open(&d, 64 << 10, true).unwrap();
        assert_eq!(t.offset(), total);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// #160: a supervisor killed between rotating and saving where it got to still resumes exactly.
    #[test]
    fn a_rotation_cut_short_still_resumes_exactly() {
        let d = scratch();
        let mut t = Transcript::open(&d, 1000, false).unwrap();
        for k in 0..20 {
            t.line(&format!("{k:0>99}")).unwrap();
        }
        let at = t.offset();
        drop(t);
        // Saved state from before the last rotation, then a rotation nobody recorded.
        let before = std::fs::read(d.join(STATE)).unwrap();
        let mut t = Transcript::open(&d, 1000, true).unwrap();
        for k in 0..5 {
            t.line(&format!("{k:0>99}")).unwrap();
        }
        let after = t.offset();
        drop(t);
        assert_eq!(resume_offset(&d), after);
        std::fs::write(d.join(STATE), &before).unwrap();
        // The state now says the rotation before last; the rotated file is newer: still exact.
        assert!(after > at);
        assert_eq!(resume_offset(&d), after);
        // A supervisor that took over from that, wrote and died before rotating: still exact.
        let mut t = Transcript::open(&d, 1000, true).unwrap();
        assert_eq!(t.offset(), after);
        t.line("one more").unwrap();
        let more = t.offset();
        drop(t);
        assert_eq!(more, after + 9);
        assert_eq!(resume_offset(&d), more);
        assert_eq!(Transcript::open(&d, 1000, true).unwrap().offset(), more);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_newest_lines_in_memory() {
        let mut n = Newest::new(20);
        for k in 0..10 {
            n.line(&format!("l{k}"));
        }
        assert!(n.text.len() <= 20 && n.text.ends_with("l9\n") && n.text.starts_with('l'));
        assert_eq!(n.total, 30);
        assert_eq!(n.dropped() + n.text.len() as u64, 30);
    }
}
