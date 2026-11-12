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
