//! What the second slice's scenarios ([`crate::placement`], [`crate::messages`]) share: a trace
//! (hashed always, for the determinism check, and kept for a replay) with the violations found, and
//! the report a run makes.

use std::fmt;

/// The scenarios a seed runs, by the name `WICKET_SIM_SCENARIO` takes.
pub const SCENARIOS: [&str; 3] = ["feed", "placement", "messages"];

/// The command that replays `seed` of `scenario`, printed with every failure.
pub fn replay_command(scenario: &str, seed: u64) -> String {
    format!("WICKET_SIM_SEED={seed} WICKET_SIM_SCENARIO={scenario} cargo test -p wicket-sim --test scenario replay -- --nocapture")
}

pub struct Trace {
    pub violations: Vec<String>,
    lines: Vec<String>,
    hash: u64,
    keep: bool,
    /// Time 0 of the scenario, for the violations' "at" (in the scenario's own unit).
    epoch: i64,
}

impl Trace {
    pub fn new(epoch: i64, keep: bool) -> Trace {
        Trace { violations: vec![], lines: vec![], hash: 0xcbf2_9ce4_8422_2325, keep, epoch }
    }

    /// Records one line: hashed always, kept if asked.
    pub fn note(&mut self, t: i64, line: impl Into<String>) {
        let line = format!("{t} {}", line.into());
        for b in line.bytes().chain(std::iter::once(b'\n')) {
            self.hash ^= u64::from(b);
            self.hash = self.hash.wrapping_mul(0x0100_0000_01b3);
        }
        if self.keep {
            self.lines.push(line);
        }
    }

    pub fn violate(&mut self, t: i64, what: impl Into<String>) {
        let what = what.into();
        self.note(t, format!("VIOLATION {what}"));
        self.violations.push(format!("at {}: {what}", t - self.epoch));
    }

    pub fn hash(&self) -> u64 {
        self.hash
    }

    pub fn lines(&self) -> &[String] {
        &self.lines
    }
}

/// What one run of a scenario found.
#[derive(Debug)]
pub struct Report {
    pub scenario: &'static str,
    pub seed: u64,
    /// The plan, as printed.
    pub plan: String,
    pub violations: Vec<String>,
    /// What it found that is known and not yet fixed: reported, not counted as violations.
    pub known: Vec<String>,
    /// A hash of the whole trace: equal for equal seeds.
    pub hash: u64,
    pub stats: String,
    pub trace: Vec<String>,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.violations.is_empty()
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.plan)?;
        writeln!(f, "  stats: {}", self.stats)?;
        writeln!(f, "  trace hash: {:016x}", self.hash)?;
        for v in &self.violations {
            writeln!(f, "  VIOLATION {v}")?;
        }
        for k in &self.known {
            writeln!(f, "  KNOWN {k}")?;
        }
        if !self.ok() {
            writeln!(f, "  replay: {}", replay_command(self.scenario, self.seed))?;
        }
        Ok(())
    }
}
