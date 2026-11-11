use std::time::Instant;

pub struct Stats {
    pub n: usize,
    pub median: f64,
    pub p99: f64,
    pub mean: f64,
    pub max: f64,
}

/// Run `f` `n` times (after `n/10` warm-up calls) and report per-call microseconds.
pub fn measure<F: FnMut()>(n: usize, mut f: F) -> Stats {
    for _ in 0..n / 10 {
        f();
    }
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        let s = Instant::now();
        f();
        v.push(s.elapsed().as_nanos() as f64 / 1000.0);
    }
    from_samples(v)
}

pub fn from_samples(mut v: Vec<f64>) -> Stats {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    Stats { n, median: v[n / 2], p99: v[(n * 99 / 100).min(n - 1)], mean: v.iter().sum::<f64>() / n as f64, max: v[n - 1] }
}

impl std::fmt::Display for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:>8.1} | {:>8.1} | {:>8.1} | {:>8.1}", self.median, self.p99, self.mean, self.max)
    }
}
