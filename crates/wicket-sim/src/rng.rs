//! The simulation's own randomness: SplitMix64, seeded. Every choice the scenario makes (its plan,
//! the boxes' requests, the stand-in upstream's usage) comes from here, so a seed replays.

#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed ^ 0x5DEE_CE66_D1CE_4E5B)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `lo..=hi`.
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        assert!(lo <= hi);
        lo + self.next_u64() % (hi - lo + 1)
    }

    pub fn range_i(&mut self, lo: i64, hi: i64) -> i64 {
        lo + self.range(0, (hi - lo) as u64) as i64
    }

    /// True with probability `p`.
    pub fn chance(&mut self, p: f64) -> bool {
        ((self.next_u64() >> 11) as f64 / (1u64 << 53) as f64) < p
    }

    /// A fresh 32-byte seed (for keys).
    pub fn bytes32(&mut self) -> [u8; 32] {
        let mut b = [0u8; 32];
        for c in b.chunks_mut(8) {
            c.copy_from_slice(&self.next_u64().to_le_bytes());
        }
        b
    }

    /// A child generator, for one host or box.
    pub fn fork(&mut self) -> Rng {
        Rng::new(self.next_u64())
    }
}
