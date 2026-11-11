//! A fuzz-style loop over the inbound-frame parser and `Replica::accept_bytes`: random and mutated
//! bytes never panic and never verify. Deterministic (a fixed-seed xorshift), no extra dependency.

use super::*;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

const INTERESTING: &[&[u8]] =
    &[b"{", b"}", b"\"", b".", b"\\u0000", b"\n", b"null", b"[]", b"-1", b"1e999", b"\"t\":\"key\"", b"=", b"/", b"+"];

fn mutate(rng: &mut Rng, src: &[u8]) -> Vec<u8> {
    let mut b = src.to_vec();
    for _ in 0..1 + rng.below(4) {
        match rng.below(7) {
            0 if !b.is_empty() => {
                let i = rng.below(b.len());
                b[i] ^= 1 << rng.below(8);
            }
            1 if !b.is_empty() => {
                let i = rng.below(b.len());
                b[i] = rng.next() as u8;
            }
            2 => b.truncate(rng.below(b.len() + 1)),
            3 if !b.is_empty() => {
                let i = rng.below(b.len());
                let n = rng.below(b.len() - i + 1).min(64);
                b.drain(i..i + n);
            }
            4 => {
                let i = rng.below(b.len() + 1);
                let s = INTERESTING[rng.below(INTERESTING.len())];
                b.splice(i..i, s.iter().copied());
            }
            5 if b.len() > 2 => {
                // Duplicate a slice somewhere else.
                let i = rng.below(b.len());
                let n = rng.below(b.len() - i).min(64);
                let chunk: Vec<u8> = b[i..i + n].to_vec();
                let j = rng.below(b.len() + 1);
                b.splice(j..j, chunk);
            }
            _ => {
                let i = rng.below(b.len() + 1);
                b.insert(i, rng.next() as u8);
            }
        }
    }
    b
}

#[test]
fn random_and_mutated_frames_never_panic_and_never_verify() {
    let (mut cp, mut r) = setup();
    // Valid frames the node has not accepted yet: a delta, a statement, a snapshot and a new
    // certificate. Each would be accepted as is.
    let next_delta = cp.p.commit(vec![add(grant("next", &evil(), T0 + 3_600_000))], T0 + 1).unwrap();
    let next_fresh = cp.p.statement(T0 + 2);
    let next_snap = cp.p.snapshot(T0 + 3);
    let v2 = cert(&cp.root, &cp.feed_key, 2, T0 + 86_400_000);
    let seeds = [next_delta, next_fresh, next_snap, Frame::new(FrameKind::Key, v2)];
    let (epoch, head) = (r.state().unwrap().epoch, r.state().unwrap().head.clone());
    let accepted_before = r.stats.accepted.clone();
    let now = T0 + 10;

    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut tried = 0;
    for _ in 0..2_000 {
        let n = rng.below(512);
        let bytes: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
        assert!(r.accept_bytes(&bytes, now).is_err());
        tried += 1;
    }
    for seed in &seeds {
        let line = seed.to_line().into_bytes();
        for _ in 0..600 {
            let bytes = mutate(&mut rng, &line);
            // A mutation that only touched the JSON wrapper (whitespace, an escape) is the same
            // frame: not a forgery, so not asserted on.
            if let Ok(f) = Frame::parse(&bytes) {
                if f == *seed {
                    continue;
                }
            }
            if let Ok(()) = r.accept_bytes(&bytes, now) {
                panic!("a mutated {:?} frame verified: {:?}", seed.kind, String::from_utf8_lossy(&bytes));
            }
            tried += 1;
        }
    }
    assert!(tried > 3_500);
    let st = r.state().unwrap();
    assert_eq!((st.epoch, &st.head, st.version), (epoch, &head, 1));
    assert_eq!(r.stats.accepted, accepted_before);
    assert_eq!(r.mode(now), Mode::Fresh);
    // The seeds themselves are fine.
    for seed in &seeds[..2] {
        r.accept_bytes(seed.to_line().as_bytes(), now).unwrap();
    }
}

#[test]
fn oversized_frames_are_refused_before_parsing() {
    let (_cp, mut r) = setup();
    let big = vec![b' '; MAX_FRAME_BYTES + 1];
    assert_eq!(r.accept_bytes(&big, T0).unwrap_err().kind(), "malformed");
}
