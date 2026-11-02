//! Keyed hashing for the tables, and the bouncer's random stream.
//!
//! The ban table and the door budgets hash fixed-size keys with a keyed
//! multiply mix (two folded 64-by-64-bit multiplies) under a per-bouncer
//! random key: an attacker who does not know the key cannot choose
//! collisions, and if keys ever do pile up in one probe sequence, the ban
//! table is rebuilt under a fresh key (threat T-9, D-102). Values that leave
//! the process or must not be guessed (references, stored digests) use
//! SipHash-1-3.

use std::{
    collections::hash_map::RandomState,
    hash::{BuildHasher, Hasher},
};

/// A 128-bit SipHash key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HashKey {
    k0: u64,
    k1: u64,
}

impl HashKey {
    pub(crate) const fn new(k0: u64, k1: u64) -> Self {
        Self { k0, k1 }
    }

    /// SipHash-1-3 over three words.
    #[inline]
    pub(crate) fn hash3(&self, a: u64, b: u64, c: u64) -> u64 {
        self.hash3_rounds::<1, 3>(a, b, c)
    }

    /// A keyed multiply mix of two words: two folded multiplies.
    #[inline]
    pub(crate) fn mix2(&self, a: u64, b: u64) -> u64 {
        fold(fold(a ^ self.k0, b ^ self.k1), self.k0 ^ MIX_C)
    }

    /// A keyed multiply mix of three words.
    #[inline]
    pub(crate) fn mix3(&self, a: u64, b: u64, c: u64) -> u64 {
        fold(fold(a ^ self.k0, b ^ self.k1) ^ c, self.k1 ^ MIX_C)
    }

    #[inline]
    fn hash3_rounds<const C: usize, const D: usize>(&self, a: u64, b: u64, c: u64) -> u64 {
        let mut s = State::new(self.k0, self.k1);
        s.word::<C>(a);
        s.word::<C>(b);
        s.word::<C>(c);
        s.finish::<C, D>(24)
    }
}

/// An odd constant (the 64-bit golden ratio) folded into the second key word.
const MIX_C: u64 = 0x9e37_79b9_7f4a_7c15;

/// The high and low words of a 128-bit product, folded together.
#[inline]
fn fold(x: u64, y: u64) -> u64 {
    let p = u128::from(x).wrapping_mul(u128::from(y));
    (p as u64) ^ ((p >> 64) as u64)
}

struct State {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
}

impl State {
    #[inline]
    fn new(k0: u64, k1: u64) -> Self {
        Self {
            v0: k0 ^ 0x736f_6d65_7073_6575,
            v1: k1 ^ 0x646f_7261_6e64_6f6d,
            v2: k0 ^ 0x6c79_6765_6e65_7261,
            v3: k1 ^ 0x7465_6462_7974_6573,
        }
    }

    #[inline]
    fn round(&mut self) {
        self.v0 = self.v0.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(13);
        self.v1 ^= self.v0;
        self.v0 = self.v0.rotate_left(32);
        self.v2 = self.v2.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(16);
        self.v3 ^= self.v2;
        self.v0 = self.v0.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(21);
        self.v3 ^= self.v0;
        self.v2 = self.v2.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(17);
        self.v1 ^= self.v2;
        self.v2 = self.v2.rotate_left(32);
    }

    #[inline]
    fn word<const C: usize>(&mut self, m: u64) {
        self.v3 ^= m;
        for _ in 0..C {
            self.round();
        }
        self.v0 ^= m;
    }

    #[inline]
    fn finish<const C: usize, const D: usize>(mut self, len: u64) -> u64 {
        self.word::<C>(len << 56);
        self.v2 ^= 0xff;
        for _ in 0..D {
            self.round();
        }
        self.v0 ^ self.v1 ^ self.v2 ^ self.v3
    }
}

/// xoshiro256** seeded from SplitMix64: jitter and references. Not used for
/// anything secret.
#[derive(Clone, Debug)]
pub(crate) struct Rng {
    s: [u64; 4],
}

impl Rng {
    pub(crate) fn from_seed(seed: u64) -> Self {
        let mut x = seed;
        let mut next = || {
            x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = x;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        };
        Self {
            s: [next(), next(), next(), next()],
        }
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        let result = self.s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        result
    }

    /// Uniform in `0..=max` (Lemire's multiply-shift; the bias is below
    /// 2^-32 for the ranges used here).
    pub(crate) fn below_or_equal(&mut self, max: u64) -> u64 {
        if max == u64::MAX {
            return self.next_u64();
        }
        ((u128::from(self.next_u64()) * u128::from(max + 1)) >> 64) as u64
    }
}

/// The seeds one bouncer uses, derived from a 32-byte seed so tests and
/// simulations are deterministic.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Seeds {
    pub(crate) tables: HashKey,
    pub(crate) references: HashKey,
    pub(crate) rng: u64,
}

impl Seeds {
    pub(crate) fn from_bytes(seed: [u8; 32]) -> Self {
        let w = |i: usize| {
            u64::from_le_bytes([
                seed[i],
                seed[i + 1],
                seed[i + 2],
                seed[i + 3],
                seed[i + 4],
                seed[i + 5],
                seed[i + 6],
                seed[i + 7],
            ])
        };
        let (a, b, c, d) = (w(0), w(8), w(16), w(24));
        let mut rng = Rng::from_seed(a ^ c.rotate_left(17));
        Self {
            tables: HashKey::new(a, b),
            references: HashKey::new(c ^ rng.next_u64(), d ^ rng.next_u64()),
            rng: rng.next_u64() ^ d,
        }
    }

    /// Random seeds from the operating system, through `RandomState` (which
    /// the standard library seeds from the OS once per thread and varies per
    /// instance).
    pub(crate) fn random() -> Self {
        let mut bytes = [0u8; 32];
        for (i, chunk) in bytes.chunks_mut(8).enumerate() {
            let mut h = RandomState::new().build_hasher();
            h.write_usize(i);
            chunk.copy_from_slice(&h.finish().to_le_bytes());
        }
        Self::from_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The round function, message schedule, and finalization are checked
    /// against the standard library's SipHash-2-4; SipHash-1-3 is the same
    /// construction with fewer rounds.
    #[test]
    #[allow(deprecated)]
    fn test_siphash_rounds_match_std_siphash24() {
        for (k0, k1, a, b, c) in [
            (0u64, 0u64, 0u64, 0u64, 0u64),
            (1, 2, 3, 4, 5),
            (u64::MAX, 7, 9, u64::MAX, 11),
        ] {
            let mut std_h = std::hash::SipHasher::new_with_keys(k0, k1);
            std_h.write_u64(a);
            std_h.write_u64(b);
            std_h.write_u64(c);
            assert_eq!(
                HashKey::new(k0, k1).hash3_rounds::<2, 4>(a, b, c),
                std_h.finish()
            );
        }
    }

    #[test]
    fn test_siphash_differs_by_key_and_input() {
        let a = HashKey::new(1, 2);
        let b = HashKey::new(1, 3);
        assert_ne!(a.hash3(1, 2, 3), b.hash3(1, 2, 3));
        assert_ne!(a.hash3(1, 2, 3), a.hash3(1, 2, 4));
        assert_eq!(a.hash3(9, 9, 9), a.hash3(9, 9, 9));
    }

    #[test]
    fn test_siphash_spreads_sequential_keys() {
        let k = HashKey::new(0x0123_4567, 0x89ab_cdef);
        let mut buckets = [0u32; 64];
        for i in 0..64_000u64 {
            buckets[(k.hash3(i, 0, 0) >> 58) as usize] += 1;
        }
        for &c in &buckets {
            assert!((800..1200).contains(&c), "bucket count {c}");
        }
    }

    #[test]
    fn test_rng_deterministic_and_bounded() {
        let mut a = Rng::from_seed(7);
        let mut b = Rng::from_seed(7);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        for _ in 0..1000 {
            assert!(a.below_or_equal(60) <= 60);
        }
        assert_eq!(a.below_or_equal(0), 0);
        let _ = a.below_or_equal(u64::MAX);
    }

    #[test]
    fn test_seeds_from_bytes_deterministic_random_differs() {
        let s1 = Seeds::from_bytes([3; 32]);
        let s2 = Seeds::from_bytes([3; 32]);
        assert_eq!(s1.tables, s2.tables);
        assert_eq!(s1.rng, s2.rng);
        let r1 = Seeds::random();
        let r2 = Seeds::random();
        assert_ne!(r1.tables, r2.tables);
    }
}
