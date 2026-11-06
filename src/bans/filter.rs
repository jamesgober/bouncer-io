//! A blocked Bloom filter in front of the ban table's address keys (D-125).
//!
//! Every address key lives in the block of its anchor prefix (the family's
//! shortest automatic length, as in the table, D-104), so one 64-byte block
//! answers for every automatic length of an address. A key sets one bit in
//! each of the block's eight words. "No" is exact: the key is not in the
//! table. "Maybe" sends the door to the table for that length.
//!
//! Lifts and expiries leave their bits set, which only adds false "maybe"s.
//! When enough have built up, the writer rebuilds the filter from the table
//! into the second buffer and switches to it. Each buffer has a generation
//! word, odd while it is cleared and filled, which readers check around
//! their read (a sequence lock): a reader that read a buffer while it was
//! rebuilt answers "maybe" for everything.

use crate::{
    hash::HashKey,
    sync::{AtomicU64, Ordering, fence},
};

use super::table::TableKey;

/// Words per block: one cache line (two under loom, to keep its models
/// small).
#[cfg(not(bouncer_loom))]
const WORDS: usize = 8;
#[cfg(bouncer_loom)]
const WORDS: usize = 2;
/// Filter bits per ban the table can hold, at least (each buffer).
const BITS_PER_KEY: usize = 6;
/// Stale keys a rebuild waits for, at least.
const MIN_STALE: u64 = 4096;

#[cfg_attr(not(bouncer_loom), repr(C, align(64)))]
struct Block([AtomicU64; WORDS]);

pub(crate) struct Filter {
    bufs: [Box<[Block]>; 2],
    /// Each buffer's generation: odd while it is being rebuilt.
    gens: [AtomicU64; 2],
    /// The buffer inserts and readers use (0 or 1).
    active: AtomicU64,
    mask: usize,
    key: HashKey,
}

/// Writer-side counts, kept under the ban memory's writer lock.
#[derive(Debug, Default)]
pub(crate) struct FilterCounts {
    /// Keys added since the last rebuild.
    pub(crate) added: u64,
    /// Keys removed from the table since the last rebuild (their bits
    /// stay).
    pub(crate) stale: u64,
    pub(crate) rebuilds: u64,
}

impl FilterCounts {
    /// Whether stale bits are a third or more of what the filter holds.
    pub(crate) fn wants_rebuild(&self) -> bool {
        self.stale >= MIN_STALE && self.stale * 3 >= self.added
    }
}

impl Filter {
    /// A filter of about `BITS_PER_KEY` bits per ban `capacity` allows,
    /// in a power of two of blocks.
    pub(crate) fn new(capacity: u32, key: HashKey) -> Filter {
        let bits = (capacity as usize).max(1) * BITS_PER_KEY;
        let n = (bits / (WORDS * 64)).max(1).next_power_of_two();
        let buf = || -> Box<[Block]> {
            (0..n)
                .map(|_| Block(core::array::from_fn(|_| AtomicU64::new(0))))
                .collect()
        };
        Filter {
            bufs: [buf(), buf()],
            gens: [AtomicU64::new(0), AtomicU64::new(0)],
            active: AtomicU64::new(0),
            mask: n - 1,
            key,
        }
    }

    #[inline]
    fn hash(&self, k: &TableKey) -> u64 {
        self.key
            .mix3((u64::from(k.kind) << 8) | u64::from(k.len), k.k0, k.k1)
    }

    #[inline]
    fn index(&self, anchor: &TableKey) -> usize {
        self.hash(anchor) as usize & self.mask
    }

    fn set(block: &Block, h: u64) {
        for (i, w) in block.0.iter().enumerate() {
            w.fetch_or(1u64 << ((h >> (6 * i)) & 63), Ordering::Relaxed);
        }
    }

    /// Marks `key`, whose anchor prefix is `anchor`. Called before the key
    /// is written to the table, under the writer lock.
    pub(crate) fn add(&self, anchor: &TableKey, key: &TableKey) {
        let buf = &self.bufs[self.active.load(Ordering::Relaxed) as usize & 1];
        Self::set(&buf[self.index(anchor)], self.hash(key));
    }

    /// One bit per key of `keys` (all anchored at `anchor`): set when that
    /// key may be in the table. A clear bit is exact.
    #[inline]
    pub(crate) fn maybe(&self, anchor: &TableKey, keys: &[TableKey]) -> u32 {
        let all = (1u32 << keys.len()) - 1;
        let b = self.active.load(Ordering::Acquire) as usize & 1;
        let gen_ = &self.gens[b];
        let g = gen_.load(Ordering::Acquire);
        if g & 1 != 0 {
            return all;
        }
        let block = &self.bufs[b][self.index(anchor)];
        let words: [u64; WORDS] = core::array::from_fn(|i| block.0[i].load(Ordering::Relaxed));
        fence(Ordering::Acquire);
        if gen_.load(Ordering::Relaxed) != g {
            return all;
        }
        let mut out = 0;
        for (n, k) in keys.iter().enumerate() {
            let h = self.hash(k);
            let mut hit = true;
            for (i, w) in words.iter().enumerate() {
                hit &= w >> ((h >> (6 * i)) & 63) & 1 != 0;
            }
            out |= u32::from(hit) << n;
        }
        out
    }

    /// Rebuilds the filter into the other buffer and switches to it:
    /// `fill` is given a function to call with every address key in the
    /// table and its anchor. The caller holds the writer lock, so no key is
    /// added meanwhile.
    pub(crate) fn rebuild(&self, fill: impl FnOnce(&mut dyn FnMut(&TableKey, &TableKey))) {
        let next = (self.active.load(Ordering::Relaxed) as usize & 1) ^ 1;
        let gen_ = &self.gens[next];
        let g = gen_.load(Ordering::Relaxed);
        gen_.store(g.wrapping_add(1), Ordering::Relaxed);
        fence(Ordering::Release);
        let buf = &self.bufs[next];
        for block in buf.iter() {
            for w in &block.0 {
                w.store(0, Ordering::Relaxed);
            }
        }
        fill(&mut |anchor, key| Self::set(&buf[self.index(anchor)], self.hash(key)));
        gen_.store(g.wrapping_add(2), Ordering::Release);
        self.active.store(next as u64, Ordering::Release);
    }

    pub(crate) fn bytes(&self) -> u64 {
        (2 * self.bufs[0].len() * WORDS * 8) as u64
    }
}

#[cfg(all(test, not(bouncer_loom)))]
mod tests {
    use super::*;
    use crate::bans::table::KIND_V4;

    fn k(len: u8, word: u64) -> TableKey {
        TableKey {
            kind: KIND_V4,
            len,
            k0: 0,
            k1: word,
        }
    }

    #[test]
    fn test_filter_never_says_no_for_an_added_key() {
        let f = Filter::new(10_000, HashKey::new(1, 2));
        let mut present = Vec::new();
        for n in 0..10_000u64 {
            let a = k(24, n << 8);
            let key = k(32, (n << 8) | (n & 0xff));
            f.add(&a, &key);
            present.push((a, key));
        }
        for (a, key) in &present {
            assert_eq!(f.maybe(a, &[*key]), 1);
        }
        // Mostly "no" for keys never added.
        let fp = (0..10_000u64)
            .filter(|n| f.maybe(&k(24, n << 8), &[k(32, (n << 8) | 0x1_0000_0000)]) != 0)
            .count();
        assert!(fp < 1_500, "false maybes: {fp}");
    }

    #[test]
    fn test_filter_rebuild_keeps_what_remains_and_drops_the_rest() {
        let f = Filter::new(4096, HashKey::new(3, 4));
        let keys: Vec<_> = (0..4096u64).map(|n| (k(24, n << 8), k(32, (n << 8) | 1))).collect();
        for (a, key) in &keys {
            f.add(a, key);
        }
        let kept = &keys[..100];
        f.rebuild(|add| {
            for (a, key) in kept {
                add(a, key);
            }
        });
        for (a, key) in kept {
            assert_eq!(f.maybe(a, &[*key]), 1, "a kept key reads maybe");
        }
        let gone = keys[100..].iter().filter(|(a, key)| f.maybe(a, &[*key]) != 0).count();
        assert!(gone < 400, "removed keys still maybe: {gone}");
        // Adds after a rebuild land in the new buffer.
        let (a, key) = (k(24, 0xdead_00), k(32, 0xdead_01));
        f.add(&a, &key);
        assert_eq!(f.maybe(&a, &[key]), 1);
        assert_eq!(f.maybe(&a, &[k(24, 0xdead_00), key]) & 2, 2);
    }

    #[test]
    fn test_filter_counts_ask_for_a_rebuild_past_a_third() {
        let mut c = FilterCounts {
            added: 30_000,
            stale: 9_999,
            rebuilds: 0,
        };
        assert!(!c.wants_rebuild());
        c.stale = 10_000;
        assert!(c.wants_rebuild());
        c.added = 9_000;
        c.stale = 3_000;
        assert!(!c.wants_rebuild(), "too few to be worth a rebuild");
    }
}
