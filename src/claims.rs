//! A lock-free table of keyed slots for counters: strike windows, budget
//! cells, refusal sampling.
//!
//! A slot is claimed by a compare-and-swap of its key word from zero to the
//! key's 64-bit keyed hash. A slot can carry a payload beside its key word
//! (a rate cell's arrival time, a connection count), so a probe and the
//! payload it finds share a cache line; callers with larger payloads keep
//! them in a parallel array of their own. Every probe for one key visits the
//! same slots in the same order and claims the first empty one, so two
//! threads adding the same key meet at the same slot. A slot whose payload
//! has gone idle (a recovered budget, an expired strike window) can be taken
//! over by another key; the caller decides when a payload is idle. Memory is
//! fixed at construction.

use crate::sync::{AtomicU64, Ordering};

/// Slots a probe visits.
const PROBE: usize = 16;

/// A key word and its payload: 8 bytes with none, 16 with a one-word
/// payload (the allocator's 16-byte alignment keeps such a slot within one
/// cache line; alignment is a matter of speed only).
#[repr(C)]
struct Slot<P> {
    key: AtomicU64,
    val: P,
}

pub(crate) struct Claims<P = ()> {
    slots: Box<[Slot<P>]>,
    mask: usize,
}

impl Claims<()> {
    /// A key hash usable as a slot key: never zero.
    #[inline]
    pub(crate) fn key(h: u64) -> u64 {
        h | 1
    }
}

impl<P: Default> Claims<P> {
    /// At least `capacity` slots, rounded up to a power of two (at least 16),
    /// each payload at its default.
    pub(crate) fn new(capacity: u32) -> Claims<P> {
        let n = (capacity as usize).next_power_of_two().max(PROBE);
        Claims {
            slots: (0..n)
                .map(|_| Slot {
                    key: AtomicU64::new(0),
                    val: P::default(),
                })
                .collect(),
            mask: n - 1,
        }
    }
}

impl<P> Claims<P> {
    pub(crate) fn len(&self) -> usize {
        self.slots.len()
    }

    /// The payload of a slot.
    #[inline]
    pub(crate) fn val(&self, slot: usize) -> &P {
        &self.slots[slot].val
    }

    /// Claimed slots for which `active` holds (a key that has not
    /// recovered), 0 to 1 of the table (a full scan). Recovered keys are
    /// reclaimed on demand, so they do not count toward a full table.
    pub(crate) fn active_load(&self, active: impl Fn(usize) -> bool) -> f32 {
        let used = (0..self.slots.len())
            .filter(|&i| self.slots[i].key.load(Ordering::Relaxed) != 0 && active(i))
            .count();
        used as f32 / self.slots.len() as f32
    }

    #[inline]
    fn start(&self, key: u64) -> usize {
        (key.rotate_right(17) as usize) & self.mask
    }

    /// The slot holding `key`, if any.
    #[inline]
    pub(crate) fn find(&self, key: u64) -> Option<usize> {
        let mut i = self.start(key);
        for _ in 0..PROBE {
            match self.slots[i].key.load(Ordering::Acquire) {
                k if k == key => return Some(i),
                0 => return None,
                _ => i = (i + 1) & self.mask,
            }
        }
        None
    }

    /// The slot holding `key`, claiming an empty one or taking over an idle
    /// one on its probe path. `idle(slot)` says whether another key's slot
    /// may be taken; `reset(slot)` prepares a taken-over slot's payload.
    /// Returns the slot and whether it is new to this key; `None` when every
    /// slot on the path is held and busy.
    #[inline]
    pub(crate) fn find_or_claim(
        &self,
        key: u64,
        idle: impl Fn(usize) -> bool,
        reset: impl Fn(usize),
    ) -> Option<(usize, bool)> {
        let mut i = self.start(key);
        let mut idle_slot: Option<(usize, u64)> = None;
        for _ in 0..PROBE {
            let word = &self.slots[i].key;
            let k = word.load(Ordering::Acquire);
            if k == key {
                return Some((i, false));
            }
            if k == 0 {
                match word.compare_exchange(0, key, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => return Some((i, true)),
                    Err(actual) if actual == key => return Some((i, false)),
                    Err(_) => {}
                }
            } else if idle_slot.is_none() && idle(i) {
                idle_slot = Some((i, k));
            }
            i = (i + 1) & self.mask;
        }
        let (slot, old) = idle_slot?;
        match self.slots[slot]
            .key
            .compare_exchange(old, key, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {
                reset(slot);
                Some((slot, true))
            }
            Err(actual) if actual == key => Some((slot, false)),
            Err(_) => None,
        }
    }

    /// Bytes reserved by the slots (key words and payloads).
    /// As [`find_or_claim`](Self::find_or_claim), but a full path never
    /// refuses: with no empty and no idle slot, the slot with the lowest
    /// `score` on the path is taken over (the earliest on a tie). Returns the
    /// slot, whether it is new to `key`, and whether a live payload was
    /// evicted for it. `None` only when every takeover lost its race.
    pub(crate) fn find_or_claim_lowest(
        &self,
        key: u64,
        idle: impl Fn(usize) -> bool,
        score: impl Fn(usize) -> u64,
        reset: impl Fn(usize),
    ) -> Option<(usize, bool, bool)> {
        let mut i = self.start(key);
        let mut idle_slot: Option<(usize, u64)> = None;
        let mut lowest: Option<(usize, u64, u64)> = None;
        for _ in 0..PROBE {
            let word = &self.slots[i].key;
            let k = word.load(Ordering::Acquire);
            if k == key {
                return Some((i, false, false));
            }
            if k == 0 {
                match word.compare_exchange(0, key, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => return Some((i, true, false)),
                    Err(actual) if actual == key => return Some((i, false, false)),
                    Err(_) => {}
                }
            } else if idle_slot.is_none() && idle(i) {
                idle_slot = Some((i, k));
            } else if idle_slot.is_none() {
                let s = score(i);
                if lowest.is_none_or(|(_, _, best)| s < best) {
                    lowest = Some((i, k, s));
                }
            }
            i = (i + 1) & self.mask;
        }
        let (slot, old, evicted) = match (idle_slot, lowest) {
            (Some((slot, old)), _) => (slot, old, false),
            (None, Some((slot, old, _))) => (slot, old, true),
            (None, None) => return None,
        };
        match self.slots[slot]
            .key
            .compare_exchange(old, key, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {
                reset(slot);
                Some((slot, true, evicted))
            }
            Err(actual) if actual == key => Some((slot, false, false)),
            Err(_) => None,
        }
    }

    pub(crate) fn bytes(&self) -> u64 {
        (self.slots.len() * core::mem::size_of::<Slot<P>>()) as u64
    }
}

/// Bits of a [`Counts`] word that hold the count; the rest hold the key.
const COUNT_BITS: u32 = 20;
/// The largest count a slot holds.
pub(crate) const COUNT_MAX: u32 = (1 << COUNT_BITS) - 1;
/// Probes an acquire makes while slots change under it, before it fails
/// closed.
const ATTEMPTS: usize = 8;

/// Counters (live connections, requests in flight) whose key and count share
/// one word. Taking over an idle slot and counting into a slot are each one
/// compare-and-swap of that word, so a count can never land under a key that
/// replaced the one it was meant for, and a slot is never taken over while
/// its count is above zero (with a separate count, both could happen between
/// a probe and its increment). The word keeps the key's top 44 bits; two
/// keys that share them share a count (more strict, never less).
pub(crate) struct Counts {
    words: Box<[AtomicU64]>,
    mask: usize,
}

impl Counts {
    /// At least `capacity` slots, rounded up to a power of two (at least 16).
    pub(crate) fn new(capacity: u32) -> Counts {
        let n = (capacity as usize).next_power_of_two().max(PROBE);
        Counts {
            words: (0..n).map(|_| AtomicU64::new(0)).collect(),
            mask: n - 1,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.words.len()
    }

    /// The key part of a word for `key` (a [`Claims::key`] hash): never zero.
    #[inline]
    fn tag(key: u64) -> u64 {
        (key >> COUNT_BITS) | 1
    }

    #[inline]
    fn start(key: u64) -> u64 {
        key.rotate_right(17)
    }

    /// Counts one under `key` when its count is below `limit` (or `over_ok`
    /// says the key may exceed it, asked only then). `Ok(true)` counted;
    /// `Ok(false)` not counted, every slot on the key's path held by another
    /// key with a live count; `Err(())` at the limit, nothing counted (also
    /// when the slots keep changing under the probe: fail closed).
    #[inline]
    pub(crate) fn acquire(
        &self,
        key: u64,
        limit: u32,
        over_ok: impl Fn() -> bool,
    ) -> Result<bool, ()> {
        let tag = Self::tag(key);
        let limit = u64::from(limit.min(COUNT_MAX));
        let fresh = (tag << COUNT_BITS) | 1;
        'attempt: for _ in 0..ATTEMPTS {
            let mut i = Self::start(key) as usize & self.mask;
            let mut idle: Option<(usize, u64)> = None;
            for _ in 0..PROBE {
                let word = &self.words[i];
                let mut w = word.load(Ordering::Acquire);
                if w == 0 {
                    match word.compare_exchange(0, fresh, Ordering::AcqRel, Ordering::Acquire) {
                        Ok(_) => return Ok(true),
                        Err(actual) => w = actual,
                    }
                }
                if w >> COUNT_BITS == tag {
                    loop {
                        let count = w & u64::from(COUNT_MAX);
                        if count == u64::from(COUNT_MAX) || (count >= limit && !over_ok()) {
                            return Err(());
                        }
                        match word.compare_exchange_weak(
                            w,
                            w + 1,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        ) {
                            Ok(_) => return Ok(true),
                            Err(actual) if actual >> COUNT_BITS == tag => w = actual,
                            // Taken over since it was read: its count was
                            // zero, so nothing of this key is lost.
                            Err(_) => continue 'attempt,
                        }
                    }
                }
                if idle.is_none() && w & u64::from(COUNT_MAX) == 0 {
                    idle = Some((i, w));
                }
                i = (i + 1) & self.mask;
            }
            let Some((slot, w)) = idle else {
                return Ok(false);
            };
            // Succeeds only if the slot still holds that key at zero; on a
            // race, probe again (the winner may have been this key).
            if self.words[slot]
                .compare_exchange(w, fresh, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(true);
            }
        }
        Err(())
    }

    /// Takes one from `key`'s count. A key can briefly hold two slots (two
    /// threads taking over different idle slots for it at once), so a
    /// matching slot at zero does not end the probe.
    #[inline]
    pub(crate) fn release(&self, key: u64) {
        let tag = Self::tag(key);
        let mut i = Self::start(key) as usize & self.mask;
        for _ in 0..PROBE {
            let word = &self.words[i];
            let mut w = word.load(Ordering::Acquire);
            if w == 0 {
                return;
            }
            while w >> COUNT_BITS == tag && w & u64::from(COUNT_MAX) > 0 {
                match word.compare_exchange_weak(w, w - 1, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => return,
                    Err(actual) => w = actual,
                }
            }
            i = (i + 1) & self.mask;
        }
    }

    /// `key`'s count (0 when it has no slot).
    pub(crate) fn count(&self, key: u64) -> u32 {
        let tag = Self::tag(key);
        let mut i = Self::start(key) as usize & self.mask;
        let mut total = 0u32;
        for _ in 0..PROBE {
            let w = self.words[i].load(Ordering::Acquire);
            if w == 0 {
                break;
            }
            if w >> COUNT_BITS == tag {
                total = total.saturating_add((w & u64::from(COUNT_MAX)) as u32);
            }
            i = (i + 1) & self.mask;
        }
        total
    }

    /// Slots with a count above zero, 0 to 1 of the table (a full scan).
    pub(crate) fn active_load(&self) -> f32 {
        let used = self
            .words
            .iter()
            .filter(|w| w.load(Ordering::Relaxed) & u64::from(COUNT_MAX) != 0)
            .count();
        used as f32 / self.words.len() as f32
    }

    /// Bytes reserved by the words.
    pub(crate) fn bytes(&self) -> u64 {
        (self.words.len() * 8) as u64
    }
}

#[cfg(all(test, not(bouncer_loom)))]
mod tests {
    use super::*;

    #[test]
    fn test_claims_find_and_claim_same_slot() {
        let c: Claims = Claims::new(64);
        let k = Claims::key(42);
        assert_eq!(c.find(k), None);
        let (s, new) = c.find_or_claim(k, |_| false, |_| {}).unwrap();
        assert!(new);
        assert_eq!(c.find(k), Some(s));
        assert_eq!(c.find_or_claim(k, |_| false, |_| {}), Some((s, false)));
    }

    #[test]
    fn test_claims_full_path_then_idle_takeover() {
        let c: Claims = Claims::new(16);
        for i in 1..=16u64 {
            assert!(
                c.find_or_claim(Claims::key(i << 1), |_| false, |_| {})
                    .is_some()
            );
        }
        assert!(
            c.find_or_claim(Claims::key(999 << 1), |_| false, |_| {})
                .is_none()
        );
        let reset = std::cell::Cell::new(false);
        let got = c.find_or_claim(Claims::key(999 << 1), |_| true, |_| reset.set(true));
        assert!(matches!(got, Some((_, true))));
        assert!(reset.get());
    }

    #[test]
    fn test_claims_concurrent_same_key_one_slot() {
        let c = std::sync::Arc::new(Claims::<()>::new(1024));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let c = std::sync::Arc::clone(&c);
                std::thread::spawn(move || {
                    (0..1000u64)
                        .map(|k| {
                            c.find_or_claim(Claims::key(k << 1), |_| false, |_| {})
                                .map(|s| s.0)
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let results: Vec<Vec<Option<usize>>> =
            handles.into_iter().map(|h| h.join().unwrap()).collect();
        for k in 0..1000 {
            let first = results[0][k];
            assert!(
                results.iter().all(|r| r[k] == first),
                "key {k} landed in different slots"
            );
        }
    }
}

#[cfg(all(test, bouncer_loom))]
mod loom_tests {
    use super::*;

    /// L-10: one key counting in and out of its idle slot while another key
    /// takes that slot over never strands a count: afterwards every slot is
    /// back at its count before.
    #[test]
    fn loom_counts_takeover_never_strands_a_count() {
        loom::model(|| {
            let counts = loom::sync::Arc::new(Counts::new(16));
            // Two keys whose probes start at the same slot, with different
            // tags; every other slot held by a busy key.
            let a = (3u64 << 17) | 1;
            let b = (3u64 << 17) | (1 << 40) | 1;
            let start = Counts::start(a) as usize & counts.mask;
            assert_eq!(start, Counts::start(b) as usize & counts.mask);
            for i in 0..counts.len() {
                let w = if i == start {
                    Counts::tag(a) << COUNT_BITS
                } else {
                    ((1000 + i as u64) << COUNT_BITS) | 1
                };
                counts.words[i].store(w, Ordering::Relaxed);
            }
            // Both sides spawned, so loom also runs either one first (D-129).
            let other = loom::sync::Arc::clone(&counts);
            let t = loom::thread::spawn(move || {
                if other.acquire(b, 10, || false) == Ok(true) {
                    other.release(b);
                }
            });
            let mine = loom::sync::Arc::clone(&counts);
            let u = loom::thread::spawn(move || {
                if mine.acquire(a, 10, || false) == Ok(true) {
                    mine.release(a);
                }
            });
            t.join().unwrap();
            u.join().unwrap();
            let live: u64 = counts
                .words
                .iter()
                .map(|w| w.load(Ordering::Acquire) & u64::from(COUNT_MAX))
                .sum();
            assert_eq!(live, counts.len() as u64 - 1, "a count was stranded");
        });
    }
}
