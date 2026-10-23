//! A lock-free table of keyed slots for counters: strike windows, budget
//! cells, refusal sampling.
//!
//! A slot is claimed by a compare-and-swap of its key word from zero to the
//! key's 64-bit keyed hash; its payload lives in a parallel array owned by
//! the caller. Every probe for one key visits the same slots in the same
//! order and claims the first empty one, so two threads adding the same key
//! meet at the same slot. A slot whose payload has gone idle (a recovered
//! budget, an expired strike window) can be taken over by another key; the
//! caller decides when a payload is idle. Memory is fixed at construction.

use crate::sync::{AtomicU64, Ordering};

/// Slots a probe visits.
const PROBE: usize = 16;

pub(crate) struct Claims {
    keys: Box<[AtomicU64]>,
    mask: usize,
}

impl Claims {
    /// At least `capacity` slots, rounded up to a power of two (at least 16).
    pub(crate) fn new(capacity: u32) -> Claims {
        let n = (capacity as usize).next_power_of_two().max(PROBE);
        Claims {
            keys: (0..n).map(|_| AtomicU64::new(0)).collect(),
            mask: n - 1,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.keys.len()
    }

    /// A key hash usable as a slot key: never zero.
    #[inline]
    pub(crate) fn key(h: u64) -> u64 {
        h | 1
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
            match self.keys[i].load(Ordering::Acquire) {
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
            let k = self.keys[i].load(Ordering::Acquire);
            if k == key {
                return Some((i, false));
            }
            if k == 0 {
                match self.keys[i].compare_exchange(0, key, Ordering::AcqRel, Ordering::Acquire) {
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
        match self.keys[slot].compare_exchange(old, key, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                reset(slot);
                Some((slot, true))
            }
            Err(actual) if actual == key => Some((slot, false)),
            Err(_) => None,
        }
    }

    /// Bytes reserved by the key words.
    pub(crate) fn bytes(&self) -> u64 {
        (self.keys.len() * 8) as u64
    }
}

#[cfg(all(test, not(bouncer_loom)))]
mod tests {
    use super::*;

    #[test]
    fn test_claims_find_and_claim_same_slot() {
        let c = Claims::new(64);
        let k = Claims::key(42);
        assert_eq!(c.find(k), None);
        let (s, new) = c.find_or_claim(k, |_| false, |_| {}).unwrap();
        assert!(new);
        assert_eq!(c.find(k), Some(s));
        assert_eq!(c.find_or_claim(k, |_| false, |_| {}), Some((s, false)));
    }

    #[test]
    fn test_claims_full_path_then_idle_takeover() {
        let c = Claims::new(16);
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
        let c = std::sync::Arc::new(Claims::new(1024));
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
