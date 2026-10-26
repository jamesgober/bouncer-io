//! Offender memory: past offences per ban key, decayed with a half-life. It
//! outlives the bans, so a returning offender's next ban is longer.
//!
//! Kept inside the ban writer lock (it changes only when a ban is set) in a
//! map sized at build. When full, the lowest decayed score among a sample is
//! dropped.

use std::collections::HashMap;

use super::table::TableKey;

/// Entries sampled to pick one to drop when the memory is full.
const EVICT_SAMPLE: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Offence {
    /// Offences as of `last`.
    pub(crate) score: f32,
    /// Seconds since the bouncer started.
    pub(crate) last: u32,
}

#[derive(Debug)]
pub(crate) struct Offenders {
    map: HashMap<TableKey, Offence>,
    capacity: usize,
    half_life: u64,
}

impl Offenders {
    pub(crate) fn new(capacity: usize, half_life_secs: u64) -> Offenders {
        Offenders {
            map: HashMap::with_capacity(capacity),
            capacity: capacity.max(1),
            half_life: half_life_secs.max(1),
        }
    }

    pub(crate) fn bytes(&self) -> u64 {
        (self.map.capacity() * (core::mem::size_of::<(TableKey, Offence)>() + 1)) as u64
    }

    #[cfg(all(test, not(bouncer_loom)))]
    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }

    /// The score decayed to `now_secs`.
    fn decayed(&self, o: &Offence, now_secs: u64) -> f32 {
        let dt = now_secs.saturating_sub(u64::from(o.last));
        o.score * 0.5f32.powf(dt as f32 / self.half_life as f32)
    }

    /// The decayed record of a key.
    pub(crate) fn get(&self, key: &TableKey, now_secs: u64) -> Option<Offence> {
        self.map.get(key).map(|o| Offence {
            score: self.decayed(o, now_secs),
            last: o.last,
        })
    }

    /// Offences that count toward the next ban's duration: the decayed
    /// score, rounded.
    pub(crate) fn offences(&self, key: &TableKey, now_secs: u64) -> u16 {
        self.get(key, now_secs).map_or(0, |o| {
            (o.score + 0.5).floor().clamp(0.0, f32::from(u16::MAX)) as u16
        })
    }

    /// Records one more offence.
    pub(crate) fn record(&mut self, key: TableKey, now_secs: u64) {
        let last = now_secs.min(u64::from(u32::MAX)) as u32;
        if let Some(o) = self.map.get(&key).copied() {
            let score = self.decayed(&o, now_secs) + 1.0;
            self.map.insert(key, Offence { score, last });
            return;
        }
        if self.map.len() >= self.capacity {
            let victim = self
                .map
                .iter()
                .take(EVICT_SAMPLE)
                .min_by(|a, b| {
                    self.decayed(a.1, now_secs)
                        .total_cmp(&self.decayed(b.1, now_secs))
                })
                .map(|(k, _)| *k);
            if let Some(k) = victim {
                self.map.remove(&k);
            }
        }
        self.map.insert(key, Offence { score: 1.0, last });
    }

    /// Sets a record as loaded or imported.
    pub(crate) fn set(&mut self, key: TableKey, offence: Offence) {
        if self.map.len() < self.capacity || self.map.contains_key(&key) {
            self.map.insert(key, offence);
        }
    }

    /// Every record (persistence).
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&TableKey, &Offence)> {
        self.map.iter()
    }
}

#[cfg(all(test, not(bouncer_loom)))]
mod tests {
    use super::*;
    use crate::bans::table::KIND_V4;

    fn k(n: u64) -> TableKey {
        TableKey {
            kind: KIND_V4,
            len: 32,
            k0: 0,
            k1: n,
        }
    }

    #[test]
    fn test_offences_decay_by_half_life() {
        // Edge case 52: after 1, 2, and 10 half-lives.
        let mut o = Offenders::new(16, 100);
        for _ in 0..4 {
            o.record(k(1), 0);
        }
        assert_eq!(o.offences(&k(1), 0), 4);
        assert_eq!(o.offences(&k(1), 100), 2);
        assert_eq!(o.offences(&k(1), 200), 1);
        assert_eq!(o.offences(&k(1), 1000), 0);
        let s = o.get(&k(1), 100).unwrap().score;
        assert!((s - 2.0).abs() < 1e-4);
        // A new offence adds to the decayed score.
        o.record(k(1), 100);
        assert_eq!(o.offences(&k(1), 100), 3);
    }

    #[test]
    fn test_full_memory_drops_a_low_score() {
        let mut o = Offenders::new(4, 100);
        for n in 0..4 {
            o.record(k(n), 0);
        }
        o.record(k(0), 0);
        o.record(k(0), 0);
        o.record(k(9), 1000);
        assert_eq!(o.len(), 4);
        assert!(o.get(&k(0), 1000).is_some(), "the highest score stays");
        assert!(o.get(&k(9), 1000).is_some());
    }
}
