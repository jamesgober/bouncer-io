//! The replicated ban state of a node that shares (it has a node id): each
//! node's ban on a key kept apart, with its stamp, and the lifts that cover
//! them (dev/PLAN.md 7.13, D-096).
//!
//! The rules make delivery order irrelevant. For each key and origin node
//! the latest ban wins (by stamp). A lift covers the bans stamped before it
//! of one origin, or of every origin when an administrator lifted the key.
//! A key is banned while one of its bans is uncovered and unexpired. The
//! ban table holds the merge of those bans, which is the same on every node
//! that has seen the same records.
//!
//! Times are Unix seconds, as in the records; stamps are the hybrid
//! logical clock of the origin (wall milliseconds and a counter).

use std::collections::{HashMap, VecDeque};

use crate::{directive::ActorKind, keys::BanKey};

/// Nodes whose bans one key may hold at once; a further node's ban is
/// refused (a backstop: a channel carries only its own node's records).
pub(crate) const MAX_ORIGINS: usize = 64;

/// Keys whose lifts are remembered at most; past it the oldest are
/// forgotten (a ban older than a forgotten lift could come back if it is
/// delivered that late).
pub(crate) const LIFTED_KEYS: usize = 65_536;

/// One node's ban on a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Contribution {
    pub(crate) origin: u16,
    pub(crate) stamp: u64,
    /// Unix seconds (to 2106); 0 = permanent.
    pub(crate) until: u32,
    pub(crate) issued: u32,
    /// The original length in seconds; 0 = permanent.
    pub(crate) length: u32,
    pub(crate) actor: u8,
    pub(crate) reason: u16,
    pub(crate) offences: u16,
    pub(crate) id: u64,
}

impl Contribution {
    fn expired(&self, now_wall: u64) -> bool {
        self.until != 0 && u64::from(self.until) <= now_wall
    }

    /// A local heuristic's timed ban (the table may evict it).
    fn evictable(&self) -> bool {
        self.actor == ActorKind::Local.code() && self.until != 0
    }
}

/// Whose bans a lift covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    /// The bans of one origin node.
    Origin(u16),
    /// Every origin's (an administrator's lift, delivered as one).
    All,
}

impl Scope {
    fn covers(self, origin: u16) -> bool {
        match self {
            Scope::All => true,
            Scope::Origin(o) => o == origin,
        }
    }
}

#[derive(Debug, Default)]
struct KeyState {
    bans: Vec<Contribution>,
    lifts: Vec<(Scope, u64)>,
}

impl KeyState {
    fn covered(&self, c: &Contribution) -> bool {
        self.lifts
            .iter()
            .any(|&(scope, stamp)| scope.covers(c.origin) && stamp >= c.stamp)
    }
}

/// Every ban and every lift: `(key, ban)` and `(key, scope, stamp)`.
pub(crate) type Dump = (Vec<(BanKey, Contribution)>, Vec<(BanKey, Scope, u64)>);

/// What a ban record did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Applied {
    /// It is now this origin's ban on the key.
    Changed,
    /// A lift or a later ban of the same origin already covers it, or it has
    /// expired.
    Superseded,
    /// The key already holds bans of `MAX_ORIGINS` nodes.
    Full,
}

/// The replicated ban state.
#[derive(Debug, Default)]
pub(crate) struct Ledger {
    keys: HashMap<BanKey, KeyState>,
    /// Keys with lifts, in the order their first lift was noted.
    lifted: VecDeque<BanKey>,
    /// Above this many keys, expired bans are swept.
    soft_cap: usize,
}

impl Ledger {
    /// A ledger for a ban table of `capacity`.
    pub(crate) fn new(capacity: u32) -> Ledger {
        Ledger {
            keys: HashMap::new(),
            lifted: VecDeque::new(),
            soft_cap: (capacity as usize).saturating_mul(2).max(1024) + LIFTED_KEYS,
        }
    }

    /// Applies one origin's ban.
    pub(crate) fn ban(&mut self, key: BanKey, c: Contribution, now_wall: u64) -> Applied {
        if c.expired(now_wall) {
            return Applied::Superseded;
        }
        self.sweep_if_large(now_wall);
        let st = self.keys.entry(key).or_default();
        st.bans.retain(|b| !b.expired(now_wall));
        if st.covered(&c) {
            return Applied::Superseded;
        }
        let full = st.bans.len() >= MAX_ORIGINS;
        match st.bans.iter_mut().find(|b| b.origin == c.origin) {
            Some(b) if b.stamp >= c.stamp => Applied::Superseded,
            Some(b) => {
                *b = c;
                Applied::Changed
            }
            None if full => Applied::Full,
            None => {
                // Most keys hold one node's ban: no room for more until needed.
                st.bans.reserve_exact(1);
                st.bans.push(c);
                Applied::Changed
            }
        }
    }

    /// Applies a lift; returns how many origins' bans it removed.
    pub(crate) fn lift(&mut self, key: BanKey, scope: Scope, stamp: u64, now_wall: u64) -> u32 {
        let st = self.keys.entry(key).or_default();
        if st.lifts.is_empty() {
            self.lifted.push_back(key);
        }
        match st.lifts.iter_mut().find(|(s, _)| *s == scope) {
            Some((_, t)) => *t = (*t).max(stamp),
            None => {
                st.lifts.reserve_exact(1);
                st.lifts.push((scope, stamp));
            }
        }
        let before = st.bans.len();
        // A lift covers bans stamped at or before it, as `covered` does for a
        // ban that arrives after the lift: two nodes can make equal stamps.
        st.bans
            .retain(|b| !(b.expired(now_wall) || (scope.covers(b.origin) && b.stamp <= stamp)));
        let removed = (before - st.bans.len()) as u32;
        self.forget_old_lifts();
        removed
    }

    /// Whether a lift would remove a ban (it covers one that is in force).
    pub(crate) fn would_lift(&self, key: &BanKey, scope: Scope, stamp: u64, now_wall: u64) -> bool {
        self.keys.get(key).is_some_and(|st| {
            st.bans
                .iter()
                .any(|b| !b.expired(now_wall) && scope.covers(b.origin) && b.stamp <= stamp)
        })
    }

    /// Drops every ban on `key` (a local removal: evicted, folded into a
    /// parent without a lift, or now allow-listed); its lifts stay.
    pub(crate) fn forget(&mut self, key: &BanKey) {
        if let Some(st) = self.keys.get_mut(key) {
            st.bans.clear();
            if st.lifts.is_empty() {
                self.keys.remove(key);
            }
        }
    }

    /// The ban of one origin on `key`, unexpired.
    pub(crate) fn own(&self, key: &BanKey, origin: u16, now_wall: u64) -> Option<Contribution> {
        self.keys
            .get(key)?
            .bans
            .iter()
            .find(|b| b.origin == origin && !b.expired(now_wall))
            .copied()
    }

    /// Whether `key` holds a ban of an origin other than `origin`.
    pub(crate) fn held_by_other(&self, key: &BanKey, origin: u16, now_wall: u64) -> bool {
        self.keys.get(key).is_some_and(|st| {
            st.bans
                .iter()
                .any(|b| b.origin != origin && !b.expired(now_wall))
        })
    }

    /// The merge of every uncovered, unexpired ban on `key`: the latest end
    /// (permanent above all), the latest issue time, the most offences, and
    /// the actor, reason, and id of the strongest ban (one the table may not
    /// evict first, then the longest, then the latest stamp). Independent of
    /// the order the bans arrived in.
    pub(crate) fn effective(&self, key: &BanKey, now_wall: u64) -> Option<Contribution> {
        let live = self
            .keys
            .get(key)?
            .bans
            .iter()
            .filter(|b| !b.expired(now_wall));
        let mut out: Option<Contribution> = None;
        let rank = |c: &Contribution| {
            (
                !c.evictable(),
                if c.until == 0 { u32::MAX } else { c.until },
                c.stamp,
                c.origin,
            )
        };
        for b in live {
            out = Some(match out {
                None => *b,
                Some(o) => {
                    let owner = if rank(b) > rank(&o) { *b } else { o };
                    let permanent = o.until == 0 || b.until == 0;
                    Contribution {
                        until: if permanent { 0 } else { o.until.max(b.until) },
                        length: if permanent { 0 } else { o.length.max(b.length) },
                        issued: o.issued.max(b.issued),
                        offences: o.offences.max(b.offences),
                        ..owner
                    }
                }
            });
        }
        out
    }

    /// Every ban and every lift, for snapshots and full exports.
    pub(crate) fn dump(&self, now_wall: u64) -> Dump {
        let mut bans = Vec::new();
        let mut lifts = Vec::new();
        for (key, st) in &self.keys {
            bans.extend(
                st.bans
                    .iter()
                    .filter(|b| !b.expired(now_wall))
                    .map(|b| (*key, *b)),
            );
            lifts.extend(st.lifts.iter().map(|&(s, t)| (*key, s, t)));
        }
        (bans, lifts)
    }

    /// Keys held (tests).
    #[cfg(all(test, not(bouncer_loom)))]
    pub(crate) fn len(&self) -> usize {
        self.keys.len()
    }

    /// Bytes held, estimated (for `capacity`).
    pub(crate) fn bytes(&self) -> u64 {
        let per_key = core::mem::size_of::<(BanKey, KeyState)>() + 1;
        let bans: usize = self.keys.values().map(|s| s.bans.capacity()).sum();
        let lifts: usize = self.keys.values().map(|s| s.lifts.capacity()).sum();
        (self.keys.capacity() * per_key
            + bans * core::mem::size_of::<Contribution>()
            + lifts * core::mem::size_of::<(Scope, u64)>()
            + self.lifted.capacity() * core::mem::size_of::<BanKey>()) as u64
    }

    fn forget_old_lifts(&mut self) {
        while self.lifted.len() > LIFTED_KEYS {
            let Some(old) = self.lifted.pop_front() else {
                break;
            };
            if let Some(st) = self.keys.get_mut(&old) {
                st.lifts.clear();
                if st.bans.is_empty() {
                    self.keys.remove(&old);
                }
            }
        }
    }

    /// Sweeps expired bans once the ledger outgrows what the ban table and
    /// the remembered lifts account for (amortized: it halves the excess).
    fn sweep_if_large(&mut self, now_wall: u64) {
        if self.keys.len() <= self.soft_cap {
            return;
        }
        self.keys.retain(|_, st| {
            st.bans.retain(|b| !b.expired(now_wall));
            !st.bans.is_empty() || !st.lifts.is_empty()
        });
        self.soft_cap = self.soft_cap.max(self.keys.len().saturating_mul(2));
    }
}

#[cfg(all(test, not(bouncer_loom)))]
mod tests {
    use super::*;

    fn key(i: u8) -> BanKey {
        BanKey::Address(std::net::IpAddr::from([198, 51, 100, i]))
    }

    fn ban(origin: u16, stamp: u64, until: u32) -> Contribution {
        Contribution {
            origin,
            stamp,
            until,
            issued: 10,
            length: until.saturating_sub(10),
            actor: ActorKind::Admin.code(),
            reason: 1,
            offences: 0,
            id: (u64::from(origin) << 48) | stamp,
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum Op {
        Ban(u8, Contribution),
        Lift(u8, Scope, u64),
    }

    fn apply(ops: &[Op]) -> Vec<(u8, Option<Contribution>)> {
        let mut l = Ledger::new(1024);
        for op in ops {
            match *op {
                Op::Ban(k, c) => {
                    let _ = l.ban(key(k), c, 0);
                }
                Op::Lift(k, s, t) => {
                    let _ = l.lift(key(k), s, t, 0);
                }
            }
        }
        (0..4).map(|k| (k, l.effective(&key(k), 0))).collect()
    }

    #[test]
    fn test_ledger_order_never_matters() {
        // Random records over four keys and three origins, applied in many
        // orders and with repetition: the same effective bans every time.
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            seed ^= seed >> 12;
            seed ^= seed << 25;
            seed ^= seed >> 27;
            seed.wrapping_mul(0x2545_f491_4f6c_dd1d)
        };
        for _ in 0..300 {
            let mut ops = Vec::new();
            // Stamps are unique per origin (each node's clock only moves
            // forward) but often equal across origins.
            let mut used = std::collections::HashSet::new();
            for i in 0..12u64 {
                let k = (next() % 4) as u8;
                let origin = 1 + (next() % 3) as u16;
                let stamp = ((i / 3) << 16) | (next() % 2);
                if !used.insert((origin, stamp)) {
                    continue;
                }
                ops.push(match next() % 4 {
                    0 => Op::Lift(k, Scope::Origin(origin), stamp),
                    1 if next() % 3 == 0 => Op::Lift(k, Scope::All, stamp),
                    _ => Op::Ban(
                        k,
                        ban(
                            origin,
                            stamp,
                            if next() % 2 == 0 { 0 } else { 1000 + i as u32 },
                        ),
                    ),
                });
            }
            let want = apply(&ops);
            for _ in 0..20 {
                let mut shuffled = ops.clone();
                for i in (1..shuffled.len()).rev() {
                    shuffled.swap(i, (next() % (i as u64 + 1)) as usize);
                }
                let repeat = (next() % shuffled.len() as u64) as usize;
                shuffled.push(shuffled[repeat]);
                assert_eq!(apply(&shuffled), want, "{ops:?}");
            }
        }
    }

    #[test]
    fn test_ledger_lift_covers_its_origin_only() {
        let mut l = Ledger::new(1024);
        assert_eq!(l.ban(key(1), ban(1, 10, 0), 0), Applied::Changed);
        assert_eq!(l.ban(key(1), ban(2, 20, 500), 0), Applied::Changed);
        assert_eq!(l.lift(key(1), Scope::Origin(1), 30, 0), 1);
        let e = l.effective(&key(1), 0).unwrap();
        assert_eq!((e.origin, e.until), (2, 500), "node 2's ban stands");
        // A late copy of node 1's ban stays lifted; a newer one wins.
        assert_eq!(l.ban(key(1), ban(1, 10, 0), 0), Applied::Superseded);
        assert_eq!(l.ban(key(1), ban(1, 40, 0), 0), Applied::Changed);
        assert_eq!(l.effective(&key(1), 0).unwrap().until, 0);
        // An administrator's lift covers every origin.
        assert_eq!(l.lift(key(1), Scope::All, 50, 0), 2);
        assert_eq!(l.effective(&key(1), 0), None);
        assert_eq!(l.ban(key(1), ban(2, 45, 900), 0), Applied::Superseded);
    }

    #[test]
    fn test_ledger_equal_stamps_lift_wins_in_either_order() {
        let mut a = Ledger::new(1024);
        let _ = a.ban(key(3), ban(1, 70, 0), 0);
        assert_eq!(a.lift(key(3), Scope::All, 70, 0), 1);
        let mut b = Ledger::new(1024);
        let _ = b.lift(key(3), Scope::All, 70, 0);
        assert_eq!(b.ban(key(3), ban(1, 70, 0), 0), Applied::Superseded);
        assert_eq!(a.effective(&key(3), 0), b.effective(&key(3), 0));
    }

    #[test]
    fn test_ledger_expiry_and_merge() {
        let mut l = Ledger::new(1024);
        let _ = l.ban(key(2), ban(1, 10, 100), 0);
        let _ = l.ban(key(2), ban(2, 20, 300), 0);
        let e = l.effective(&key(2), 0).unwrap();
        assert_eq!((e.until, e.origin), (300, 2));
        assert_eq!(l.effective(&key(2), 300), None, "both ended");
        assert_eq!(
            l.ban(key(2), ban(3, 30, 50), 60),
            Applied::Superseded,
            "already over"
        );
        l.forget(&key(2));
        assert_eq!(l.effective(&key(2), 0), None);
    }

    #[test]
    fn test_ledger_forgets_the_oldest_lifts() {
        let mut l = Ledger::new(1024);
        for i in 0..=LIFTED_KEYS as u32 {
            let k = BanKey::Address(std::net::IpAddr::from(i.to_be_bytes()));
            let _ = l.lift(k, Scope::All, 1, 0);
        }
        assert_eq!(l.lifted.len(), LIFTED_KEYS);
        let first = BanKey::Address(std::net::IpAddr::from(0u32.to_be_bytes()));
        assert!(!l.keys.contains_key(&first));
    }
}
