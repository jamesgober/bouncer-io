//! The compositions bouncer's door is compared with (NFR-10, PLAN D-081).
//! See `benches/comparison.rs` for what each one is.

// Each bench uses part of it.
#![allow(dead_code)]

use std::{
    collections::HashSet,
    net::IpAddr,
    num::NonZeroU32,
    sync::{Arc, atomic::AtomicBool},
};

use bouncer_io::{Cidr, Family};
use governor::{Quota, RateLimiter};
use prefix_trie::PrefixSet;

use crate::fixture::{ALLOW, PROXIES, cidrs};

/// Longest-prefix sets per family.
#[derive(Default)]
pub struct Tries {
    v4: PrefixSet<(u32, u8)>,
    v6: PrefixSet<(u128, u8)>,
}

impl Tries {
    pub fn insert(&mut self, c: &Cidr) {
        match (c.family(), c.network()) {
            (Family::V4, IpAddr::V4(a)) => {
                self.v4.insert((u32::from(a), c.len()));
            }
            (_, IpAddr::V6(a)) => {
                self.v6.insert((u128::from(a), c.len()));
            }
            _ => {}
        }
    }

    #[inline]
    pub fn covers(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(a) => self.v4.get_lpm(&(u32::from(a), 32)).is_some(),
            IpAddr::V6(a) => self.v6.get_lpm(&(u128::from(a), 128)).is_some(),
        }
    }
}

/// The lookup-only composition: banned hosts, banned prefixes, a rate check.
pub struct LookupOnly {
    prefixes: Tries,
    hosts: HashSet<IpAddr>,
    limiter: governor::DefaultKeyedRateLimiter<IpAddr>,
}

impl LookupOnly {
    pub fn new(bans: &[Cidr]) -> LookupOnly {
        let mut c = LookupOnly {
            prefixes: Tries::default(),
            hosts: HashSet::new(),
            limiter: RateLimiter::keyed(Quota::per_second(NonZeroU32::new(1_000_000_000).unwrap())),
        };
        for p in bans {
            if p.len() == p.family().max_len() {
                c.hosts.insert(p.network());
            } else {
                c.prefixes.insert(p);
            }
        }
        c
    }

    #[inline]
    pub fn banned(&self, addr: IpAddr) -> bool {
        self.hosts.contains(&addr) || self.prefixes.covers(addr)
    }

    /// Not banned, and within the rate.
    #[inline]
    pub fn admit(&self, addr: IpAddr) -> bool {
        !self.banned(addr) && self.limiter.check_key(&addr).is_ok()
    }
}

/// The same-job composition.
pub struct EqualJob {
    inner: LookupOnly,
    allow: Tries,
    proxies: Tries,
    live: dashmap::DashMap<u64, Arc<AtomicBool>>,
}

impl EqualJob {
    pub fn new(bans: &[Cidr]) -> EqualJob {
        let mut e = EqualJob {
            inner: LookupOnly::new(bans),
            allow: Tries::default(),
            proxies: Tries::default(),
            live: dashmap::DashMap::new(),
        };
        for c in cidrs(&ALLOW) {
            e.allow.insert(&c);
        }
        for c in cidrs(&PROXIES) {
            e.proxies.insert(&c);
        }
        e
    }

    /// The door's job: a proxy hop is admitted (its client is judged later),
    /// an allow-listed source skips bans and budgets, anything else must be
    /// unbanned and within its rate; an admitted connection gets a revocable
    /// handle, registered under its id.
    #[inline]
    pub fn door(&self, id: u64, addr: IpAddr) -> Option<Arc<AtomicBool>> {
        let admitted =
            self.proxies.covers(addr) || self.allow.covers(addr) || self.inner.admit(addr);
        if !admitted {
            return None;
        }
        let h = Arc::new(AtomicBool::new(false));
        self.live.insert(id, Arc::clone(&h));
        Some(h)
    }

    /// The connection ended: deregister its handle.
    #[inline]
    pub fn release(&self, id: u64) {
        self.live.remove(&id);
    }
}
