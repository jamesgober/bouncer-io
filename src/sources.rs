//! Shared-address detection: an address showing many distinct sessions or
//! accounts is likely a NAT (an office, a mobile carrier, carrier-grade NAT
//! in RFC 6598 space), so automation prefers identity keys and throttling
//! over banning everyone behind it.
//!
//! Per client (IPv4 address, IPv6 /64): a 64-bit bitmap of hashed identities
//! seen within the window, and the end of the shared flag. One `fetch_or`
//! per identity bind; 16 bytes per tracked address plus its claim word.

use std::{collections::VecDeque, net::IpAddr, sync::Mutex};

use crate::{
    claims::Claims,
    hash::HashKey,
    keys::{Cidr, Family},
    sync::{AtomicU64, Ordering},
};

/// Distinct identities (bits set) above which an address is shared.
pub(crate) const SHARED_THRESHOLD: u32 = 16;
/// The window identities are counted in.
const WINDOW_SECS: u64 = 3600;
/// How long the shared flag lasts.
const FLAG_SECS: u64 = 24 * 3600;
/// Flagged addresses remembered for "is any inside this prefix".
const FLAGGED_LIST: usize = 4096;

pub(crate) struct Sources {
    key: HashKey,
    claims: Claims,
    bits: Box<[AtomicU64]>,
    /// window start secs (32) | flagged until secs (32)
    meta: Box<[AtomicU64]>,
    flagged: Mutex<VecDeque<(Cidr, u64)>>,
}

/// The client prefix of an address: IPv4 /32, IPv6 /64.
fn client(addr: IpAddr) -> Cidr {
    let host = Cidr::host(addr);
    match host.family() {
        Family::V4 => host,
        Family::V6 => host.parent(64).unwrap_or(host),
    }
}

impl Sources {
    pub(crate) fn new(capacity: u32, key: HashKey) -> Sources {
        let claims = Claims::new(capacity);
        let n = claims.len();
        Sources {
            key,
            bits: (0..n).map(|_| AtomicU64::new(0)).collect(),
            meta: (0..n).map(|_| AtomicU64::new(0)).collect(),
            claims,
            // Sized once, so flagging on the bind path never allocates.
            flagged: Mutex::new(VecDeque::with_capacity(FLAGGED_LIST)),
        }
    }

    pub(crate) fn bytes(&self) -> u64 {
        self.claims.bytes()
            + (self.bits.len() * 16) as u64
            + (FLAGGED_LIST * core::mem::size_of::<(Cidr, u64)>()) as u64
    }

    fn slot_key(&self, c: &Cidr) -> u64 {
        Claims::key(self.key.hash3(
            u64::from(c.len()) | (u64::from(c.family() == Family::V6) << 8) | (1 << 16),
            (c.bits() >> 64) as u64,
            c.bits() as u64,
        ))
    }

    /// Notes an identity (its two words) seen from `addr`. Returns `true`
    /// when this note flagged the address as shared.
    pub(crate) fn note(&self, addr: IpAddr, k0: u64, k1: u64, now_secs: u64) -> bool {
        let c = client(addr);
        let key = self.slot_key(&c);
        let (bits, meta) = (&self.bits, &self.meta);
        let idle = |slot: usize| {
            let m = meta[slot].load(Ordering::Acquire);
            (m >> 32) + WINDOW_SECS <= now_secs && (m & 0xffff_ffff) <= now_secs
        };
        let Some((slot, _)) = self.claims.find_or_claim(key, idle, |s| {
            bits[s].store(0, Ordering::Release);
            meta[s].store((now_secs.min(u64::from(u32::MAX))) << 32, Ordering::Release);
        }) else {
            return false;
        };
        let m = meta[slot].load(Ordering::Acquire);
        if (m & 0xffff_ffff) > now_secs {
            return false; // already flagged: nothing more to learn
        }
        let start = m >> 32;
        if start + WINDOW_SECS <= now_secs {
            // A new window: start it once, keeping the flag.
            let next = (now_secs.min(u64::from(u32::MAX)) << 32) | (m & 0xffff_ffff);
            if meta[slot]
                .compare_exchange(m, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                bits[slot].store(0, Ordering::Release);
            }
        }
        // The identity words are keyed digests already (or account ids the
        // caller assigned): a multiply-mix picks the bit.
        let mixed = (k0.wrapping_mul(0x9e37_79b9_7f4a_7c15)
            ^ k1.wrapping_mul(0xc2b2_ae3d_27d4_eb4f))
        .wrapping_mul(0x1656_67b1_9e37_79f9);
        let bit = 1u64 << (mixed >> 58);
        let before = bits[slot].fetch_or(bit, Ordering::AcqRel);
        if before & bit != 0 || (before | bit).count_ones() <= SHARED_THRESHOLD {
            return false;
        }
        // Over the threshold: flag it, once per flag period.
        let m = meta[slot].load(Ordering::Acquire);
        if (m & 0xffff_ffff) > now_secs {
            return false;
        }
        let until = now_secs.saturating_add(FLAG_SECS).min(u64::from(u32::MAX));
        if meta[slot]
            .compare_exchange(
                m,
                (m & !0xffff_ffff) | until,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        let mut list = self
            .flagged
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        list.retain(|&(f, end)| f != c && end > now_secs);
        if list.len() >= FLAGGED_LIST {
            list.pop_front();
        }
        list.push_back((c, until));
        true
    }

    /// Whether `addr` is flagged as shared now.
    pub(crate) fn is_shared(&self, addr: IpAddr, now_secs: u64) -> bool {
        let c = client(addr);
        self.claims
            .find(self.slot_key(&c))
            .is_some_and(|slot| (self.meta[slot].load(Ordering::Acquire) & 0xffff_ffff) > now_secs)
    }

    /// Whether any flagged address lies inside `prefix` (escalation stops
    /// there).
    pub(crate) fn any_within(&self, prefix: &Cidr, now_secs: u64) -> bool {
        self.flagged
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .any(|&(c, end)| end > now_secs && (prefix.covers(&c) || c.covers(prefix)))
    }
}

#[cfg(all(test, not(bouncer_loom)))]
mod tests {
    use super::*;

    #[test]
    fn test_many_identities_flag_an_address_then_expire() {
        // Edge case 56: set and expired.
        let s = Sources::new(64, HashKey::new(7, 8));
        let a: IpAddr = "198.51.100.1".parse().unwrap();
        let mut flagged = false;
        for i in 0..200u64 {
            flagged |= s.note(a, i, i.wrapping_mul(31), 10);
            if flagged {
                break;
            }
        }
        assert!(flagged);
        assert!(s.is_shared(a, 10));
        assert!(s.any_within(&"198.51.100.0/24".parse().unwrap(), 10));
        assert!(!s.is_shared("198.51.100.2".parse().unwrap(), 10));
        assert!(!s.is_shared(a, 10 + FLAG_SECS));
        assert!(!s.any_within(&"198.51.100.0/24".parse().unwrap(), 10 + FLAG_SECS));
    }

    #[test]
    fn test_few_identities_do_not_flag() {
        let s = Sources::new(64, HashKey::new(7, 8));
        let a: IpAddr = "2001:db8::1".parse().unwrap();
        for i in 0..8u64 {
            assert!(!s.note(a, i, 0, 5));
            assert!(!s.note(a, i, 0, 6), "the same identity twice counts once");
        }
        assert!(!s.is_shared("2001:db8::ffff".parse().unwrap(), 6));
    }
}
