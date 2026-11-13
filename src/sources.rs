//! Shared addresses: an address many people use (an office, a mobile
//! carrier, a carrier-grade NAT), where automation prefers identity keys and
//! throttling over banning everyone behind it.
//!
//! An address is shared when the deployment names it (`SharedAddresses::known`)
//! or, with detection on, when many distinct accounts bind from it within an
//! hour. Sessions do not count: a client mints them at will (D-137). Per
//! client (IPv4 address, IPv6 /64): a 64-bit bitmap of hashed accounts seen
//! within the window, and the end of the shared flag. One `fetch_or` per
//! account bind; 16 bytes per tracked address plus its claim word.

use std::net::IpAddr;

use crate::{
    claims::Claims,
    hash::HashKey,
    keys::{Cidr, Family},
    sync::{AtomicU64, Ordering},
};

/// Distinct accounts (bits set of 64) above which an address is shared:
/// about 32 accounts in an hour.
pub(crate) const SHARED_THRESHOLD: u32 = 24;
/// Most known shared ranges a deployment can name.
pub(crate) const MAX_KNOWN: usize = 4096;

/// Which addresses bouncer treats as shared by many people (a NAT), where a
/// threshold throttles the address and bans the identities instead of
/// banning everyone behind it.
///
/// Detection, the default, counts distinct accounts bound from an address in
/// an hour: about 32 make it shared for a day. A shared address still has
/// ceilings: the door holds it to its prefix's budgets, a throttle on it
/// slows it at the door, and a second threshold while it is throttled bans
/// it. Ranges named with [`known`](Self::known) are shared whatever the
/// evidence, and also keep prefix escalation and prefix strike bans off the
/// prefixes they cover; a detected address does neither.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Bouncer, Cidr, SharedAddresses};
/// let carrier: Cidr = "100.64.0.0/10".parse()?;
/// let bouncer = Bouncer::builder()
///     .shared_addresses(SharedAddresses::detect().known(&[carrier]))
///     .build()?;
/// assert!(bouncer.explain("100.64.1.2".parse::<std::net::IpAddr>()?).shared_source);
///
/// let strict = Bouncer::builder().shared_addresses(SharedAddresses::off()).build()?;
/// # let _ = strict;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedAddresses {
    pub(crate) detect: bool,
    pub(crate) known: Vec<Cidr>,
}

impl SharedAddresses {
    /// Detection by distinct accounts, and no known ranges (the default).
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::SharedAddresses;
    /// assert_eq!(SharedAddresses::detect(), SharedAddresses::default());
    /// ```
    #[must_use]
    pub fn detect() -> SharedAddresses {
        SharedAddresses {
            detect: true,
            known: Vec::new(),
        }
    }

    /// No address is ever shared, unless named with [`known`](Self::known):
    /// every address is held to its own budgets and banned at its
    /// thresholds.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Bouncer, SharedAddresses};
    /// let bouncer = Bouncer::builder().shared_addresses(SharedAddresses::off()).build()?;
    /// # let _ = bouncer;
    /// # Ok::<(), bouncer_io::BouncerError>(())
    /// ```
    #[must_use]
    pub fn off() -> SharedAddresses {
        SharedAddresses {
            detect: false,
            known: Vec::new(),
        }
    }

    /// Ranges known to be shared (a carrier's NAT pools, an office's egress),
    /// at most 4,096. Replaces any set before.
    ///
    /// # Examples
    ///
    /// ```
    /// use bouncer_io::{Cidr, SharedAddresses};
    /// let pools: [Cidr; 2] = ["100.64.0.0/10".parse()?, "2001:db8:ca7::/48".parse()?];
    /// let shared = SharedAddresses::off().known(&pools);
    /// # let _ = shared;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn known(mut self, ranges: &[Cidr]) -> SharedAddresses {
        self.known = ranges.to_vec();
        self
    }
}

impl Default for SharedAddresses {
    fn default() -> SharedAddresses {
        SharedAddresses::detect()
    }
}
/// The window identities are counted in.
const WINDOW_SECS: u64 = 3600;
/// How long the shared flag lasts.
const FLAG_SECS: u64 = 24 * 3600;

pub(crate) struct Sources {
    detect: bool,
    known: Vec<Cidr>,
    key: HashKey,
    claims: Claims,
    bits: Box<[AtomicU64]>,
    /// window start secs (32) | flagged until secs (32)
    meta: Box<[AtomicU64]>,
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
    pub(crate) fn new(capacity: u32, key: HashKey, policy: &SharedAddresses) -> Sources {
        let claims = Claims::new(capacity);
        let n = claims.len();
        Sources {
            detect: policy.detect,
            known: policy.known.clone(),
            key,
            bits: (0..n).map(|_| AtomicU64::new(0)).collect(),
            meta: (0..n).map(|_| AtomicU64::new(0)).collect(),
            claims,
        }
    }

    pub(crate) fn bytes(&self) -> u64 {
        self.claims.bytes()
            + (self.bits.len() * 16) as u64
            + (self.known.len() * core::mem::size_of::<Cidr>()) as u64
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
        if !self.detect {
            return false;
        }
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
        meta[slot]
            .compare_exchange(
                m,
                (m & !0xffff_ffff) | until,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Whether `addr` is shared now: named, or flagged by detection.
    pub(crate) fn is_shared(&self, addr: IpAddr, now_secs: u64) -> bool {
        if self.known.iter().any(|k| k.contains(addr)) {
            return true;
        }
        if !self.detect {
            return false;
        }
        let c = client(addr);
        self.claims
            .find(self.slot_key(&c))
            .is_some_and(|slot| (self.meta[slot].load(Ordering::Acquire) & 0xffff_ffff) > now_secs)
    }

    /// Whether a known shared range overlaps `prefix`: escalation and prefix
    /// strike bans stop there. A detected address does not stop them, or a
    /// client that earned the flag would shield its whole prefix (D-137).
    pub(crate) fn known_within(&self, prefix: &Cidr) -> bool {
        self.known
            .iter()
            .any(|k| prefix.covers(k) || k.covers(prefix))
    }
}

#[cfg(all(test, not(bouncer_loom)))]
mod tests {
    use super::*;

    #[test]
    fn test_many_identities_flag_an_address_then_expire() {
        // Edge case 56: set and expired.
        let s = Sources::new(64, HashKey::new(7, 8), &SharedAddresses::detect());
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
        assert!(!s.known_within(&"198.51.100.0/24".parse().unwrap()));
        assert!(!s.is_shared("198.51.100.2".parse().unwrap(), 10));
        assert!(!s.is_shared(a, 10 + FLAG_SECS));
    }

    #[test]
    fn test_few_identities_do_not_flag() {
        let s = Sources::new(64, HashKey::new(7, 8), &SharedAddresses::detect());
        let a: IpAddr = "2001:db8::1".parse().unwrap();
        for i in 0..8u64 {
            assert!(!s.note(a, i, 0, 5));
            assert!(!s.note(a, i, 0, 6), "the same identity twice counts once");
        }
        assert!(!s.is_shared("2001:db8::ffff".parse().unwrap(), 6));
    }
}
