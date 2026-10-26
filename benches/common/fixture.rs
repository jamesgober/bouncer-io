//! The NFR-2 fixture shared by the benches: 1,000,000 bans over every
//! automatic length and 10,000 administrator prefixes at other lengths,
//! with banned and admitted probe addresses.

// Each bench uses part of it.
#![allow(dead_code)]

use std::net::IpAddr;

use bouncer_io::{AllowList, BanSpec, Bouncer, Budgets, Cidr};

/// The allow list both sides of a comparison hold (immune entries).
pub const ALLOW: [&str; 2] = ["198.18.0.0/15", "fd00::/8"];
/// The trusted proxies both sides hold.
pub const PROXIES: [&str; 2] = ["10.0.0.0/8", "fd12::/16"];

pub fn cidrs(list: &[&str]) -> Vec<Cidr> {
    list.iter().map(|s| s.parse().unwrap()).collect()
}

pub fn v6(bits: u128) -> IpAddr {
    IpAddr::V6(std::net::Ipv6Addr::from(bits))
}

/// SplitMix64: deterministic input data.
pub struct Mix(pub u64);
impl Mix {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

/// The fixture: the bouncer (door budgets off, so the door measures ban
/// memory and the ticket), every prefix it holds, and probes.
pub struct Fixture {
    pub bouncer: Bouncer,
    /// Every banned prefix, for building the same set elsewhere.
    pub prefixes: Vec<Cidr>,
    pub banned: Vec<IpAddr>,
    pub admitted: Vec<IpAddr>,
}

pub fn fixture() -> Fixture {
    fixture_with(Budgets::off())
}

/// The fixture with the given budgets.
pub fn fixture_with(budgets: Budgets) -> Fixture {
    build(budgets, 10_000)
}

/// The fixture with the given budgets and number of administrator prefixes.
pub fn build(budgets: Budgets, admin_prefixes: usize) -> Fixture {
    let bouncer = Bouncer::builder()
        .ban_capacity(1_100_000)
        .tickets(4096)
        .budgets(budgets)
        .allow(
            cidrs(&ALLOW)
                .into_iter()
                .fold(AllowList::new(), |l, c| l.immune(c, "bench")),
        )
        .trusted_proxies(&cidrs(&PROXIES))
        .escalation(bouncer_io::EscalationPolicy::default().off())
        .seed([9; 32])
        .try_build()
        .unwrap();
    let mut m = Mix(1);
    let mut prefixes = Vec::with_capacity(1_010_000);
    let mut banned = Vec::new();
    let plan: [(u8, bool, u32); 5] = [
        (32, false, 300_000),
        (24, false, 200_000),
        (64, true, 300_000),
        (56, true, 100_000),
        (48, true, 100_000),
    ];
    for (len, is_v6, count) in plan {
        for _ in 0..count {
            let addr = if is_v6 {
                v6(((u128::from(m.next()) << 64) | u128::from(m.next())) | (0x2001u128 << 112))
            } else {
                IpAddr::from((m.next() as u32 | 0x8000_0000).to_be_bytes())
            };
            let cidr = Cidr::new(addr, len).unwrap();
            if bouncer.ban(BanSpec::prefix(cidr).permanent()).is_ok() {
                prefixes.push(cidr);
                if banned.len() < 4096 {
                    banned.push(addr);
                }
            }
        }
    }
    let mut admin = 0;
    while admin < admin_prefixes {
        let r = m.next();
        let cidr = if r % 2 == 0 {
            let len = 8 + (r >> 8) as u8 % 23; // 8..=30, skipping /24
            if len == 24 {
                continue;
            }
            Cidr::new(
                IpAddr::from((m.next() as u32 & 0x7fff_ffff).to_be_bytes()),
                len,
            )
            .unwrap()
        } else {
            let len = 20 + (r >> 8) as u8 % 100;
            if [48, 56, 64].contains(&len) {
                continue;
            }
            Cidr::new(v6((u128::from(m.next()) << 64) | (0x2a00u128 << 112)), len).unwrap()
        };
        if bouncer.ban(cidr).is_ok() {
            prefixes.push(cidr);
            admin += 1;
        }
    }
    let admitted = (0..4096)
        .map(|i| {
            if i % 2 == 0 {
                IpAddr::from([192, 0, (i >> 8) as u8, i as u8])
            } else {
                v6((0x3fff_u128 << 112) | u128::from(m.next()))
            }
        })
        .collect();
    Fixture {
        bouncer,
        prefixes,
        banned,
        admitted,
    }
}
