//! bouncer against the obvious composition of existing crates for the same
//! job (NFR-10), on the same data:
//!
//! - `door_1m`: bouncer's door (ban memory and the ticket, budgets off)
//!   against a `prefix-trie` longest-prefix match per family plus a
//!   `HashSet` exact lookup, holding the same 1,010,000 prefixes.
//! - `budget_check`: bouncer's per-source rate step (`datagram`, verified,
//!   no bans) against a `governor` keyed rate limiter.
//! - `checkpoint_fast`: a checkpoint with nothing revoked against an
//!   `Arc<AtomicBool>` load (the cheapest possible "am I revoked" flag).
//!
//! `cargo bench --bench comparison`. Compare ratios within one run: absolute
//! numbers move with the machine, ratios much less.

#[path = "common/fixture.rs"]
mod fixture;

use std::{
    collections::HashSet,
    hint::black_box,
    net::IpAddr,
    num::NonZeroU32,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use bouncer_io::{
    Bouncer, Budgets, Cidr, ConnId, DatagramVerdict, Family, Provenance, Rate, RequestId,
};
use criterion::{Criterion, criterion_group, criterion_main};
use fixture::{Mix, fixture};
use governor::{Quota, RateLimiter};
use prefix_trie::PrefixSet;

/// The composition: one trie per family for prefixes, a hash set for hosts.
struct Composition {
    v4: PrefixSet<(u32, u8)>,
    v6: PrefixSet<(u128, u8)>,
    hosts: HashSet<IpAddr>,
}

impl Composition {
    fn new(prefixes: &[Cidr]) -> Composition {
        let mut c = Composition {
            v4: PrefixSet::new(),
            v6: PrefixSet::new(),
            hosts: HashSet::new(),
        };
        for p in prefixes {
            if p.len() == p.family().max_len() {
                c.hosts.insert(p.network());
                continue;
            }
            match (p.family(), p.network()) {
                (Family::V4, IpAddr::V4(a)) => {
                    c.v4.insert((u32::from(a), p.len()));
                }
                (_, IpAddr::V6(a)) => {
                    c.v6.insert((u128::from(a), p.len()));
                }
                _ => {}
            }
        }
        c
    }

    #[inline]
    fn banned(&self, addr: IpAddr) -> bool {
        if self.hosts.contains(&addr) {
            return true;
        }
        match addr {
            IpAddr::V4(a) => self.v4.get_lpm(&(u32::from(a), 32)).is_some(),
            IpAddr::V6(a) => self.v6.get_lpm(&(u128::from(a), 128)).is_some(),
        }
    }
}

fn door(c: &mut Criterion) {
    let f = fixture();
    let comp = Composition::new(&f.prefixes);
    // Both see the same verdicts.
    for a in f.banned.iter().chain(f.admitted.iter()) {
        let ours = f.bouncer.door(*a).is_err();
        assert_eq!(ours, comp.banned(*a), "{a}");
    }
    let now = f.bouncer.now();
    let mut g = c.benchmark_group("door_1m");
    let mut i = 0usize;
    g.bench_function("bouncer/admitted", |b| {
        b.iter(|| {
            i = (i + 1) & 4095;
            let t = f.bouncer.door_at(
                ConnId(i as u64),
                black_box(f.admitted[i]),
                Provenance::Socket,
                now,
            );
            black_box(t.is_ok())
        })
    });
    g.bench_function("composition/admitted", |b| {
        b.iter(|| {
            i = (i + 1) & 4095;
            black_box(comp.banned(black_box(f.admitted[i])))
        })
    });
    g.bench_function("bouncer/banned", |b| {
        b.iter(|| {
            i = (i + 1) % f.banned.len();
            let t = f.bouncer.door_at(
                ConnId(i as u64),
                black_box(f.banned[i]),
                Provenance::Socket,
                now,
            );
            black_box(t.is_err())
        })
    });
    g.bench_function("composition/banned", |b| {
        b.iter(|| {
            i = (i + 1) % f.banned.len();
            black_box(comp.banned(black_box(f.banned[i])))
        })
    });
    // Random peers over the whole space: every probe is a cache miss.
    let mut m = Mix(77);
    let random: Vec<IpAddr> = (0..1 << 16)
        .map(|_| {
            if m.next() % 2 == 0 {
                IpAddr::from((m.next() as u32).to_be_bytes())
            } else {
                fixture::v6((u128::from(m.next()) << 64) | (0x2001u128 << 112))
            }
        })
        .collect();
    g.bench_function("bouncer/random", |b| {
        b.iter(|| {
            i = (i + 1) & 0xffff;
            let t = f.bouncer.door_at(
                ConnId(i as u64),
                black_box(random[i]),
                Provenance::Socket,
                now,
            );
            black_box(t.is_ok())
        })
    });
    g.bench_function("composition/random", |b| {
        b.iter(|| {
            i = (i + 1) & 0xffff;
            black_box(comp.banned(black_box(random[i])))
        })
    });
    g.finish();
}

fn budget(c: &mut Criterion) {
    // Generous limits, so both measure the admitted path.
    let rate = Rate::per_second(1_000_000_000).burst(1_000_000_000);
    let b = Bouncer::builder()
        .budgets(Budgets::off().door_rate(rate, rate))
        .tickets(64)
        .ban_capacity(1024)
        .try_build()
        .unwrap();
    let limiter = RateLimiter::keyed(Quota::per_second(NonZeroU32::new(1_000_000_000).unwrap()));
    let mut m = Mix(5);
    let peers: Vec<IpAddr> = (0..4096)
        .map(|_| IpAddr::from((m.next() as u32 | 0x8000_0000).to_be_bytes()))
        .collect();
    let mut g = c.benchmark_group("budget_check");
    let mut i = 0usize;
    g.bench_function("bouncer", |bench| {
        bench.iter(|| {
            i = (i + 1) & 4095;
            black_box(b.datagram(black_box(peers[i]), true, b.now()) == DatagramVerdict::Accept)
        })
    });
    g.bench_function("governor_keyed", |bench| {
        bench.iter(|| {
            i = (i + 1) & 4095;
            black_box(limiter.check_key(black_box(&peers[i])).is_ok())
        })
    });
    g.finish();
}

fn checkpoint(c: &mut Criterion) {
    let b = Bouncer::builder()
        .budgets(Budgets::off())
        .tickets(64)
        .ban_capacity(1024)
        .try_build()
        .unwrap();
    let conn = b.door("192.0.2.1".parse().unwrap()).unwrap();
    let mut req = conn.request(RequestId(1)).unwrap();
    let flag = Arc::new(AtomicBool::new(false));
    let mut g = c.benchmark_group("checkpoint_fast");
    g.bench_function("bouncer", |bench| {
        bench.iter(|| black_box(req.checkpoint().is_pass()))
    });
    g.bench_function("arc_atomic_bool", |bench| {
        bench.iter(|| black_box(!black_box(&flag).load(Ordering::Acquire)))
    });
    g.finish();
}

/// Where the door's time goes: the ticket alone (an empty bouncer), the
/// judgement alone on empty tables, and the judgement against the fixture
/// (`datagram`, verified, budgets off: allow list, proxies, ban memory).
fn parts(c: &mut Criterion) {
    let empty = Bouncer::builder()
        .budgets(Budgets::off())
        .tickets(4096)
        .ban_capacity(1024)
        .try_build()
        .unwrap();
    let f = fixture();
    let now = f.bouncer.now();
    let mut g = c.benchmark_group("door_parts");
    let mut i = 0usize;
    g.bench_function("ticket_only", |b| {
        b.iter(|| {
            i = (i + 1) & 4095;
            black_box(
                empty
                    .door_at(
                        ConnId(i as u64),
                        black_box(f.admitted[i]),
                        Provenance::Socket,
                        now,
                    )
                    .is_ok(),
            )
        })
    });
    g.bench_function("judge_empty", |b| {
        b.iter(|| {
            i = (i + 1) & 4095;
            black_box(empty.datagram(black_box(f.admitted[i]), true, now))
        })
    });
    g.bench_function("judge_1m_admitted", |b| {
        b.iter(|| {
            i = (i + 1) & 4095;
            black_box(f.bouncer.datagram(black_box(f.admitted[i]), true, now))
        })
    });
    g.bench_function("judge_1m_banned", |b| {
        b.iter(|| {
            i = (i + 1) % f.banned.len();
            black_box(f.bouncer.datagram(black_box(f.banned[i]), true, now))
        })
    });
    g.bench_function("clock_now", |b| b.iter(|| black_box(f.bouncer.now())));
    g.finish();
}

criterion_group! {
    name = comparison;
    config = Criterion::default().sample_size(50);
    targets = door, budget, checkpoint, parts
}
criterion_main!(comparison);
