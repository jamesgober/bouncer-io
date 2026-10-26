//! bouncer against the obvious composition of existing crates for the same
//! job (NFR-10), on the same data:
//!
//! - `door_1m`: bouncer's door (ban memory, a per-address rate budget, and
//!   the ticket) against a `prefix-trie` longest-prefix match per family, a
//!   `HashSet` exact lookup, and a `governor` keyed rate check, holding the
//!   same 1,010,000 prefixes (PLAN 11).
//! - `door_1m/equal_job`: the composition doing the door's whole job: the
//!   same lookups and rate check, plus an allow-list trie, a trusted-proxy
//!   trie, and a revocable handle per connection (an `Arc<AtomicBool>`
//!   registered in a `DashMap`, removed when the connection ends).
//! - `ticket_cycle`: issuing and releasing a request ticket against one
//!   `Arc` allocation per request.
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

/// The composition: one trie per family for prefixes, a hash set for hosts,
/// and a keyed rate limiter.
struct Composition {
    v4: PrefixSet<(u32, u8)>,
    v6: PrefixSet<(u128, u8)>,
    hosts: HashSet<IpAddr>,
    limiter: governor::DefaultKeyedRateLimiter<IpAddr>,
}

impl Composition {
    fn new(prefixes: &[Cidr]) -> Composition {
        let mut c = Composition {
            v4: PrefixSet::new(),
            v6: PrefixSet::new(),
            hosts: HashSet::new(),
            limiter: RateLimiter::keyed(Quota::per_second(NonZeroU32::new(1_000_000_000).unwrap())),
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

    /// The door's job: not banned, and within the rate.
    #[inline]
    fn admit(&self, addr: IpAddr) -> bool {
        !self.banned(addr) && self.limiter.check_key(&addr).is_ok()
    }
}

/// The composition with the rest of the door's job.
struct EqualJob {
    inner: Composition,
    allow_v4: PrefixSet<(u32, u8)>,
    allow_v6: PrefixSet<(u128, u8)>,
    proxy_v4: PrefixSet<(u32, u8)>,
    proxy_v6: PrefixSet<(u128, u8)>,
    live: dashmap::DashMap<u64, Arc<AtomicBool>>,
}

impl EqualJob {
    fn new(prefixes: &[Cidr]) -> EqualJob {
        let mut e = EqualJob {
            inner: Composition::new(prefixes),
            allow_v4: PrefixSet::new(),
            allow_v6: PrefixSet::new(),
            proxy_v4: PrefixSet::new(),
            proxy_v6: PrefixSet::new(),
            live: dashmap::DashMap::new(),
        };
        // A few entries, like a real deployment's lists.
        e.allow_v4.insert((0x0a14_0000, 16));
        e.allow_v6.insert((0xfd00_u128 << 112, 8));
        e.proxy_v4.insert((0x0a00_0000, 8));
        e.proxy_v6.insert((0xfd12_u128 << 112, 16));
        e
    }

    /// Admit and register a revocable handle; returns it (dropping it
    /// deregisters, as a ticket's release does).
    #[inline]
    fn door(&self, id: u64, addr: IpAddr) -> Option<(u64, Arc<AtomicBool>)> {
        let (allowed, proxy) = match addr {
            IpAddr::V4(a) => {
                let k = (u32::from(a), 32);
                (
                    self.allow_v4.get_lpm(&k).is_some(),
                    self.proxy_v4.get_lpm(&k).is_some(),
                )
            }
            IpAddr::V6(a) => {
                let k = (u128::from(a), 128);
                (
                    self.allow_v6.get_lpm(&k).is_some(),
                    self.proxy_v6.get_lpm(&k).is_some(),
                )
            }
        };
        if !allowed && !proxy && !self.inner.admit(addr) {
            return None;
        }
        let h = Arc::new(AtomicBool::new(false));
        self.live.insert(id, Arc::clone(&h));
        Some((id, h))
    }

    fn release(&self, id: u64) {
        self.live.remove(&id);
    }
}

fn door(c: &mut Criterion) {
    // A per-address rate budget generous enough never to refuse, like the
    // composition's limiter.
    let rate = Rate::per_second(1_000_000_000).burst(1_000_000_000);
    let f = fixture::fixture_with(Budgets::off().door_rate(rate, rate));
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
            black_box(comp.admit(black_box(f.admitted[i])))
        })
    });
    let equal = EqualJob::new(&f.prefixes);
    g.bench_function("equal_job/admitted", |b| {
        b.iter(|| {
            i = (i + 1) & 4095;
            let t = equal.door(i as u64, black_box(f.admitted[i]));
            if let Some((id, _)) = &t {
                equal.release(*id);
            }
            black_box(t.is_some())
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
            black_box(comp.admit(black_box(f.banned[i])))
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
    g.bench_function("equal_job/random", |b| {
        b.iter(|| {
            i = (i + 1) & 0xffff;
            let t = equal.door(i as u64, black_box(random[i]));
            if let Some((id, _)) = &t {
                equal.release(*id);
            }
            black_box(t.is_some())
        })
    });
    g.bench_function("composition/random", |b| {
        b.iter(|| {
            i = (i + 1) & 0xffff;
            black_box(comp.admit(black_box(random[i])))
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
    let mut g = c.benchmark_group("ticket_cycle");
    g.bench_function("bouncer", |bench| {
        bench.iter(|| black_box(conn.request(RequestId(2)).is_ok()))
    });
    g.bench_function("arc_per_request", |bench| {
        bench.iter(|| black_box(Arc::new(AtomicBool::new(false))))
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
