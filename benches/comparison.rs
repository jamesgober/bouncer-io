//! bouncer against compositions of existing crates on the same data
//! (NFR-10, PLAN D-081). Two compositions:
//!
//! - **same-job** (`door_1m/equal_job`), the NFR-10 comparison: everything
//!   bouncer's door does, built from the best crate for each part, in the
//!   door's order: a trusted-proxy check and an allow-list check
//!   (`prefix-trie` longest-prefix match per family, the same entries as
//!   bouncer's), the ban lookup (a `HashSet` of banned hosts and a
//!   `prefix-trie` per family holding the same 1,010,000 prefixes), a
//!   per-address rate check (`governor` keyed limiter, which reads its own
//!   clock), and a revocable handle per admitted connection (an
//!   `Arc<AtomicBool>` registered in a `DashMap` and removed when the
//!   connection ends, as a ticket is released).
//! - **lookup-only** (`door_1m/lookup_only`): the ban lookup and the rate
//!   check alone. Published beside the other, labelled; it does less than
//!   the door.
//!
//! bouncer's door is measured with `door` (it reads the clock, as governor
//! does) and with `door_at` (the time passed in, as a transport that already
//! holds the accept time does). Also: `ticket_cycle` (a request ticket
//! against one `Arc` per request), `budget_check` (bouncer's rate step
//! against governor alone), `checkpoint_fast` (against an `AtomicBool`
//! load), and `door_parts` (where the door's time goes).
//!
//! `cargo bench --bench comparison`. Compare ratios within one run.

#[path = "common/compose.rs"]
mod compose;
#[path = "common/fixture.rs"]
mod fixture;

use std::{
    hint::black_box,
    net::IpAddr,
    num::NonZeroU32,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use bouncer_io::{Bouncer, Budgets, ConnId, DatagramVerdict, Provenance, Rate, RequestId};
use compose::{EqualJob, LookupOnly};
use criterion::{Criterion, criterion_group, criterion_main};
use fixture::{Mix, fixture};
use governor::{Quota, RateLimiter};

fn door(c: &mut Criterion) {
    // A per-address rate budget generous enough never to refuse, like the
    // compositions' limiter.
    let rate = Rate::per_second(1_000_000_000).burst(1_000_000_000);
    let f = fixture::fixture_with(Budgets::off().door_rate(rate, rate));
    let lookup = LookupOnly::new(&f.prefixes);
    let equal = EqualJob::new(&f.prefixes);
    let mut m = Mix(77);
    // Random peers over the whole space: every probe is a cache miss.
    let random: Vec<IpAddr> = (0..1 << 16)
        .map(|_| {
            if m.next() % 2 == 0 {
                IpAddr::from((m.next() as u32).to_be_bytes())
            } else {
                fixture::v6((u128::from(m.next()) << 64) | (0x2001u128 << 112))
            }
        })
        .collect();
    // Every side gives the same verdict on every probe.
    for (n, a) in f
        .banned
        .iter()
        .chain(&f.admitted)
        .chain(&random)
        .enumerate()
    {
        let ours = f.bouncer.door(*a).is_ok();
        let theirs = equal.door(n as u64, *a).is_some();
        equal.release(n as u64);
        assert_eq!(ours, theirs, "{a}");
    }
    let sets: [(&str, &[IpAddr]); 3] = [
        ("admitted", &f.admitted),
        ("random", &random),
        ("banned", &f.banned),
    ];
    let now = f.bouncer.now();
    let mut g = c.benchmark_group("door_1m");
    for (name, probes) in sets {
        let n = probes.len();
        let mut i = 0usize;
        g.bench_function(format!("bouncer/{name}"), |b| {
            b.iter(|| {
                i = (i + 1) % n;
                black_box(f.bouncer.door(black_box(probes[i])).is_ok())
            })
        });
        g.bench_function(format!("bouncer_at/{name}"), |b| {
            b.iter(|| {
                i = (i + 1) % n;
                let t = f.bouncer.door_at(
                    ConnId(i as u64),
                    black_box(probes[i]),
                    Provenance::Socket,
                    now,
                );
                black_box(t.is_ok())
            })
        });
        g.bench_function(format!("equal_job/{name}"), |b| {
            b.iter(|| {
                i = (i + 1) % n;
                let t = equal.door(i as u64, black_box(probes[i]));
                if t.is_some() {
                    equal.release(i as u64);
                }
                black_box(t.is_some())
            })
        });
        g.bench_function(format!("lookup_only/{name}"), |b| {
            b.iter(|| {
                i = (i + 1) % n;
                black_box(lookup.admit(black_box(probes[i])))
            })
        });
    }
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
