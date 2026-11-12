//! Many threads at once.
//!
//! NFR-3 (PLAN 11: ticket issue and release under 40 ns median at 32
//! threads): every thread runs the door and drops the ticket, on one bouncer
//! with no bans and no budgets, so what is measured is the ticket: the free
//! list, the cell, and the shard's reference count.
//!
//! The door against the same-job composition (NFR-10 is judged on one
//! thread; a server runs many): the fixture of 1,000,000 bans and both door
//! rate tiers on bouncer's side, the composition with its rate check per
//! address and per prefix on the other, each thread admitting its own
//! addresses.
//!
//! Each thread times batches; the tables show the median and p99 batch
//! across all threads, in nanoseconds per operation, and the total rate.
//! `cargo bench --bench threads`.

#[path = "common/compose.rs"]
mod compose;
#[path = "common/fixture.rs"]
mod fixture;

use std::{hint::black_box, net::IpAddr, sync::Barrier, time::Instant};

use bouncer_io::{Bouncer, Budgets, ConnectionId, Provenance, Rate};

/// Operations per timed batch, and batches per thread.
const BATCH: usize = 2_000;
const BATCHES: usize = 400;

/// Median and p99 nanoseconds per operation over every thread's batches, and
/// millions of operations a second in all. `op(thread, i)` runs one.
fn run(threads: usize, op: &(impl Fn(usize, usize) + Sync)) -> (f64, f64, f64) {
    let barrier = Barrier::new(threads);
    let start = Instant::now();
    let mut all: Vec<f64> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..threads)
            .map(|t| {
                let barrier = &barrier;
                s.spawn(move || {
                    for i in 0..BATCH {
                        op(t, i);
                    }
                    barrier.wait();
                    (0..BATCHES)
                        .map(|b| {
                            let s = Instant::now();
                            for i in 0..BATCH {
                                op(t, b * BATCH + i);
                            }
                            s.elapsed().as_nanos() as f64 / BATCH as f64
                        })
                        .collect::<Vec<f64>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect()
    });
    let secs = start.elapsed().as_secs_f64();
    all.sort_by(f64::total_cmp);
    let at = |p: f64| all[((all.len() as f64 - 1.0) * p) as usize];
    let rate = (threads * BATCH * (BATCHES + 1)) as f64 / secs / 1e6;
    (at(0.5), at(0.99), rate)
}

fn header(title: &str) {
    println!("{title}");
    println!(
        "{:<10} {:>12} {:>12} {:>14}",
        "threads", "median ns", "p99 ns", "M ops/s"
    );
}

fn counts() -> impl Iterator<Item = usize> {
    let cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
    [1, 2, 4, 8, 16, 32].into_iter().filter(move |&t| t <= cpus)
}

fn main() {
    header("ticket issue and release (NFR-3)");
    for threads in counts() {
        let bouncer = Bouncer::builder()
            .budgets(Budgets::off())
            .tickets(65_536)
            .build()
            .unwrap();
        let now = bouncer.now();
        let (median, p99, rate) = run(threads, &|t, i| {
            let peer = IpAddr::from([192, 0, 2, t as u8]);
            let ticket = bouncer.door_at(
                ConnectionId(i as u64),
                black_box(peer),
                Provenance::Socket,
                now,
            );
            black_box(ticket.is_ok());
        });
        println!("{threads:<10} {median:>12.1} {p99:>12.1} {rate:>14.1}");
    }

    let rate = Rate::per_second(1_000_000_000).burst(1_000_000_000);
    let f = fixture::fixture_with(Budgets::off().door_rate(rate, rate).capacity(1 << 20));
    let equal = compose::EqualJob::with_prefix_rate(&f.prefixes);
    // Each thread its own 1,024 addresses, each in a /48 of its own and
    // outside every banned range, so no two threads share a prefix's rate
    // state (the fixture's admitted addresses share a few prefixes).
    let peers: Vec<Vec<IpAddr>> = (0..32u128)
        .map(|t| {
            (0..1024u128)
                .map(|i| fixture::v6((0x3ffe_u128 << 112) | (t << 96) | (i << 80) | 1))
                .collect()
        })
        .collect();
    assert!(peers.iter().flatten().all(|&p| f.bouncer.door(p).is_ok()));
    let peer = |t: usize, i: usize| peers[t][i & 1023];
    let now = f.bouncer.now();
    println!();
    header("door_at, 1,000,000 bans, both rate tiers, admitted peers in their own prefixes");
    for threads in counts() {
        let (median, p99, rate) = run(threads, &|t, i| {
            let ticket = f.bouncer.door_at(
                ConnectionId(((t as u64) << 40) | i as u64),
                black_box(peer(t, i)),
                Provenance::Socket,
                now,
            );
            black_box(ticket.is_ok());
        });
        println!("{threads:<10} {median:>12.1} {p99:>12.1} {rate:>14.1}");
    }
    println!();
    header("same-job composition, rate per address and per prefix, the same peers");
    for threads in counts() {
        let (median, p99, rate) = run(threads, &|t, i| {
            let id = ((t as u64) << 40) | i as u64;
            let handle = equal.door(id, black_box(peer(t, i)));
            if handle.is_some() {
                equal.release(id);
            }
            black_box(handle.is_some());
        });
        println!("{threads:<10} {median:>12.1} {p99:>12.1} {rate:>14.1}");
    }
}
