//! NFR-3: ticket issue and release with many threads at once (PLAN 11:
//! under 40 ns median at 32 threads).
//!
//! Every thread runs the door and drops the ticket, on one bouncer with no
//! bans and no budgets, so what is measured is the ticket: the free list,
//! the cell, and the shard's reference count. Each thread times batches;
//! the table shows the median and p99 batch across all threads, in
//! nanoseconds per cycle, and the total rate.
//!
//! `cargo bench --bench threads`.

use std::{
    hint::black_box,
    net::IpAddr,
    sync::{Arc, Barrier},
    time::Instant,
};

use bouncer_io::{Bouncer, Budgets, ConnId, Provenance};

/// Cycles per timed batch, and batches per thread.
const BATCH: usize = 2_000;
const BATCHES: usize = 400;

fn run(threads: usize) -> (f64, f64, f64) {
    let bouncer = Bouncer::builder()
        .budgets(Budgets::off())
        .tickets(65_536)
        .try_build()
        .unwrap();
    let barrier = Arc::new(Barrier::new(threads));
    let start = Instant::now();
    let handles: Vec<_> = (0..threads)
        .map(|t| {
            let bouncer = bouncer.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let peer = IpAddr::from([192, 0, 2, t as u8]);
                let now = bouncer.now();
                for i in 0..BATCH {
                    black_box(
                        bouncer
                            .door_at(ConnId(i as u64), peer, Provenance::Socket, now)
                            .is_ok(),
                    );
                }
                barrier.wait();
                (0..BATCHES)
                    .map(|b| {
                        let s = Instant::now();
                        for i in 0..BATCH {
                            let t = bouncer.door_at(
                                ConnId((b * BATCH + i) as u64),
                                black_box(peer),
                                Provenance::Socket,
                                now,
                            );
                            black_box(t.is_ok());
                        }
                        s.elapsed().as_nanos() as f64 / BATCH as f64
                    })
                    .collect::<Vec<f64>>()
            })
        })
        .collect();
    let mut all: Vec<f64> = handles
        .into_iter()
        .flat_map(|h| h.join().unwrap())
        .collect();
    let secs = start.elapsed().as_secs_f64();
    all.sort_by(f64::total_cmp);
    let at = |p: f64| all[((all.len() as f64 - 1.0) * p) as usize];
    let rate = (threads * BATCH * (BATCHES + 1)) as f64 / secs / 1e6;
    (at(0.5), at(0.99), rate)
}

fn main() {
    println!(
        "{:<10} {:>12} {:>12} {:>14}",
        "threads", "median ns", "p99 ns", "M cycles/s"
    );
    let cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
    for threads in [1, 2, 4, 8, 16, 32] {
        if threads > cpus {
            break;
        }
        let (median, p99, rate) = run(threads);
        println!("{threads:<10} {median:>12.1} {p99:>12.1} {rate:>14.1}");
    }
}
