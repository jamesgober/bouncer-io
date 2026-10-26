//! A low-noise table of the door against both compositions (NFR-10).
//!
//! Each case runs in many short rounds; the table shows the fastest round
//! (least disturbed by other work on the machine) and the median round, in
//! nanoseconds per operation. `cargo bench --bench perf`. The numbers in
//! `docs/PERFORMANCE.md` come from this.

#[path = "common/compose.rs"]
mod compose;
#[path = "common/fixture.rs"]
mod fixture;

use std::{
    hint::black_box,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use bouncer_io::{Bouncer, Budgets, ConnId, Provenance, Rate, RequestId};
use compose::{EqualJob, LookupOnly};
use fixture::Mix;

/// Rounds per case, and operations per round.
const ROUNDS: usize = 61;
const OPS: usize = 20_000;

/// Fastest and median nanoseconds per operation.
fn measure(mut op: impl FnMut(usize)) -> (f64, f64) {
    for i in 0..OPS {
        op(i);
    }
    let mut rounds: Vec<f64> = (0..ROUNDS)
        .map(|r| {
            let start = Instant::now();
            for i in 0..OPS {
                op(r * OPS + i);
            }
            start.elapsed().as_nanos() as f64 / OPS as f64
        })
        .collect();
    rounds.sort_by(f64::total_cmp);
    (rounds[0], rounds[ROUNDS / 2])
}

fn row(name: &str, (best, median): (f64, f64)) {
    println!("{name:<34} {best:>8.1} {median:>8.1}");
}

fn main() {
    // `cargo bench` passes `--bench`; anything else filters nothing.
    let rate = Rate::per_second(1_000_000_000).burst(1_000_000_000);
    let f = fixture::fixture_with(Budgets::off().door_rate(rate, rate));
    let lookup = LookupOnly::new(&f.prefixes);
    let equal = EqualJob::new(&f.prefixes);
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
    let now = f.bouncer.now();
    println!(
        "{:<34} {:>8} {:>8}",
        "case (ns per operation)", "fastest", "median"
    );
    for (name, probes) in [
        ("admitted", &f.admitted),
        ("random", &random),
        ("banned", &f.banned),
    ] {
        let n = probes.len();
        row(
            &format!("door/{name}"),
            measure(|i| {
                black_box(f.bouncer.door(black_box(probes[i % n])).is_ok());
            }),
        );
        row(
            &format!("door_at/{name}"),
            measure(|i| {
                let t = f.bouncer.door_at(
                    ConnId(i as u64),
                    black_box(probes[i % n]),
                    Provenance::Socket,
                    now,
                );
                black_box(t.is_ok());
            }),
        );
        row(
            &format!("same-job composition/{name}"),
            measure(|i| {
                let t = equal.door(i as u64, black_box(probes[i % n]));
                if t.is_some() {
                    equal.release(i as u64);
                }
                black_box(t.is_some());
            }),
        );
        row(
            &format!("lookup-only composition/{name}"),
            measure(|i| {
                black_box(lookup.admit(black_box(probes[i % n])));
            }),
        );
    }
    // Parts of the door.
    let empty = Bouncer::builder()
        .budgets(Budgets::off())
        .tickets(4096)
        .ban_capacity(1024)
        .try_build()
        .unwrap();
    let conn = f.bouncer.door(f.admitted[0]).unwrap();
    let mut req = conn.request(RequestId(1)).unwrap();
    let flag = Arc::new(AtomicBool::new(false));
    let no_rate = fixture::build(Budgets::off(), 10_000);
    row(
        "door_at, no rate budget, admitted",
        measure(|i| {
            let t = no_rate.bouncer.door_at(
                ConnId(i as u64),
                black_box(no_rate.admitted[i & 4095]),
                Provenance::Socket,
                now,
            );
            black_box(t.is_ok());
        }),
    );
    drop(no_rate);
    let no_admin = fixture::build(Budgets::off(), 0);
    row(
        "door_at, no rate, no admin set, admitted",
        measure(|i| {
            let t = no_admin.bouncer.door_at(
                ConnId(i as u64),
                black_box(no_admin.admitted[i & 4095]),
                Provenance::Socket,
                now,
            );
            black_box(t.is_ok());
        }),
    );
    drop(no_admin);
    row(
        "ticket only (empty bouncer)",
        measure(|i| {
            black_box(
                empty
                    .door_at(
                        ConnId(i as u64),
                        black_box(f.admitted[i & 4095]),
                        Provenance::Socket,
                        now,
                    )
                    .is_ok(),
            );
        }),
    );
    row(
        "judgement, 1m bans, admitted",
        measure(|i| {
            let _ = black_box(
                f.bouncer
                    .datagram(black_box(f.admitted[i & 4095]), true, now),
            );
        }),
    );
    row(
        "request ticket cycle",
        measure(|i| {
            black_box(conn.request(RequestId(i as u128 + 2)).is_ok());
        }),
    );
    row(
        "arc per request",
        measure(|_| {
            black_box(Arc::new(AtomicBool::new(false)));
        }),
    );
    row(
        "checkpoint",
        measure(|_| {
            black_box(req.checkpoint().is_pass());
        }),
    );
    row(
        "atomic bool load",
        measure(|_| {
            black_box(!black_box(&flag).load(Ordering::Acquire));
        }),
    );
    row(
        "Bouncer::now",
        measure(|_| {
            black_box(f.bouncer.now());
        }),
    );
}
