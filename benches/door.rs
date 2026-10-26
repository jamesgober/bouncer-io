//! The door with 1,000,000 bans over every automatic length and 10,000
//! administrator prefixes (NFR-2), and the checkpoint fast path (NFR-1).
//!
//! `cargo bench --bench door`. The p99 numbers come from
//! `cargo run --release --example door_p99`.

#[path = "common/fixture.rs"]
mod fixture;

use std::hint::black_box;

use bouncer_io::{ConnId, Provenance, RequestId};
use criterion::{Criterion, criterion_group, criterion_main};

fn benches(c: &mut Criterion) {
    let fixture::Fixture {
        bouncer: b,
        banned,
        admitted,
        ..
    } = fixture::fixture();
    let now = b.now();
    let mut i = 0usize;
    c.bench_function("door_1m/admitted", |bench| {
        bench.iter(|| {
            i = (i + 1) & 4095;
            let t = b.door_at(
                ConnId(i as u64),
                black_box(admitted[i]),
                Provenance::Socket,
                now,
            );
            black_box(t.is_ok())
        })
    });
    c.bench_function("door_1m/banned", |bench| {
        bench.iter(|| {
            i = (i + 1) % banned.len();
            let t = b.door_at(
                ConnId(i as u64),
                black_box(banned[i]),
                Provenance::Socket,
                now,
            );
            black_box(t.is_err())
        })
    });
    let conn = b.door(admitted[0]).unwrap();
    let mut req = conn.request(RequestId(1)).unwrap();
    c.bench_function("checkpoint_fast", |bench| {
        bench.iter(|| black_box(req.checkpoint().is_pass()))
    });
    c.bench_function("ticket_cycle", |bench| {
        bench.iter(|| black_box(conn.request(RequestId(2)).is_ok()))
    });
}

criterion_group! {
    name = door;
    config = Criterion::default().sample_size(50);
    targets = benches
}
criterion_main!(door);
