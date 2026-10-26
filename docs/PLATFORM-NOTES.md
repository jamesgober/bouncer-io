<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br><b>bouncer-io</b><br>
    <sub><sup>PLATFORM NOTES</sup></sub>
</h1>
<div align="center">
    <sup>
        <a href="../README.md" title="Project Home"><b>HOME</b></a>
        <span>&nbsp;│&nbsp;</span>
        <a href="./API.md" title="API reference"><b>API</b></a>
        <span>&nbsp;│&nbsp;</span>
        <a href="./ARCHITECTURE.md" title="Architecture"><b>ARCHITECTURE</b></a>
        <span>&nbsp;│&nbsp;</span>
        <a href="./PERFORMANCE.md" title="Performance"><b>PERFORMANCE</b></a>
        <span>&nbsp;│&nbsp;</span>
        <a href="./SECURITY.md" title="Security"><b>SECURITY</b></a>
        <span>&nbsp;│&nbsp;</span>
        <span>PLATFORM NOTES</span>
    </sup>
</div>
<br>

What differs between the platforms bouncer-io runs on, and what a deployment should know about each.

- [Supported targets](#supported-targets)
- [Clocks](#clocks)
- [Persistence and durability](#persistence-and-durability)
- [Threads, shards, and CPUs](#threads-shards-and-cpus)
- [Memory](#memory)
- [Building and testing](#building-and-testing)

## Supported targets

| | |
|---|---|
| Tested | Linux and Windows on x86-64, macOS on arm64 (the CI runners), Rust stable and 1.85 |
| Required | 64-bit atomics (`AtomicU64`): tickets, the epoch, and the ban table's sequence locks are 64-bit words. Targets without them (some 32-bit microcontrollers) are not supported |
| Unsafe code | none (`#![forbid(unsafe_code)]`); the guaranteed wipe goes through crypt-io's volatile writes |

## Clocks

bouncer-io reads a monotonic clock for expiry and budgets, and the wall clock only for persistence and sharing, through clock-lib (`ManualClock` in tests).

- `Bouncer::now` costs about 24 ns on Windows (measured, `docs/PERFORMANCE.md`); a transport that already has the accept time should call `door_at` with it instead of `door`.
- `std::time::Instant` resolves 100 ns on Windows. Per-call latencies below that cannot be measured with it there; the benches time batches.
- Expiry is monotonic: stepping the wall clock never shortens or lengthens a ban in force. Wall-clock steps between a save and a load follow the rules of [`docs/API.md`](./API.md) (`max_wall_jump`, `strict_wall_jump`), and are reported (`persist.wall_jump`).

## Persistence and durability

`FilePersistence` writes a snapshot to a temporary file, syncs it, and renames it over the old one; journal batches are appended and synced.

| | Unix | Windows |
|---|---|---|
| Snapshot replace | rename, then the directory is synced, so the rename itself survives a power loss | rename replaces the target; Windows has no directory sync, so a power loss right after the rename can leave the old snapshot (never a mix of the two) |
| Journal | appended and synced (`fsync`) | appended and synced (`FlushFileBuffers`) |
| Torn writes | a torn journal tail is dropped on load, a damaged record stops the replay, and the rest is reported lost; both platforms the same |

A store of your own (`Persistence`) decides its own durability; bouncer-io calls `sync` after every batch.

## Threads, shards, and CPUs

- The ticket registry is split into shards: by default the number of logical CPUs, rounded up to a power of two, at most 256. A thread is given a shard on first use and keeps it; a ticket can be dropped on any thread.
- The optional maintenance thread is named `bouncer-maintainer`. It parks when nothing is due (no wake-ups while idle).
- On CPUs with more than one core complex (for example two-CCD Ryzen parts), the scheduler moving a thread between complexes changes latency by 30% or more; the published numbers are pinned to one core.

## Memory

| | Bytes |
|---|---|
| Ban table | 56 per slot, allocated at build (`ban_capacity`) |
| Ledger of each node's bans (nodes with a node id) | 151 per ban held, growing with the bans (measured with 100,000 bans) |
| Budget tables | allocated at build (`Budgets::capacity`); the concurrency tables hold at least twice the ticket capacity |
| Outbound sharing log, lift memory | at most 65,536 records each, growing to that bound |

`Bouncer::capacity` reports the bytes of every table.

## Building and testing

- The loom models and the fuzz targets run on Linux (fuzzing needs a nightly toolchain and `cargo-fuzz`).
- The timing tests and the soak are ignored by default: `cargo test --release --test timing -- --ignored` and `BOUNCER_SOAK_SECS=86400 cargo test --release --test soak -- --ignored --nocapture`.
- The instruction-count gate runs Callgrind on Linux in CI (`benches/gate.rs`).

<br>

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>James Gober.</strong></sup>
</div>
