<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br><b>bouncer-io</b><br>
    <sub><sup>PERFORMANCE</sup></sub>
</h1>
<div align="center">
    <sup>
        <a href="../README.md" title="Project Home"><b>HOME</b></a>
        <span>&nbsp;│&nbsp;</span>
        <a href="./API.md" title="API reference"><b>API</b></a>
        <span>&nbsp;│&nbsp;</span>
        <a href="./ARCHITECTURE.md" title="Architecture"><b>ARCHITECTURE</b></a>
        <span>&nbsp;│&nbsp;</span>
        <span>PERFORMANCE</span>
    </sup>
</div>
<br>

What the door, the checkpoint, and the ticket cost, measured against compositions of existing crates doing the same work on the same data. Every number here comes from a bench in this repository; run it yourself to check.

- [How it is measured](#how-it-is-measured)
- [The door against both compositions](#the-door-against-both-compositions)
- [Where the door's time goes](#where-the-doors-time-goes)
- [Checkpoints and revocation storms](#checkpoints-and-revocation-storms)
- [What 0.6 changed](#what-06-changed)
- [The NFR-10 target](#the-nfr-10-target)
- [The regression gate](#the-regression-gate)

## How it is measured

| | |
|---|---|
| Host | AMD Ryzen 9 9950X3D, Windows 11 |
| Toolchain | Rust 1.95.0, release profile (fat LTO, one codegen unit) |
| Bench | `cargo bench --bench perf` |
| Method | each case runs in 61 rounds of 20,000 operations; the tables show the fastest round and the median round, in nanoseconds per operation |
| Pinning | the process is pinned to one logical core (`ProcessorAffinity` 0x4). Unpinned, the scheduler moves the process between the CPU's two core complexes and results swing by 30% or more; pinned, two runs agree within a few percent |
| Fixture | 1,000,000 bans over IPv4 /32 and /24 and IPv6 /64, /56, /48, plus 10,000 administrator prefixes at other lengths; an allow list and trusted proxies of two entries each; probes: 4,096 admitted addresses, 65,536 random addresses over the whole space, 4,096 banned addresses |

The two compositions (`benches/common/compose.rs`):

- **Same-job composition**: the NFR-10 comparison (PLAN D-081). Everything bouncer's door does, built from the best crate for each part, in the door's order: a trusted-proxy check and an allow-list check (`prefix-trie` longest-prefix match per family, the same entries), the ban lookup (a `HashSet` of banned hosts and a `prefix-trie` per family holding the same 1,010,000 prefixes), a per-address rate check (`governor` keyed limiter), and a revocable handle per admitted connection (an `Arc<AtomicBool>` registered in a `DashMap` and removed when the connection ends).
- **Lookup-only composition**: the ban lookup and the rate check alone. It does less than the door (no revocable handle, no allow list, no proxies), so it is not a like-for-like comparison; it is published because it is the obvious first thing to compare with.

Equal conditions: both sides give the same verdict on every probe (checked before measuring). bouncer's rate budget is generous enough never to refuse, like the composition's limiter, and holds as many keys as the run uses (the composition's map grows without bound; bouncer's tables are fixed at build). bouncer checks two rates (per client and per prefix) where the composition checks one. `door_at` takes the time from the caller, as net-io does with its accept time; `door` reads the clock itself, as `governor` does (governor reads a TSC-based clock; bouncer reads the operating system's, about 24 ns on Windows).

## The door against both compositions

| Case | `door_at` | `door` | Same-job composition | Lookup-only composition |
|---|---|---|---|---|
| admitted | 113.4 | 140.3 | 109.3 | 46.6 |
| random peers | 151.2 | 178.8 | 118.1 | 66.6 |
| banned | 70.8 | 91.8 | 15.7 | 10.9 |

Fastest round, ns per operation. Admitted: bouncer is within 4% of the same-job composition. Random peers: bouncer is 1.28 times slower (the ban table and budget tables miss the cache one after the other). Banned: the composition finds a banned host in its `HashSet` and stops; bouncer probes every prefix length in use.

## Where the door's time goes

| Part | ns |
|---|---|
| ticket issue and release (empty bouncer, judgement included) | 45.0 |
| request ticket cycle | 40.1 |
| one `Arc` allocation per request (for comparison) | 25.2 |
| judgement, nothing configured | 11.3 |
| judgement, allow list and proxies | 15.1 |
| judgement, 1,000,000 bans | 53.2 |
| judgement, 1,000,000 bans and the administrator set | 59.4 |
| `door_at` without the rate budget | 95.5 |
| `Bouncer::now` | 24.3 |

The ticket is cheaper than the composition's revocable handle (about 47 ns of `Arc` and `DashMap`); the two rate checks cost about the same as `governor`'s one; the ban lookup is where bouncer spends more, about 12 ns per prefix length probed, of which the keyed hash is about half.

## Checkpoints and revocation storms

`cargo bench --bench storm`, pinned to two cores (one for the revoker):

| Case | ns |
|---|---|
| checkpoint, nothing revoked (p50 / p99 of means over 10,000) | 0.3 / 0.4 |
| an `AtomicBool` load (for comparison) | 0.4 |
| checkpoint while another thread revokes 100,009 times a second (p50 / p99) | 0.4 / 0.8 |
| checkpoint slow path, seven keys bound, every kind in the revocation table (p50 / p99) | 64.4 / 96.2 |
| checkpoint through a `#[track_caller]` wrapper / a plain wrapper | 0.73 / 0.73 |

A checkpoint is as cheap as reading a flag (PLAN 11: within 10% of an `AtomicBool` load). Under a revocation storm each ticket pays the slow path once per epoch move, so the average barely moves (T-12). The slow path stays under PLAN 11's 150 ns with seven keys.

## PLAN 11 targets

| Target | Measured | |
|---|---|---|
| checkpoint, nothing revoked: median under 2 ns, p99 under 5 ns | 0.2 ns; p99 of means 0.4 ns | met |
| checkpoint slow path under 150 ns with 7 keys | p50 64.4 ns, p99 96.2 ns | met |
| before commit under 5 ns | 0.2 ns | met |
| transport egress under 3 ns | 1.3 ns | met |
| door, 1,000,000 bans and 10,000 administrator prefixes: under 100 ns p99 | 113.4 ns per call (fastest round, admitted); per-call p99 needs a nanosecond timer (`Instant` on Windows resolves 100 ns) | not met |
| ticket issue and release under 40 ns median, 32 threads | 40.1 ns, one thread; 32 threads not measured | open |
| bind under 30 ns each | about 24 ns (request and session bind 63.8, request alone 40.1) | met |
| revoke under 1 µs | 118.7 ns | met |
| ban insert under 500 ns | median 457 ns while the table fills to 1.2 million (fastest round 324) | met |
| eject-now sweep, 65,536 cells, under 1 ms | 317 µs over 65,535 live cells | met |
| memory per ban 45 to 48 B, hard limit 64 B | 56 B per table slot | within the limit, above the target |
| idle CPU: no wake-ups with nothing pending | the maintainer parks with nothing due (tested since 0.4) | met |

## What 0.6 changed

The same pinned harness on the 0.5.0 code:

| Case | 0.5.0 | 0.6 | Change |
|---|---|---|---|
| `door_at`, admitted | 149.0 | 113.4 | -24% |
| `door`, admitted | 180.4 | 140.3 | -22% |
| `door_at`, random peers | 177.5 | 151.2 | -15% |
| ticket issue and release | 84.5 | 45.0 | -47% |
| request ticket cycle | 47.3 | 40.1 | -15% |
| request and session bind | about 120 | 63.8 | -47% |
| ban insert, median while the table fills | about 3,500 | 457 | -87% |
| `door_at`, banned | 66.7 | 70.8 | +6% (within run-to-run spread) |

What did it: each prefix's keyed hash is computed once per door check and shared by the ban lookup and the door budgets (they now use the same key and encoding); the budget step hashes nothing when no budget is configured; connections are marked as holding concurrency slots only when there are any; a connection's latest request is kept in its own word, written with a plain store instead of a compare-and-swap, and no longer cleared on release; a released cell's present bits are read with a load instead of a swap; connection ids generated by the door come from the cell's index and generation instead of a shared counter; the door skips an empty allow list; a bind reads the clock only when a ban of its kind exists, and the shared-address count uses the door's latest second instead of a second clock read; offender memory and lift tombstones evict in constant time instead of scanning (offender memory had made inserts slow down without bound once it was full).

Tried and reverted, because pinned measurement showed them slower: a two-pass probe in the claims tables (the common case found its key no faster, and the hot loop grew); loading the budget slots before the ban lookup to overlap the cache misses (the loads competed with the lookup's own, and banned peers paid for budget keys they never use).

## The NFR-10 target

NFR-10 (PLAN D-081, decided by James): the door at least 20% faster than the same-job composition, which means about 90 ns admitted and about 95 ns for random peers on this host. At the end of 0.6 the door is at 113.4 and 151.2: within 4% of the composition admitted, 1.28 times slower for random peers. The target is not met. What is left, and what each step is expected to give, is in `dev/ROADMAP.md`.

## The regression gate

Time on a shared machine cannot gate a 5% regression, so CI counts instructions instead: `benches/gate.rs` runs each hot path (door admitted and banned, the request cycle, the checkpoint, a session bind, a ban insert) in its own function under Callgrind, and `scripts/gate.py` compares each function's inclusive count with `benches/gate-baseline.txt`. More than 5% over fails the build. The counts repeat run to run (fixed seeds, fixed inputs).

<br>

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>James Gober.</strong></sup>
</div>
