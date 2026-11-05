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
- [What 0.8 changed](#what-08-changed)
- [What 0.9 changed](#what-09-changed)
- [Many threads](#many-threads)
- [The NFR-10 target](#the-nfr-10-target)
- [The regression gate](#the-regression-gate)

## How it is measured

| | |
|---|---|
| Host | AMD Ryzen 9 9950X3D, Windows 11 |
| Toolchain | Rust 1.95.0, release profile (fat LTO, one codegen unit) |
| Bench | `cargo bench --bench perf` |
| Method | each case runs in 61 rounds of 20,000 operations; the tables show the fastest round and the median round, in nanoseconds per operation |
| Pinning | the process is pinned to one logical core (`ProcessorAffinity` 0x4 before 0.9, 0x1000 from 0.9: logical core 2 turned out to share its physical core with a long-running job of other work). Unpinned, the scheduler moves the process between the CPU's two core complexes and results swing by 30% or more; pinned, two runs agree within a few percent |
| Comparing | from 0.9, the door is judged against the compositions by the median of six processes' within-run ratios: an identical binary's absolute numbers moved 15% between processes (each gets its own memory layout), while the ratio within one process held within 2 points |
| Fixture | 1,000,000 bans over IPv4 /32 and /24 and IPv6 /64, /56, /48, plus 10,000 administrator prefixes at other lengths; an allow list and trusted proxies of two entries each; probes: 4,096 admitted addresses, 65,536 random addresses over the whole space, 4,096 banned addresses |

The two compositions (`benches/common/compose.rs`):

- **Same-job composition**: the NFR-10 comparison (PLAN D-081). Everything bouncer's door does, built from the best crate for each part, in the door's order: a trusted-proxy check and an allow-list check (`prefix-trie` longest-prefix match per family, the same entries), the ban lookup (a `HashSet` of banned hosts and a `prefix-trie` per family holding the same 1,010,000 prefixes), a per-address rate check (`governor` keyed limiter), and a revocable handle per admitted connection (an `Arc<AtomicBool>` registered in a `DashMap` and removed when the connection ends).
- **Lookup-only composition**: the ban lookup and the rate check alone. It does less than the door (no revocable handle, no allow list, no proxies), so it is not a like-for-like comparison; it is published because it is the obvious first thing to compare with.

Equal conditions: both sides give the same verdict on every probe (checked before measuring). bouncer's rate budget is generous enough never to refuse, like the composition's limiter, and holds as many keys as the run uses (the composition's map grows without bound; bouncer's tables are fixed at build). bouncer checks two rates (per client and per prefix) where the composition checks one. `door_at` takes the time from the caller, as net-io does with its accept time; `door` reads the clock itself, as `governor` does (governor reads a TSC-based clock; bouncer reads the operating system's, about 24 ns on Windows).

## The door against both compositions

| Case | `door_at` | `door` | Same-job composition | Lookup-only composition |
|---|---|---|---|---|
| admitted | 101.6 | 131.6 | 119.8 | 51.0 |
| random peers | 130.8 | 170.0 | 126.6 | 73.9 |
| banned | 67.0 | 93.0 | 17.0 | 11.8 |

Fastest of 10 rounds, ns per operation, at 0.8. The machine was under full load from other work when these were taken, so every row is about 8 to 10% above a quiet run (the composition rows were 110 to 116 ns on a quieter one); compare rows with each other, not with the 0.6 figures. Admitted: bouncer is 15% faster than the same-job composition. Random peers: bouncer is within 3% of it (the ban table's group and the two budget tiers miss the cache one after the other). Banned: the composition finds a banned host in its `HashSet` and stops; bouncer reads the address's anchor group and checks every length in use.

## Where the door's time goes

| Part | ns |
|---|---|
| ticket issue and release (empty bouncer, judgement included) | 50.1 |
| request ticket cycle | 45.4 |
| one `Arc` allocation per request (for comparison) | 27.8 |
| judgement, nothing configured | 8.7 |
| judgement, allow list and proxies | 10.3 |
| judgement, 1,000,000 bans | 36.5 |
| judgement, 1,000,000 bans and the administrator set | 41.8 |
| `door_at` without the rate budget, admitted / random peers | 89.6 / 123.6 |
| `Bouncer::now` | 26.0 |

The same loaded run as the table above. The ticket is cheaper than the composition's revocable handle (about 47 ns of `Arc` and `DashMap`). The ban lookup with 1,000,000 bans costs about 28 ns over an empty bouncer: one group read for all of an address's lengths, hashed with a keyed multiply mix. The two rate checks cost 7 to 18 ns for random peers across runs now that each key's state sits beside it in one slot (about 36 ns before D-106). What is left for random peers over admitted ones is mostly the ban table's cache miss, about 34 ns without a rate budget.

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
| door, 1,000,000 bans and 10,000 administrator prefixes: under 100 ns p99 | per call with a nanosecond timer (Linux, `examples/door_p99.rs`, 1,000,000 distinct cold peers): p50 111 ns, p99 462 ns at best, on a host whose every core was busy; warm, 95.5 ns per call (fastest round, admitted) | not met; re-derived target proposed (PLAN D-121) |
| ticket issue and release under 40 ns median, 32 threads | 42.4 ns at one thread on an idle core, 57.9 ns median at 32 (D-113) | not met; re-derived target proposed (PLAN D-121) |
| bind under 30 ns each | about 27 ns (request and session bind 68.0, request alone 41.0) | met |
| revoke under 1 µs | 134 ns (account, 0.9: a second slot write, D-116) | met |
| ban insert under 500 ns | median 453 ns while the table fills to 1.2 million (fastest round 331) | met |
| eject-now sweep, 65,536 cells, under 1 ms | 361 µs over 65,535 live cells | met |
| memory per ban 45 to 48 B, hard limit 64 B | 37.7 B (32-byte slots at the table's load, tag bytes and overflow bits included) | met |
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

## What 0.8 changed

The 0.7.0 and 0.8 binaries run alternately on the same core, ten rounds each, fastest round kept, with the machine under full load from other work (both sides saw the same load; the composition rows moved under 1%):

| Case | 0.7.0 | 0.8 | Change |
|---|---|---|---|
| `door_at`, admitted | 126.0 | 101.6 | -19% |
| `door`, admitted | 155.8 | 131.6 | -16% |
| `door_at`, random peers | 149.2 | 130.8 | -12% |
| `door`, random peers | 284.1 | 170.0 | -40% |
| `door_at`, banned | 74.8 | 67.0 | -10% |
| judgement, 1,000,000 bans and the administrator set | 63.3 | 41.8 | -34% |
| ticket issue and release | 49.5 | 50.1 | +1% |
| revoke (account) | 185.8 | 149.5 | -20% |
| ban insert, fastest round while the table fills | 450.6 | 500.2 | +11% (+5% on a lightly loaded machine) |
| memory per ban | 56.0 B | 37.7 B | -33% |
| memory per key of a rate budget | 88 B | 16 B | -82% |

What did it: the ban table hashes with a keyed multiply mix instead of SipHash and is rebuilt under a fresh key if an insert reaches the probe bound (PLAN D-102); an address's keys from its family's shortest automatic length on share one probe sequence, so a lookup reads one group for all of them (D-104); each length's key is built once, keys past the anchor are tagged by an unkeyed multiply, and the first table and the allow list are read without a thread-local access; slots are 32 bytes, with keys that fit one word stored exactly and longer keys as keyed fingerprints (D-105); a budget key's state sits beside it in one slot, under rate-net's `GcraParams` shared by the tier (D-106, D-110). Ban insert pays about 5% for the fingerprint and the originals kept beside the table.

Tried and dropped: connection release without its link swap (loom model L-7 fails without it, D-103); a per-thread stash of free connection cells, and budgets reusing the lookup's prefix hash (no gain measured); the ticket owner releasing with a plain load and store (loom model L-5 rejects it); loading the budget slots before the ban lookup, again on the new table (random peers +26%, banned peers +92%); touching the prefix tier's slot after the ban lookup, before the client tier's locked update (no gain measured).

## What 0.9 changed

The door against both compositions, within-run ratios (door/composition), median of six processes, one idle core; the second composition also checks a rate per prefix, the same rate work as the door (D-120):

| Case | `door_at` | Same-job composition | ratio | with a prefix rate too | ratio |
|---|---|---|---|---|---|
| admitted | 95.5 | 114.7 | 0.837 | 133.2 | 0.728 |
| random peers | 124.3 | 124.2 | 1.004 | 147.1 | 0.846 |
| random peers near the bans | 112.0 | 151.2 | 0.724 | 191.2 | 0.578 |
| banned | 63.8 | 17.0 | 3.75 | 16.5 | 3.86 |

ns per operation: each row's median over the six processes of its fastest round. "Random peers near the bans" draws IPv4 addresses with the top bit set and IPv6 under 2001::/16, the space the dynamic bans cover; in the plain random set a quarter of the peers are IPv4 below that, which the fixture's administrator /8s cover almost entirely, so they take the refusal path. A second run, under full load from other work, gave the same ratios within 3 points.

What moved, and why:

- **The anchors are on** (D-118). D-104's grouped lookup, one probe group for every automatic length of an address, had never been switched on. It is now, with an anchored key held to its anchor's first four groups. `door_at` random peers 133.6 to 124.3 ns, the judgement of random peers 74.6 to 63.8 ns.
- **Shards no longer share cache lines** (D-113). This changes nothing on one thread; it is the many-threads table below.
- **Ban insert** has 24% fewer instructions (5,880 against 7,735 per insert under Callgrind). Offender memory and the escalation tracker hash with keyed SipHash-1-3 one word per field, where the standard library's hasher took each field byte by byte. The free-slot scan reads tags before slots, and probe steps wrap without a division. Its time is back to about 0.7.0's: 4% faster than 0.8.0 in an alternating run, within that run's noise.
- **Revocation** costs a second slot write (D-116): account revocation 101 to 134 ns on an idle core (17% in an alternating run under load). This is the price of births that a racing epoch move cannot defeat.

0.8.0 against 0.9, alternating on one core under full load from other work (both sides saw the same load; the composition rows moved up to 8% between them, which is this run's noise):

| Case | 0.8.0 | 0.9 | change |
|---|---:|---:|---:|
| `door_at`, random peers | 224.6 | 195.6 | -12.9% |
| `door`, random peers | 355.3 | 323.1 | -9.1% |
| `door_at`, admitted | 149.4 | 147.9 | -1.0% |
| judgement, 1,000,000 bans and the administrator set | 68.6 | 57.9 | -15.6% |
| ban insert, fastest round while the table fills | 620.1 | 593.9 | -4.2% |
| revoke (account) | 151.5 | 176.8 | +16.7% |

Where the instructions of an admitted `door_at` go (Callgrind, 1,105 in all): the two rate tiers 287, the probe of the automatic lengths 236 and its slot comparisons 69, ticket issue 140 and release 86, the rest the door's own steps. A banned one (636): the lookup 305, the reference 114, reporting the refusal 28.

## Many threads

`benches/threads.rs`, every thread its own 1,024 addresses in /48s of their own (so no two threads share a prefix's rate state), not pinned, on a machine with other work running:

| Threads | ticket cycle, median | `door_at`, median | `door_at`, M a second | composition, median | composition, M a second |
|---:|---:|---:|---:|---:|---:|
| 1 | 58.1 | 151.0 | 6.7 | 161.4 | 6.1 |
| 2 | 56.9 | 152.4 | 13.2 | 212.7 | 8.0 |
| 8 | 58.0 | 166.8 | 48.1 | 435.4 | 16.5 |
| 16 | 58.2 | 184.5 | 81.7 | 581.6 | 26.8 |
| 32 | 58.2 | 194.2 | 100.9 | 851.4 | 34.4 |

The door with both rate tiers and 1,000,000 bans against the composition with its rate per address and per prefix; at 32 threads the door does 2.9 times its work. Before D-113 the ticket cycle took 162 ns at 32 threads (its free lists and shard handles shared cache lines); on an idle pinned core it is 42.4 ns at one thread and flat to eight. The door's p99 at 32 threads, about 3 µs, is two threads per core with other work on the machine.

## The NFR-10 target

NFR-10 (PLAN D-081, decided by James): the door at least 20% faster than the same-job composition, admitted and random peers. At 0.9 it is not met against that composition (admitted 16.3% faster, random peers at parity); against a composition doing the door's rate work (a rate per address and per prefix) the door is 27.2% and 15.4% faster, and 2.9 times its throughput at 32 threads. Why the remaining gap is not closed without giving something up, and the re-derived target proposed to James, are in PLAN D-120 and [`docs/READINESS-1.0.md`](./READINESS-1.0.md).

## The regression gate

Time on a shared machine cannot gate a 5% regression, so CI counts instructions instead: `benches/gate.rs` runs each hot path (door admitted and banned, the request cycle, the checkpoint, a session bind, a ban insert) in its own function under Callgrind, and `scripts/gate.py` compares each function's inclusive count with `benches/gate-baseline.txt`. More than 5% over fails the build. The counts repeat run to run (fixed seeds, fixed inputs).

<br>

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>James Gober.</strong></sup>
</div>
