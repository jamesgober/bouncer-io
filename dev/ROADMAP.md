# bouncer-io - Roadmap

> Path from scaffold to a stable 1.0, on the portfolio's version series. Hard parts are front-loaded; each version has hard exit criteria and names the API items it delivers (by section of [`../docs/API.md`](../docs/API.md)).
> Design and decisions: [`PLAN.md`](./PLAN.md). Edge cases and threats are numbered there (section 12.5 and section 8).
>
> **Anti-deferral rule:** no listed hard task moves to a later version unless this file records the move and the reason.

## v0.1.0 - Scaffold (DONE, 2026-10-13)
- [x] Manifest, README, CHANGELOG, REPS, dual license, CI, deny, clippy, rustfmt, DIRECTIVES, ROADMAP, PLAN.

## v0.2.0 - Design lock (DONE, 2026-10-22)
Exit: James approves `docs/API.md`; net-io's plan references the same hook shapes; every open decision has an answer or a recorded owner.
- [x] Every public item written in `docs/API.md` with tier, grade, version, cost, errors, and examples.
- [x] `dev/PLAN.md` rewritten from the specification; decisions D-009 to D-035 logged; open decisions answered (PLAN section 15).
- [x] Roadmap rewritten to the portfolio series (D-009).
- [x] Cell and ban-entry layouts with computed sizes (PLAN 7.4, 7.8); loom model plan (PLAN 12.4).
- [x] net-io hook shape proposed for net-io's 0.2 (D-015).
- [x] README: Tier 1 example, `&mdash;` entities removed; DIRECTIVES aligned.
- [x] James's approval of the API (2026-10-22).
- [x] Hook shape agreed with net-io's 0.2: the `Gate` trait (D-015, 2026-10-23).
- [x] net-io confirmed the two additions (`GateTag` in `Admitted` and `ConnectionInfo`; `WriteCheck.response`), 2026-10-23 (PLAN D-055).
- [x] Release: version 0.2.0, CHANGELOG, `docs/release/v0.2.0.md`, CI, tag, GitHub release, publish (O-16).

## v0.3.0 - Core: keys, ban memory, the door, tickets, the epoch
Items: constants; `Bouncer::new`, `builder`, `door`, `door_at`, `ban`, `lift`, `now`, `capacity`; builder capacity, lengths, durations, allow list, trusted proxies, clock, seed, `try_build`; every key type; `Refusal`, `Provenance`; `Ticket` issue, accessors, `request`, `checkpoint` (epoch and direct flags), `bind_client`, release on drop, `tag`; `TicketId`, `TicketKind`, `TicketTag`; `Verdict`, `Denial`, `DenialCode`, `Reference`; `BanSpec`, `LiftSpec`, `BanDuration`, `BanId`, `Lifted`, `DurationPolicy` with jitter, `AllowList`; `Actor`, `ActorKind`, `Reason`, `Evidence`; dynamic ban table and compiled prefix set; `BouncerError`, `ConfigError`.
Exit:
- [x] A banned address or prefix is refused before a byte, with 1,000,000 bans (first measurement recorded in PLAN 11.1). The 100 ns p99 target is not met yet; see the move below.
- [x] Edge cases 1 to 19 and 21 to 26 pass (`tests/door.rs`, unit tests in `keys`, `ticket`, `bans`).
- [x] Loom L-2 and L-3 pass.
- [x] No allocation on door, request, checkpoint, release, and `bind_client` (`tests/alloc.rs`).
- [x] Property tests 1 to 6 of PLAN 12.2 (`tests/properties.rs`).
- [x] Threat tests T-1 (door part), T-2 (rotation part), T-9 (flooding needs the key), T-10, T-18.
- [x] Fuzz target `cidr_parse` builds and runs in CI.

## v0.4.0 - Extended: revocation, wipe, replace, eject, strikes, budgets, events
crypt-io 1.2 with the public `wipe` (O-3) was published 2026-10-23.
Also: edge cases 20, 27, 28; the strike part of T-1.
Items: `revoke`, `apply`, `Target`, `RevokeMode`, `Revocation`, `RevocationEpoch`, builder `epoch`; revocation tables, quiescence cleanup, idle-ticket checks, eject-now sweeps; `before_commit`, `is_cancelled`, `bind_fingerprint`, `bind_session`, `bind_account`, `bind_tenant`; `Bouncer::request`, `egress`, `release`, `into_tag`; `Collected`; `DenialFormat`, `NoFormat`, `Ejector`, `CloseKind`, `Ejected`, `deny_and_eject`; `Denial`, `DenialCode`, `DenialTable`, `Reference`; `Directive`, `Action`, `BanKeys`, `Applied`; strikes, `StrikeRules`, `Enforcement` (observe by default); door budgets and `Rate`; `EventSink`, `Event`, signal catalog; `maintain`, the parked maintainer; `revocation_rate_limit`; `docs/INTEGRATION.md`.
Exit:
- [x] A request revoked at each checkpoint (between stages, before commit, pipeline egress, transport egress) never sends a byte of its original response, never passes before-commit, gets the configured denial, and is ejected (`tests/revoke.rs`, `tests/wipe.rs`).
- [x] `Collected` memory reads all zero after wipe and at free, growth included (inspecting allocator, debug and release, `tests/wipe.rs`).
- [x] Loom L-1, L-4, L-5, L-6 pass (with L-2 and L-3).
- [x] 10^8 checkpoints with concurrent revocations: no missed revocation (`tests/stress.rs`, release, about 0.1 s).
- [x] Edge cases 20, 27 to 44, and 46 pass; 45 (a formatter that panics) and 47 (the flush deadline) are the transport's and are documented.
- [x] Threat tests T-1 (strikes), T-6, T-7 (in-process), T-8 (byte equality), T-11, T-13, T-14 (one source cannot exhaust the registry), T-21, T-22, T-23, T-26. T-12 (p99 under a revocation storm) is a benchmark and moves to 0.6.
- [x] Fuzz target `directive_sequence` (against a model of bans and revocations), run in CI with `cidr_parse`.
- [x] No allocation on egress, binds, before-commit, and strikes added to `tests/alloc.rs`.
- [x] `docs/INTEGRATION.md`.

## v0.5.0 - Feature complete
Also: identity throttles (moved from 0.4, PLAN D-052); `set_posture` and its effects (PLAN D-053); `health` reporting revocation load and detached tickets.
Items: `BanRecord`; escalation, offender memory, shared-address detection; lane and tenant budgets, `bind_lane`; throttle directives; posture; `explain`, `list`, `replace_allow`; `health`; persistence (snapshot, journal, MAC, `FilePersistence`, `LoadFailure`, wall-jump rules); sharing (`NodeId`, `Delta`, `Sequence`, `ImportReport`, HLC stamps, revocation records, skew bound); `metrics`; `datagram`; `docs/ARCHITECTURE.md`.
Exit:
- [x] Bans survive a restart; the kill test (`tests/persistence.rs`) runs in CI on Linux, macOS, and Windows, 12 rounds per run and 1,000 before a release (PLAN D-078).
- [x] Two in-process bouncers exchanging deltas converge under every permutation, each delivered twice; each keeps enforcing when the other is gone; a revocation on one stops a running request on the other (`tests/share.rs`).
- [x] Every P0, P1, and P2 item of `docs/API.md` exists, except `TABLE_RESEEDED`, which belongs to the table rebuild moved to 0.6 (PLAN D-038).
- [x] Edge cases 48 to 67 pass (the list ends at 67).
- [x] Threat tests T-3, T-4, T-5, T-15, T-16, T-17, T-19, T-20, T-25, T-27.
- [x] Fuzz targets `snapshot_decode`, `journal_replay`, `delta_decode`, run in CI with the others.

## v0.6.0 - Optimisation
Items: the door under 100 ns p99 with 1,000,000 bans (moved from 0.3); T-12, p99 checkpoint under 100,000 revocations per second (moved from 0.4); table rebuild with a fresh seed at the probe bound (moved from 0.3); 8-byte keys and 32-byte slots; the benchmarks of PLAN 11 against the named competitors; prefix structure confirmed or changed (O-4); keyed hash chosen (O-8); shard `Arc` confirmed (O-5); `#[track_caller]` cost on `checkpoint` measured (0.2 defence idea); `docs/PERFORMANCE.md`.
Exit:
- [x] Every target of PLAN 11 met, or the gap recorded here with a plan: see `docs/PERFORMANCE.md`. Gaps: the door's 100 ns p99 (113.4 ns per call admitted; plan below); ticket issue and release at 32 threads (not measured; measured at one thread, 40.1 ns); memory per ban 56 B against 45 to 48 B (within the 64 B limit; plan below).
- [ ] NFR-10 met on `door_1m` (PLAN D-081: 20% faster than the same-job composition). Not met: admitted 113.4 against 109.3 ns, random peers 151.2 against 118.1 ns. `checkpoint_fast` within 10% of an `AtomicBool` load: met (0.2 against 0.3 ns). `budget_check`: bouncer checks two rates (client and prefix) in about the time governor checks one.
- [x] Baselines committed; the 5% regression gate active (Callgrind instruction counts in `benches/gate-baseline.txt`, from the first CI run; the second run matched it exactly).
- [x] T-12: checkpoints under 100,009 revocations a second, p99 0.8 ns (mean of 10,000); the slow path with seven keys bound, p99 96.2 ns.
- [x] O-4, O-5, O-8 decided by measurement (PLAN D-082, D-085); `#[track_caller]` measured (D-089); `docs/PERFORMANCE.md` written.

The plan to reach NFR-10 (each estimate marked as such until built and measured):

| Step | Expected | Cost and risk |
|---|---|---|
| one probe for a family's automatic lengths: a prefix's children stored in its group, with an overflow path | random peers -15 to -30 ns, admitted about -10 ns [est.] | a table redesign: probe-overflow rules must keep the per-parent quota (T-4) and the probe bound; loom and fuzz again |
| 8-byte keys and 32-byte slots | random peers -5 to -15 ns [est.]; memory per ban 56 -> about 32 B | the same redesign; identity keys keep their digests beside the slot or in a second table |
| keyed multiply-mix hash with the table reseed at the probe bound (T-9) | about -5 to -8 ns [est.] | the reseed needs a whole-table swap that readers never wait on |
| connection release without the link swap (a store-load pairing proved by a loom model) | about -4 ns [est.] | a new loom model |
| a fast monotonic clock in clock-lib, for `door` | `door` -15 to -20 ns [est.] | clock-lib's own release; `door_at` does not need it |

Moves recorded at 0.7: the loopback half of edge case 47 (the transport aborting a slow reader after the flush deadline) moves to 0.8 with the net-io feature (reason: the abort is the transport's; bouncer's part, handing over the deadline, is tested at 0.7).

Moves recorded at 0.6: the table rebuild with a fresh seed (T-9) and 8-byte keys with 32-byte slots move with the plan above (reason: both are parts of the ban-table redesign; with SipHash under a random key an attacker cannot choose colliding keys without the key, and an insert past the probe bound still fails cleanly as `BanTableFull` with an event).

## v0.7.0 - Hardening
Items: every fuzz target run 24 h without findings; every attack test of PLAN 8; the timing test (T-8); 24 h soak (NFR-13); three-node simulation with partitions, skew, and reordering; adversarial review with every finding fixed test-first; `docs/SECURITY.md`, `docs/PLATFORM-NOTES.md`.
Exit:
- [x] Zero open findings (the table below; every fuzz target ran 24 hours on the final code with no findings).
- [x] Soak shows flat memory and no missed revocation (24 hours on the final code: 540 million connections, 57.1 million revocations, none missed; live heap 45.98 MB from the first hour to the last, varying by under 6 KB).
- [x] Timing distributions not separable (D-093: admitted latency against neighbours' bans, bind latency near banned digests; the control separates).
- [x] Edge cases 69 to 71 pass (69: correctness under 32 threads, and 10^5 bans and lifts a second on one thread, measured 2.3 million; 71: a blocking sink sees no admitted connection and 100 refusals a second).

Review findings (each fixed test-first; open until its fix lands):

| Finding | Status |
|---|---|
| Forged datagrams drained a real prefix's budget, refusing its TCP connections | fixed, D-092 |
| Full budget tables admitted newcomers uncharged; concurrency tables smaller than the registry lifted the per-address limit; `budget_load` reported a healthy bouncer as unhealthy | fixed, D-094 |
| Decoder fuzz targets stopped at the checksum (`delta_decode` coverage 53) | fixed, D-095 |
| Sharing does not converge: a lift is ordered against the held ban's local issue time in whole seconds, clamped to this node's start, instead of the ban's stamp; and one merged entry per key cannot apply "a channel lifts only its own node's bans" in an order-independent way when two nodes ban the same key (`tests/cluster.rs`, seed 1: diverges in 15 steps) | fixed, D-096: per-origin bans with their stamps; the simulation passes over 5,000 seeds |
| Adversarial review: a node channel could forge another node's records, poison the seen-set, or pin bans; a restart made peers drop a node's new records; import evictions grew the ledger; origins per key unbounded; imported bans skipped the placement rules; a request could outlive its connection on the fast path; revoking a connection from a request left its siblings passing; persistence rollback undetected without a counter outside the files | fixed, D-101 (rollback documented as not covered, `docs/SECURITY.md`) |
| Edge cases 34, 40, 45, 47 had no test; 16, 17, 22, 30, 32, 33, 39, 43, 46, 48, 59, 67, 69, 71 were partly tested; test comments numbered edge cases by an older list | fixed: every one tested; on the way, D-097 (the handshake deadline), D-098 (sampled events were not sampled), D-099 (a strike into a full table revoked nothing; a stronger later revocation did not raise the code), D-100 (the epoch steps over `u64::MAX`) |

The 24-hour fuzz and soak runs ran on the final 0.7 code (2026-10-26 to 2026-10-27).

## v0.8.0 - Alpha
Needs a published net-io 0.3 or later.
Items: feature `net-io` (`Gate` for `Bouncer`, `ConnectionGate`, conversions, `NetIoEjector`); serve-net running with bouncer on Windows and WSL; the replay harness (scanner, slowloris, credential stuffing from a /48, CGNAT population).

Status: the `net-io` feature is built and tested over loopback (`tests/net_io.rs`, D-107). The replay harness is built (`tests/replay.rs`) and found two defects, both fixed test-first: credential stuffing that moves to a new /64 per attempt was never banned (D-108), and a CGNAT population was refused as one client by the default door budgets (D-109). Results, attacker against innocents:

| Trace | Attacker | Innocents |
|---|---|---|
| scanner: one IPv4 address, 20 malformed connections a second for a minute; 50 neighbours in its /24 | 5 admitted, banned at 250 ms | 3,000 admitted, none refused |
| slowloris: one address, a connection every 10 ms held 30 s until the transport kills it | at most 64 held, banned at 30 s | 4,800 admitted, none refused |
| credential stuffing from a /48, a new /64 per attempt | 80 attempts, then the /48 banned (8 s) | 600 admitted from the next /48, none refused |
| CGNAT: 2,000 users behind one address, 100 connections a second; one of them guesses passwords | 5 requests served, then session and account banned | 12,000 admitted, none refused |

serve-net running with bouncer, and the same traces through it, wait for serve-net's first release: it is not on crates.io, and a path dependency is not allowed (each repository builds alone in CI).
Exit:
- [x] A browser on localhost banned by an admin call is refused at the door (`tests/net_io.rs`, a net-io server on loopback; the browser itself is checked with serve-net).
- [x] A logged-in browser whose session is revoked mid-request gets the generic denial and its connection is closed (`tests/net_io.rs`: the session's denial and nothing of the body, then a reset).
- [x] A streamed response cut by revocation leaks at most one chunk (loopback capture: nothing after the revocation reaches the client).
- [ ] serve-net running with bouncer on Windows and WSL (waits for serve-net's first release).
- [ ] NFR-10: the door 20% faster than the same-job composition, admitted and random peers (PLAN D-081).

NFR-10 work at 0.8 (A/B against the 0.7 base, pinned to one core; the totals, 0.7.0 against this branch, are in `docs/PERFORMANCE.md`):

| Step | Result |
|---|---|
| keyed multiply mix, reseed at the probe bound (D-102) | judgement with 1,000,000 bans -27%, `door_at` admitted -11% |
| addresses anchored at their family's shortest automatic length, one group per lookup (D-104) | `door_at` random peers -15% |
| first table and allow list read without a thread-local access | judgement -10% more |
| each length's key built once, unkeyed tags past the anchor, direct masks | judgement 55 -> 33 ns in all |
| 32-byte slots, one-word keys, long keys as keyed fingerprints (D-105) | memory per ban 56.0 -> 37.7 B (NFR-6 met); door within noise; account revocation -20% |
| connection release without the link swap | dropped: loom L-7 fails without it (D-103) |
| a per-thread stash of free cells | dropped: no gain measured (the thread-local access costs what the two compare-and-swaps did) |
| the ticket owner releasing with a load and a store | dropped: loom L-5 rejects it |
| budgets reusing the lookup's prefix hash | dropped: no gain measured |
| the budget cells loaded before the ban lookup, so their misses overlap | dropped: random peers +26%, banned peers +92% (a banned peer now pays for cells it never needed) |
| budget slots carrying their payload: a rate key's arrival time and a concurrency count beside the key, GCRA parameters shared by the tier (D-106) | `door_at` random peers -13%, `door` random peers -18%, admitted -13% (machine under full load; relative only); a rate key 88 -> 16 B |
| a fast clock for `door` | not in clock-lib: its directives put timers out of scope and forbid `unsafe` (no timestamp counter); `door_at` with the transport's accept time is the fast path |

Where it stands (0.7.0 against this branch, 10 alternating rounds): `door_at` admitted 112.7 -> 92.1 ns against the composition's 110.7 (17% faster; the target is 20%, about 89 ns); random peers 150.3 -> 133.3 against 115.9 (1.15 times slower; the target is about 93 ns); banned 68.8 -> 55.5. For random peers the parts are: ticket 43 ns, judgement with 1,000,000 bans 34 ns, the two rate checks about 36 ns (the client's and the prefix's slots, in two tables, both missing the cache).

Next steps (estimates until built and measured):

| Step | Expected | Cost and risk |
|---|---|---|
| a client's budget slot in its prefix's probe sequence (the D-104 anchor applied to the budget tables), so one cache miss serves both rate checks; after D-106 each tier misses once, so this saves one more | random peers -8 to -12 ns [est.] | reclaiming idle slots must not let a prefix's clients push out the prefix's own slot; the per-prefix fairness of T-4 must hold; loom again for the claim path |
| the ticket cell and its connection id written in one cache line on issue | admitted -3 to -5 ns [est.] | a cell layout change; loom L-5 and L-7 again |

## v0.9.0 - Beta and release candidates
Items: used end to end by the web stack and one non-HTTP service (a database network layer or the back-channel); API review against the simple-API rule; `cargo-semver-checks` in CI; release candidates `0.9.x`.
Exit:
- [ ] No API change needed by either consumer for two release candidates.

## v1.0.0 - Stable
Items: the full audit (API, docs, tests, benchmarks, security) recorded in `docs/STABILITY-1.0.md`.
Exit:
- [ ] Audit passed; API frozen until 2.0. James gives the go before the tag.

## After 1.0
- Challenge verdict and proof-of-work verifier; kernel-drop export; tarpit mode; ASN keys once a data source is chosen.

## Moves recorded
- 2026-10-23: T-12 (checkpoint p99 under a revocation storm) moves from 0.4 to 0.6. Reason: it is a latency benchmark, and 0.6 is where the benchmarks run on a quiet machine; the storm's correctness (every revocation applies, the excess is reported) is tested at 0.4.
- 2026-10-23: identity throttles (session, account) move from 0.4 to 0.5 with lane and tenant budgets, and `set_posture` with its budget halving to 0.5. Reason: each acts on budgets that land at 0.5. `Throttle` on a source works at 0.4.
- 2026-10-23: the door's 100 ns p99 target moves from the 0.3 exit to 0.6, where it already stands as an exit. Reason: measured at 0.3 on a shared machine (PLAN 11.1), the door costs 230-360 ns per call with 1,000,000 bans and random peers. The cost is ticket issue and release (about 70 ns), hashing (about 30 ns per probe), and TLB and cache misses into a 60 MiB table. The fixes are optimisation work: 8-byte keys and 32-byte slots, the O-8 hash decision, fewer atomic operations per ticket, and measurement on a quiet machine.
- 2026-10-23: rebuilding a ban table with a fresh seed when the probe bound is reached (part of T-9) moves to 0.6 with the O-8 hash decision (PLAN D-038). Reason: it needs a lock-free whole-table swap, and with SipHash under a random key, colliding keys can be chosen only with the key. Until then an insert past the bound fails cleanly as `BanTableFull`.
- 2026-10-23: edge case 20 (`bind_session` twice) moves to 0.4 with the identity binds, edge cases 27 and 28 (tags after `release`) to 0.4 with `Bouncer::release`, and the strike part of T-1 to 0.4 with strikes. `BanRecord` moves to 0.5 with `list` and `explain`, its first users. Reason: each needs an item of that version.
- 2026-10-22: the old 0.3 "door" and 0.4 "inside" phases became 0.3 core and 0.4 extended; strikes and door budgets moved from the old 0.3 to 0.4 because they report through the event sink, which is built in 0.4 (nothing is dropped; the door's ban checks stay in 0.3). The old 0.5 "memory and sharing" is part of 0.5 feature complete. The old 0.9 hardening is now 0.7, earlier than before.
- 2026-10-22: the net-io hook implementation is at 0.8, not 0.3 as in the old roadmap, because it depends on a published net-io 0.3 and no path dependency is allowed. bouncer's own `egress(tag)` and `request(tag, id)` are at 0.4, so the hook is a thin adapter when it lands.
