# bouncer-io - Roadmap

> Path from scaffold to a stable 1.0, on the portfolio's version series. Hard parts are front-loaded; each version has hard exit criteria and names the API items it delivers (by section of [`../docs/API.md`](../docs/API.md)).
> Design and decisions: [`PLAN.md`](./PLAN.md). Edge cases and threats are numbered there (section 12.5 and section 8).
>
> **Anti-deferral rule:** no listed hard task moves to a later version unless this file records the move and the reason.

## v0.1.0 - Scaffold (DONE, 2026-10-13)
- [x] Manifest, README, CHANGELOG, REPS, dual license, CI, deny, clippy, rustfmt, DIRECTIVES, ROADMAP, PLAN.

## v0.2.0 - Design lock
Exit: James approves `docs/API.md`; net-io's plan references the same hook shapes; every open decision has an answer or a recorded owner.
- [x] Every public item written in `docs/API.md` with tier, grade, version, cost, errors, and examples.
- [x] `dev/PLAN.md` rewritten from the specification; decisions D-009 to D-035 logged; open decisions answered (PLAN section 15).
- [x] Roadmap rewritten to the portfolio series (D-009).
- [x] Cell and ban-entry layouts with computed sizes (PLAN 7.4, 7.8); loom model plan (PLAN 12.4).
- [x] net-io hook shape proposed for net-io's 0.2 (D-015).
- [x] README: Tier 1 example, `&mdash;` entities removed; DIRECTIVES aligned.
- [ ] James's approval of the API.
- [ ] net-io's 0.2 confirms the close notice, the per-response gate tag, and kill by id (or the gap is recorded here with its reason).
- [ ] Release: version 0.2.0, CHANGELOG, `docs/release/v0.2.0.md`, CI, tag, GitHub release, publish (O-16).

## v0.3.0 - Core: keys, ban memory, the door, tickets, the epoch
Items: constants; `Bouncer::new`, `builder`, `door`, `door_at`, `ban`, `lift`, `now`, `capacity`; builder capacity, lengths, durations, allow list, trusted proxies, clock, seed, `try_build`; every key type; `Refusal`, `Provenance`; `Ticket` issue, accessors, `request`, `checkpoint` (epoch and direct flags), `bind_client`, release on drop, `tag`; `TicketId`, `TicketKind`, `TicketTag`; `Verdict`; `BanSpec`, `LiftSpec`, `BanDuration`, `BanRecord`, `DurationPolicy` with jitter, `AllowList`; `Actor`, `Reason`, `Evidence`; dynamic ban table and compiled prefix set; `BouncerError`, `ConfigError`.
Exit:
- [ ] A banned address or prefix is refused before a byte, with 1,000,000 bans, under 100 ns p99 (first measurement, recorded).
- [ ] Edge cases 1 to 28 pass.
- [ ] Loom L-2 and L-3 pass.
- [ ] No allocation on door and checkpoint (counting allocator).
- [ ] Property tests 1 to 6 of PLAN 12.2.
- [ ] Threat tests T-1 (door part), T-2, T-9 (reseed), T-10, T-18.
- [ ] Fuzz target `cidr_parse` builds and runs in CI.

## v0.4.0 - Extended: revocation, wipe, replace, eject, strikes, budgets, events
Needs crypt-io 1.2 with the public `wipe` (O-3) published first.
Items: `revoke`, `apply`, `Target`, `RevokeMode`, `Revocation`, `RevocationEpoch`, builder `epoch`; revocation tables, quiescence cleanup, idle-ticket checks, eject-now sweeps; `before_commit`, `is_cancelled`, `bind_fingerprint`, `bind_session`, `bind_account`, `bind_tenant`; `Bouncer::request`, `egress`, `release`, `into_tag`; `Collected`; `DenialFormat`, `NoFormat`, `Ejector`, `CloseKind`, `Ejected`, `deny_and_eject`; `Denial`, `DenialCode`, `DenialTable`, `Reference`; `Directive`, `Action`, `BanKeys`, `Applied`; strikes, `StrikeRules`, `Enforcement` (observe by default); door budgets and `Rate`; `EventSink`, `Event`, signal catalog; `maintain`, the parked maintainer; `revocation_rate_limit`; `docs/INTEGRATION.md`.
Exit:
- [ ] A request revoked at each checkpoint (between stages, before commit, pipeline egress, transport egress) never sends a byte of its original response, never passes before-commit, gets the configured denial, and is ejected.
- [ ] `Collected` memory reads all zero after wipe and at free (inspecting allocator, release build).
- [ ] Loom L-1, L-4, L-5, L-6 pass.
- [ ] 10^8 checkpoints with concurrent revocations: no missed revocation.
- [ ] Edge cases 29 to 47 pass.
- [ ] Threat tests T-6, T-7 (in-process), T-8 (byte equality), T-11, T-12, T-13, T-14, T-21, T-22, T-23, T-26.
- [ ] Fuzz target `directive_sequence`.

## v0.5.0 - Feature complete
Items: escalation, offender memory, shared-address detection; lane and tenant budgets, `bind_lane`; throttle directives; posture; `explain`, `list`, `replace_allow`; `health`; persistence (snapshot, journal, MAC, `FilePersistence`, `LoadFailure`, wall-jump rules); sharing (`NodeId`, `Delta`, `Sequence`, `ImportReport`, HLC stamps, revocation records, skew bound); `metrics`; `datagram`; `docs/ARCHITECTURE.md`.
Exit:
- [ ] Bans survive a restart (kill tests pass on Linux, macOS, Windows).
- [ ] Two in-process bouncers exchanging deltas converge under every permutation; each keeps enforcing when the other is gone; a revocation on one stops a running request on the other.
- [ ] Every P0, P1, and P2 item of `docs/API.md` exists.
- [ ] Edge cases 48 to 68 pass.
- [ ] Threat tests T-3, T-4, T-5, T-15, T-16, T-17, T-19, T-20, T-25, T-27.
- [ ] Fuzz targets `snapshot_decode`, `journal_replay`, `delta_decode`.

## v0.6.0 - Optimisation
Items: the benchmarks of PLAN 11 against the named competitors; prefix structure confirmed or changed (O-4); keyed hash chosen (O-8); shard `Arc` confirmed (O-5); `#[track_caller]` cost on `checkpoint` measured (0.2 defence idea); `docs/PERFORMANCE.md`.
Exit:
- [ ] Every target of PLAN 11 met, or the gap recorded here with a plan.
- [ ] NFR-10 met on `door_1m` and `budget_check`; `checkpoint_fast` within 10% of an `AtomicBool` load.
- [ ] Baselines committed; the 5% regression gate active.

## v0.7.0 - Hardening
Items: every fuzz target run 24 h without findings; every attack test of PLAN 8; the timing test (T-8); 24 h soak (NFR-13); three-node simulation with partitions, skew, and reordering; adversarial review with every finding fixed test-first; `docs/SECURITY.md`, `docs/PLATFORM-NOTES.md`.
Exit:
- [ ] Zero open findings.
- [ ] Soak shows flat memory and no missed revocation.
- [ ] Timing distributions not separable.
- [ ] Edge cases 69 to 71 pass.

## v0.8.0 - Alpha
Needs a published net-io 0.3 or later.
Items: feature `net-io` (`Admission`, `Egress`, conversions, `NetIoEjector`); serve-net running with bouncer on Windows and WSL; the replay harness (scanner, slowloris, credential stuffing from a /48, CGNAT population).
Exit:
- [ ] A browser on localhost banned by an admin call is refused at the door.
- [ ] A logged-in browser whose session is revoked mid-request gets the generic denial and its connection is closed.
- [ ] A streamed response cut by revocation leaks at most one chunk (loopback capture).

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
- 2026-10-22: the old 0.3 "door" and 0.4 "inside" phases became 0.3 core and 0.4 extended; strikes and door budgets moved from the old 0.3 to 0.4 because they report through the event sink, which is built in 0.4 (nothing is dropped; the door's ban checks stay in 0.3). The old 0.5 "memory and sharing" is part of 0.5 feature complete. The old 0.9 hardening is now 0.7, earlier than before.
- 2026-10-22: the net-io hook implementation is at 0.8, not 0.3 as in the old roadmap, because it depends on a published net-io 0.3 and no path dependency is allowed. bouncer's own `egress(tag)` and `request(tag, id)` are at 0.4, so the hook is a thin adapter when it lands.
