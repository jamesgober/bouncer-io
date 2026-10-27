<h1 align="center">
    <img width="90px" height="auto" src="https://raw.githubusercontent.com/jamesgober/jamesgober/main/media/icons/hexagon-3.svg" alt="Triple Hexagon">
    <br><b>CHANGELOG</b>
</h1>
<p>
  All notable changes to <code>bouncer-io</code> will be documented in this file. The format is based on <a href="https://keepachangelog.com/en/1.1.0/">Keep a Changelog</a>,
  and this project adheres to <a href="https://semver.org/spec/v2.0.0.html/">Semantic Versioning</a>.
</p>

---

## [Unreleased]

### Changed

- The ban table hashes with a keyed multiply mix instead of SipHash-1-3 and is rebuilt under a fresh key when an insert reaches the probe bound (`table.reseeded`); the door budgets hash under a key of their own.
- An address's ban keys from its family's shortest automatic length (/24, /48 by default) share one probe sequence, so the door reads one group for all of an address's lengths; a prefix with many banned hosts spills to its own sequence.
- Ban table slots are 32 bytes: memory per ban falls from 56 to 37.7 bytes. Keys that fit one word are stored exactly; longer ones as keyed 64-bit fingerprints, with the originals kept beside the table for listings, persistence, and sharing.
- `door_at` is 18% faster admitted, 11% faster for random peers, and 19% faster for banned peers than in 0.7.0; account revocation is 25% faster; ban insert is about 5% slower.

## [0.7.0] - 2026-10-27

### Fixed

- Forged datagrams no longer spend a real source's budget. Unverified datagrams were charged at their prefix under the same key as the prefix's connections and verified datagrams, so a flood of forged UDP naming a victim's /24 or /48 could get the victim's TCP connections refused. They now have a prefix key of their own.
- Full budget tables no longer admit uncharged. Once both rate tiers were full of keys still limiting, newcomers passed with no budget at all; they are now charged together to one global cell at the prefix rate, as the design always said. The door's concurrency tables hold at least twice the ticket capacity, so held connections can no longer fill them and lift the per-address limit.
- A node channel carries only its own node's records. A hostile node could replay or forge another node's records to shorten or erase its bans, pin bans that node could not lift, or mark its records as seen so they were dropped. Records are no longer passed on; every node exchanges deltas with every other node.
- A restarted node's records reach its peers. Sequence numbers and log positions restarted at 1, so peers dropped the new records as seen.
- A ban an import evicts from a full table leaves the sharing ledger, which could otherwise grow without bound; one key holds the bans of at most 64 nodes; a channel's bans follow the placement rules of their actor and never cover a whole address family.
- A request issued while its connection was being released or revoked could pass every checkpoint; it is now revoked. Revoking a connection from one of its requests now stops the connection's other requests at once.
- Sharing converges. A lift was ordered against the held ban's local issue time in whole seconds (clamped to the node's start), and one merged ban per key could not apply "a node lifts only its own bans" in an order-independent way, so nodes could disagree after every delta was delivered. Each node's ban on a key is now kept apart with its stamp, and lifts are scoped: to their own node's bans, or to every node's for an administrator's lift delivered through the administration channel (`import(.., Actor::Admin(..))`).
- An enforced strike whose ban did not fit (the table full of bans it may not evict) left the striking peer running; it now revokes the ticket all the same (`StrikeOutcome::RevokedNotBanned`).
- Events documented as sampled (door refusals, identity budget refusals, expiries) were delivered once per occurrence; they are now sampled, at most 100 a second per signal, each carrying the count it stands for.
- A revoked ticket now reports the stronger code when a stronger revocation matches it later.
- A proxied request whose adapter never binds the client is reported once it has waited `max_unchecked` (at the next maintenance run), not only when it ends.
- The revocation epoch steps over `u64::MAX`, the mark of always-checking tickets (reachable only after 2^64 revocations).
- `Health::budget_load` counts the slots holding a key that has not recovered. It counted claimed slots, which reach 1 in normal use with many clients (recovered keys are reclaimed only when a slot is needed), so `is_ok` reported a healthy bouncer as unhealthy.
- `docs/API.md` named 0.5.0 as the current version.

### Changed

- Snapshots, journals, and deltas are format 2 (`SNAPSHOT_FORMAT` is 2): a lift records its scope. Format 1 files and deltas are read, and a format-1 snapshot is rewritten as format 2 when it is loaded; 0.5 and 0.6 refuse format 2 with `UnsupportedFormat`.
- `import` needs a node id (`NodeIdUnset` otherwise), as `export_delta` did.
- On a node that shares, a lift by an automated actor removes only that node's own ban on the key; another node's ban on it stays.

### Added

- Tests for threats T-1 (a peer that is not a trusted proxy cannot name a client), T-7 (a stream cut by revocation leaks at most the chunk in flight), T-18 (no printable value or event carries digest bytes), and T-20 (unverified datagram sources are never banned). Every test named in the threat table now exists under that name.
- The full T-6 stress run uses 32 threads, as the threat table states (10^8 checkpoints with concurrent revocations; no missed revocation).
- Timing tests for threat T-8 (`tests/timing.rs`, run with `--ignored` in release): admitted latency does not depend on neighbours' bans, and bind latency does not reveal digests near a banned one (Kolmogorov-Smirnov at p < 0.01, with a control that must separate).
- The soak (`tests/soak.rs`, NFR-13): 100,000 connections a second with bans and revocations running; checks for missed revocations and for heap growth after warming.
- A connection closed while requests under it are live reports them revoked (`revoke.applied`, reason `CONNECTION_CLOSED`); a wipe-and-eject event says whether the connection was ejected.
- Tests for every edge case of the plan that lacked one or was partly tested (16, 17, 22, 30, 32, 33, 34, 39, 40, 43, 45 to 48, 59, 67, 69, 71); test comments use the plan's numbering.
- A three-node simulation (`tests/cluster.rs`): partitions, a clock 30 seconds ahead, reordering, and duplication; every node agrees after healing.
- The decoder fuzz targets frame part of their inputs (magic, lengths, CRC), so mutations reach the record decoders behind the checksums.

---

## [0.6.0] - 2026-10-26

Optimisation, measured against compositions of existing crates.

### Changed

- The door: each prefix's keyed hash is computed once per check and shared
  by the ban lookup and the door budgets; the budget step hashes nothing when
  no budget is configured; an empty allow list is skipped. 149 -> 113 ns per
  admission with 1,000,000 bans (pinned).
- Tickets: a connection's latest request is written with a plain store and
  not cleared on release; release reads instead of swapping; door-generated
  connection ids come from the ticket cell; connections hold concurrency
  slots only when there are any. Issue and release 85 -> 45 ns.
- Binds read the clock only when a ban of their kind exists; shared-address
  detection counts with the door's latest second. About 76 -> 24 ns.
- Prefix keys hash over two words.

### Fixed

- Offender memory scanned itself to evict once full, so ban inserts slowed
  down without bound (median 3.5 µs at 1.2 million bans); it now evicts in
  constant time (457 ns). Lift tombstones had the same scan.

### Added

- `docs/PERFORMANCE.md`: the door against the same-job and the lookup-only
  compositions, every PLAN 11 target, the change from 0.5.0, and the method.
- Benches `comparison`, `perf` (pinned table), `storm` (T-12, the slow path,
  `#[track_caller]`), and `gate` with `scripts/gate.py`: a CI job that fails
  on a hot path more than 5% over its instruction-count baseline.

---

## [0.5.0] - 2026-10-23

Feature complete: persistence, sharing across nodes, escalation, offender
memory, shared addresses, lane and tenant budgets, posture, administration.

### Added

- Persistence: `Persistence`, `FilePersistence`, `LoadFailure`,
  `PersistError`, `SNAPSHOT_MAGIC`, `SNAPSHOT_FORMAT`; builder `persistence`,
  `mac_key`, `on_load_failure`, `max_wall_jump`, `strict_wall_jump`;
  `Bouncer::flush`. Bans, lift tombstones, and offender memory survive a
  restart, loaded before the first door check. A snapshot plus a journal,
  CRC32C on every record, an optional keyed BLAKE3 MAC chained across journal
  batches, crash-safe snapshot replacement, and a tolerated torn tail.
- Sharing: `NodeId`, `Delta`, `Sequence`, `ImportReport`, `ImportError`;
  `Bouncer::export_delta`, `export_snapshot`, `import`; builder `node` and
  `max_clock_skew`. Bans, lifts, offender records, and revocations merge in
  any order with hybrid logical clock stamps; a revocation on one node stops
  running requests on the others.
- Escalation (`EscalationPolicy`, builder `escalation`): enough banned
  children of a prefix ban the parent and fold the children, never across an
  allow-list entry, a trusted proxy, or a shared address.
- Offender memory with decay (`DurationPolicy::half_life`): a returning
  offender's next ban is longer, forgotten over time.
- Shared-address detection: an address with many sessions or accounts is
  treated as a NAT; automation bans identities and throttles the address
  (`StrikeOutcome::Throttled`).
- Lane and tenant budgets: `Budgets::lane_rate`, `tenant_rate`,
  `tenant_plan`, `tenant_in_flight`; `Ticket::bind_lane`; `LaneClass`.
  Identity throttles on sessions, accounts, tenants, and fingerprints.
- Posture: `Bouncer::set_posture` and `posture`; builder
  `strict_budget_divisor` and `strict_revokes_unauthenticated`.
- Administration: `Bouncer::explain` (`Explanation`, `OffenderRecord`,
  `BudgetState`, `StrikeState`), `list` (`Filter`, `Page`, `Listing`,
  `BanRecord`), `replace_allow`, `health` (`Health`, `MaintainerState`).
- `metrics` feature: `Bouncer::metrics` and `MetricsSnapshot`, per-shard
  counters; the checkpoint fast path stays one load.
- `Bouncer::datagram` and `DatagramVerdict` for UDP.
- Signals `bouncer.budget.refused`, `bouncer.posture.changed`,
  `bouncer.persist.wall_jump`; reasons `LOCKDOWN` and `BUDGET`; ban expiry,
  eviction, and unresolved proxy hops now report.
- `docs/ARCHITECTURE.md`.
- Tests: persistence (with a kill test), sharing, escalation, administration,
  posture, edge cases; fuzz targets `snapshot_decode`, `journal_replay`,
  `delta_decode`.

### Changed

- `Budgets` is no longer `Copy` (it holds tenant plans).
- Events take their wall time from the bouncer's clock.
- A merged ban keeps the later issue time.
- An automated ban that a wider, longer ban already covers is not stored.

### Dependencies

- `better-bucket` 1.1 (default features off) for tenant token buckets.

---

## [0.4.0] - 2026-10-23

In-flight revocation, wipe, replace, eject, strikes, budgets, and events.

### Added

- `Bouncer::revoke` and `Bouncer::apply` with `Directive`, `Action`,
  `BanKeys`, `Applied`, `Target`, `RevokeMode`, `Revocation`, and the public
  `RevocationEpoch` (injectable with `BouncerBuilder::epoch`). Revoking a
  connection, request, session, account, tenant, source prefix, or
  fingerprint denies every running ticket that carries it at its next
  checkpoint; a check that begins after `revoke` returns cannot miss it.
- `Ticket::before_commit`, `is_cancelled`, `bind_fingerprint`,
  `bind_session`, `bind_account`, `bind_tenant`, `strike`, `into_tag`,
  `deny_and_eject`, `deny_and_eject_with`.
- Tags for transports: `Bouncer::request(tag, id)`, `Bouncer::egress(tag)`
  (the check before every socket write), `Bouncer::release(tag)`.
- `Collected`, the zeroizing response buffer, wiped through crypt-io's
  volatile writes and never reallocated in place; `DenialFormat`,
  `NoFormat`, `FormatError`, `Ejector`, `CloseKind`, `Ejected`,
  `DenialTable`.
- Strikes: `StrikeKind`, `StrikeOutcome`, `StrikeRules`, `Enforcement`,
  `Mode`, `Posture`. Local thresholds observe by default; a decoy touch is
  definitive.
- Door budgets: `Budgets` and `Rate` (rate per client and prefix through
  rate-net's GCRA, concurrency per client and prefix, throttles); trusted
  proxies and budget-exempt sources are not charged.
- Events: `EventSink`, `NoSink`, `Event`, `SignalId`, `Category`,
  `Subject`, `GENERATOR`, and the `signals` catalog; every action reports.
- Maintenance: `Bouncer::maintain`, `MaintenanceReport`, the parked
  maintainer thread (`BouncerBuilder::maintainer`), eject-now sweeps,
  checks on idle tickets (reported as `checkpoint.missing`), and cleanup of
  revocation entries no live ticket needs.
- Builder: `revocation_capacity`, `budgets`, `strikes`, `enforcement`,
  `denials`, `denial_format`, `event_sink`, `ejector`, `epoch`,
  `max_unchecked`, `maintainer`, `revocation_rate_limit`.
- `docs/INTEGRATION.md`: the checkpoint contract and how a transport, a
  pipeline, a protocol adapter, the gates, and the signal bridge wire in.
- Tests: revocation, wipe (with an inspecting allocator), a 10^8-checkpoint
  stress run, loom models L-1, L-4, L-5, L-6, and the `directive_sequence`
  fuzz target.

### Changed

- `Bouncer::new` turns on door budgets by default (20 per second, burst 40,
  and 64 concurrent per client).
- Receipts (`Revocation`, `Applied`, `Lifted`) are no longer `#[must_use]`.
- `docs/API.md`: `LowConfidence` removed (a low-confidence ban is applied as
  a throttle); budgets key IPv6 clients at /64 with a /48 prefix.

### Dependencies

- `rate-net` 2.0 (default features off) and `crypt-io` 1.2 (features
  `zeroize` and `mac-blake3` only).

---

## [0.3.0] - 2026-10-23

The core: keys, ban memory, the door, tickets, and the checkpoint.

### Added

- `Bouncer` with `new`, `builder`, `door`, `door_at`, `ban`, `lift`, `now`,
  and `capacity`; `BouncerBuilder` with ticket, shard, and ban capacities,
  automatic IPv4 and IPv6 lengths, the duration policy, the allow list,
  trusted proxies, a clock, and fixed seeds for tests.
- Keys: `Cidr` with a strict parser (at most 64 bytes, no zone ids, no
  leading zeros in IPv4 octets or the length, the byte position of the first
  error), `normalize` (IPv4-mapped IPv6 to IPv4; NAT64, Teredo, and 6to4 left
  alone), `prefix_of`, `ConnId`, `RequestId`, `AccountKey`, `TenantKey`, and
  the digests `SessionKey` and `FingerprintKey`, which compare in constant
  time and never print.
- Ban memory: bans by address (IPv6 clients at /64), prefix, session,
  account, tenant, fingerprint, and fingerprint within a prefix; timed by
  `DurationPolicy` (growing for repeat offenders, capped, with jitter) or
  permanent for the actors allowed to; never on allow-listed keys or trusted
  proxies; bounded, evicting only expired entries and timed bans from local
  heuristics. A lock-free table for the automatic lengths and identity keys,
  and a compiled multibit trie for administrator prefixes of any length.
- The door: trusted proxy hops, the `AllowList` (immune and budget-exempt
  entries), and ban memory, from the peer address alone. Every refusal is a
  `Refusal` value for logs; the peer sees the same close for every reason.
- Tickets: `Ticket::request`, `checkpoint` (one atomic load while nothing is
  revoked), `bind_client` for the real client behind a trusted proxy (PROXY
  protocol on the connection, forwarded headers per request), `tag`, and
  release on drop. A request whose connection is gone is denied; a request
  under a proxy hop is denied until its client is bound.
- `Verdict`, `Denial`, `DenialCode`, `Reference`, `Actor`, `ActorKind`,
  `Reason`, `Evidence`, `BouncerError`, `ConfigError`.
- Tests: edge cases and threat tests in `tests/door.rs`, property tests,
  a counting-allocator test showing the door, request, checkpoint, and
  `bind_client` paths do not allocate, loom models for the ticket free list
  and the ban table's sequence-locked slots, and a `cidr_parse` fuzz target.
- `benches/door.rs` and `examples/door_p99.rs`: the door with 1,000,000 bans
  and 10,000 administrator prefixes.

### Changed

- `docs/API.md`: `BanRecord.actor` is an `ActorKind`; `ActorKind` added;
  ticket tags are a cell index and a generation.

---

## [0.2.0] - 2026-10-22

The design lock: the full public API, the plan rewritten from the crate's
specification, and the move to the portfolio template. No functional code yet.

### Added

- `docs/API.md`: every public item of the crate with its tier, grade, version,
  cost target, errors, and examples: the door, tickets and checkpoints,
  in-flight revocation, `Collected` and wipe-replace-eject, ban memory and the
  allow list, directives, strikes (observe by default), budgets, events and the
  signal catalog, persistence, sharing across nodes, health, and the net-io
  hooks.

- `dev/PLAN.md`: the door (admission by address, prefix, fingerprint, session,
  and account), in-flight revocation through epoch-gated checkpoints,
  wipe-replace-eject, ban memory with prefix escalation, strikes, threats by
  attacker tier, what it does not cover, architecture, performance targets,
  ecosystem, open decisions, and the decision log.
- `dev/DIRECTIVES.md` and `dev/ROADMAP.md`.
- `deny.toml`, `.gitattributes`, `LICENSE-MIT`, `docs/release/v0.1.0.md`.
- Session revocations from gate-net, and tombstone, decoy, and binding
  signals as strikes (`dev/PLAN.md` section 4).

### Changed

- `dev/PLAN.md` rewritten from the specification: requirements, the
  enterprise and distributed design, threats with tests and costs, the full
  edge-case list, answers to every open decision, and decisions D-009 to
  D-035. Local heuristics now observe by default instead of banning.
- `dev/ROADMAP.md` follows the portfolio series: 0.3 core, 0.4 extended,
  0.5 feature complete, 0.6 optimisation, 0.7 hardening, 0.8 alpha, 0.9 beta.
- README: a Tier 1 quick start; the license list no longer uses dash
  entities.

- Edition 2024, MSRV 1.85, and `Apache-2.0 OR MIT` (was edition 2021, MSRV
  1.75, Apache-2.0 only).
- CI runs Linux, macOS, and Windows on stable and 1.85, plus `cargo audit`
  and `cargo deny`.
- The crate description now states the purpose: a connection gate with
  in-flight revocation, not a rate limiter.
- Planning documents moved into the committed `dev/` folder.

---

## [0.1.0] - 2026-05-12

### Added

- Initial repository scaffold: README, REPS specification stub, CI workflow,
  planning structure.

[Unreleased]: https://github.com/jamesgober/bouncer-io/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/jamesgober/bouncer-io/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/jamesgober/bouncer-io/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/jamesgober/bouncer-io/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/jamesgober/bouncer-io/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/jamesgober/bouncer-io/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jamesgober/bouncer-io/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesgober/bouncer-io/releases/tag/v0.1.0
