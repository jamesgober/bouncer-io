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

[Unreleased]: https://github.com/jamesgober/bouncer-io/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/jamesgober/bouncer-io/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jamesgober/bouncer-io/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesgober/bouncer-io/releases/tag/v0.1.0
