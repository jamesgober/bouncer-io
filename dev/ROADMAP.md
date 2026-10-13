# bouncer-io - Roadmap

> Path from scaffold to a stable 1.0. Hard parts are front-loaded; each phase has hard exit criteria.
> Design and decisions: [`PLAN.md`](./PLAN.md).
>
> **Anti-deferral rule:** no listed hard task moves to a later phase unless this file records the move and the reason.

## v0.1.0 - Scaffold (DONE, 2026-10-13)
- [x] Manifest, README, CHANGELOG, REPS, dual license, CI, deny, clippy, rustfmt, DIRECTIVES, ROADMAP, PLAN.

## v0.2.0 - Design lock
Exit: every public type, trait, and signature written in `docs/API.md` and approved; net-io's hook traits agreed between the two crates.
- [ ] Ticket, keys, `checkpoint`, `revoke`, `ban`, `lift`, `Collected`, `Denial`, strike intake, events.
- [ ] Epoch and snapshot-swap concurrency design, with the loom model plan.
- [ ] Ban memory layout and the per-entry memory budget.
- [ ] Open decisions O-1 to O-3 answered.

## v0.3.0 - The door
Exit: on net-io 0.3.0, a banned address, prefix, or fingerprint is refused before a byte is read, at the target cost with 1,000,000 bans.
- [ ] Address normalization and prefix keys (property tests).
- [ ] Ban memory: insert, expiry, escalation, budget and eviction order, allowlist immunity.
- [ ] Admission hook implementation; per-prefix concurrency and accept-rate budgets.
- [ ] Strikes and thresholds; events.
- [ ] Benchmarks: door check at scale.

## v0.4.0 - Inside: revocation, wipe, eject
Exit: a request revoked at any checkpoint (between stages, before commit, egress) never sends its original response, never commits, receives the denial, and is ejected; loom-verified.
- [ ] Revocation sets and the epoch; `checkpoint`.
- [ ] Cancel flag.
- [ ] `Collected` zeroizing buffer; wipe tests that read the memory back.
- [ ] `Denial` trait and the generic codes; egress hook implementation.
- [ ] Kill through net-io's kill handle; ban memory updated on eject.
- [ ] Stress: millions of checkpoints with concurrent revokes.

## v0.5.0 - Memory and sharing
Exit: bans survive a restart and propagate between two nodes; each node keeps enforcing when the other is unreachable.
- [ ] Persistence (snapshot loaded before the first accept).
- [ ] Snapshot and delta import/export.
- [ ] Administrator review and lift, audited.
- [ ] sentinel-sec decision intake.

## v0.9.0 - Hardening
- [ ] Fuzzing (ban snapshots, key parsing); adversarial review with findings fixed test-first; soak test.

## v1.0.0 - Stable
- [ ] Frozen after the web stack and one non-HTTP service have used it end to end.
