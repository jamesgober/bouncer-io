# bouncer-io - Engineering Directives

> Engineering standards and the definition of done for this project. Read alongside `REPS.md` (root, authoritative), [`PLAN.md`](./PLAN.md) (design and decisions), and [`ROADMAP.md`](./ROADMAP.md) (current phase). If anything here conflicts with `REPS.md`, `REPS.md` wins, except where `PLAN.md` records an approved exception.

---

## 0. Philosophy

This library is built and maintained to a production standard and treated as a flagship piece of work. Plan the full path, then build one verified step at a time. "Good enough" is treated as a defect. It is a member of the owner's `-io` domain and part of the service security stack (net-io, bouncer-io, customs-sec, gate-net, gate-sec, shield-sec, sentinel-sec, sandbox-sec). A security component that cannot name the attack it stops, and prove it with a test, does not ship.

---

## 1. What this is

bouncer-io is the connection gate: admission at the door (ban memory by address, prefix, fingerprint, session, and account; per-prefix budgets), in-flight revocation through epoch-gated checkpoints, and wipe-replace-eject when a revoked request crosses one. It implements net-io's admission and egress hooks and enforces decisions from gate-net and sentinel-sec. It is not a rate limiter, a parser, or the detection layer. See `PLAN.md` sections 1 and 2.

---

## 2. Engineering law (non-negotiable)

- **Ours, not rented.** No third-party runtime dependency, except audited cryptographic primitives reached through `crypt-io` (features `zeroize` and `mac-blake3` only). First-party crates are wired when first used, at published versions (no `path` dependencies across repositories); `rate-net` and `better-bucket` only with default features off, because their defaults pull third-party crates. No async runtime. Dev-only test tooling (`criterion`, `proptest`, `loom`) is allowed.
- **Protocol-free.** Nothing in this crate knows the wire format of the traffic it protects; adapters at the top translate.
- **Unsafe.** `#![forbid(unsafe_code)]`, no exception. The guaranteed wipe of `Collected` goes through crypt-io's volatile writes. Integration test crates may use `unsafe` for an inspecting allocator.
- **Hostile-input hardening.** Every input may be adversarial: explicit budgets for bytes, time, and counts, checked before the resource is committed; no reachable panics; no quadratic paths.
- **Fail closed.** When a check cannot run, the answer is no.
- **Secrets.** Compared in constant time, zeroized after use, never in logs, errors, or `Debug` output.
- **Performance.** Peak is the baseline: allocation-free hot paths, lock-free reads where correctness can be proven, no "faster" claim without `criterion` numbers at realistic scale.
- **Cross-platform.** Linux, macOS, and Windows are first-class, verified by CI on stable and MSRV 1.85. Platform differences are documented per feature.
- **Error handling.** Every fallible path returns `Result`; errors are `#[non_exhaustive]` and say what to do.
- **Simple API.** Tier 1 calls take one or two arguments and read without the docs; checked at the design lock and at the 1.0 audit.
- **Distributed by default.** Bans and revocations are state: kept behind traits, shared as mergeable deltas, enforced locally during a partition. Local heuristics observe by default; explicit commands always act.
- **Never isolated.** Every action is an event for the security signal bridge; decisions arrive through `apply` from any thread.
- **Production-ready.** `#![deny(missing_docs)]`; no `unwrap`/`expect`/`todo!`/`dbg!`/printing in library code; every public item has rustdoc with a runnable example; every claim in the docs maps to a test.

---

## 3. Definition of done

1. Compiles clean on Linux/macOS/Windows, stable and MSRV 1.85.
2. `fmt`, `clippy -D warnings` (all targets, all/no-default features), `test --all-features`, `cargo doc -D warnings` clean.
3. `cargo audit` + `cargo deny check` pass.
4. No `unwrap`/`expect`/`todo!`/`dbg!` in shipping code.
5. A Tier-1 API exists and headlines the docs.
6. Property tests cover every section-4 invariant; a fuzz target exists for every parser or decoder; every threat listed in `PLAN.md` has an attack test that must fail.
7. Hot-path changes carry benchmarks; no regression over 5%.
8. `README.md`, `docs/API.md`, and `CHANGELOG.md` updated; the matching `docs/release/vX.Y.Z.md` written before the tag.
9. `PLAN.md` decision log updated for every design decision made during the work.
10. v1.0.0 only after the web stack and one non-HTTP service has used the API end to end, and after an adversarial security review with every finding fixed test-first.

---

## 4. Project-specific invariants

- A refused connection has no byte read from it.
- A revoked ticket never has a byte of its original response written, and never passes a before-commit checkpoint.
- After a revoke, the request's `Collected` buffer holds only zeroes.
- A checkpoint with nothing revoked costs one atomic load and compare.
- Readers of ban memory and revocation sets never wait on writers.
- Allowlisted keys and trusted proxies can never be banned, struck, or revoked by automation.
- A request under a trusted proxy hop is denied until its real client is bound.
- Memory never grows past the capacities fixed at build.
- Denials are generic: nothing in a denial reveals why it happened.

---

## 5. Writing style

- Plain, specific, human prose in every shipping file. No marketing voice.
- Banned in shipping files: "comprehensive", "robust", "seamless", "leverage", and the em-dash character (U+2014) in prose.
- Commits: imperative present tense, descriptive subject line.
