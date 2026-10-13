# bouncer-io - Project Plan

> The design, strategy, and decision record for `bouncer-io`. A living document: every design decision, idea, or open question about bouncer-io is written here or in [`ROADMAP.md`](./ROADMAP.md) before it is acted on.
>
> **Read order:** [`../REPS.md`](../REPS.md) &rarr; [`DIRECTIVES.md`](./DIRECTIVES.md) &rarr; **this file** &rarr; [`ROADMAP.md`](./ROADMAP.md).
>
> **Status:** scaffold, `0.1.0`. Design lock is `0.2.0`.

---

## Contents

1. [Purpose](#1-purpose)
2. [What bouncer-io is not](#2-what-bouncer-io-is-not)
3. [Where it sits](#3-where-it-sits)
4. [The ticket](#4-the-ticket)
5. [The door: admission](#5-the-door-admission)
6. [Inside: in-flight revocation](#6-inside-in-flight-revocation)
7. [Wipe, replace, eject](#7-wipe-replace-eject)
8. [Ban memory](#8-ban-memory)
9. [Strikes and local heuristics](#9-strikes-and-local-heuristics)
10. [Threats by attacker tier](#10-threats-by-attacker-tier)
11. [What it does not cover](#11-what-it-does-not-cover)
12. [Architecture](#12-architecture)
13. [Performance targets](#13-performance-targets)
14. [Ecosystem and dependencies](#14-ecosystem-and-dependencies)
15. [Testing](#15-testing)
16. [Open decisions](#16-open-decisions)
17. [Ideas parking lot](#17-ideas-parking-lot)
18. [Decision log](#18-decision-log)

---

## 1. Purpose

bouncer-io is the door guy. Every connection that comes in goes past it, and everything that goes back out goes past it again.

- **At the door** it knows who is banned and refuses them before a single byte of their traffic is read.
- **Inside** it does not care where in the pipeline a request has got to. If the request, its session, its account, or its source is flagged while the request is still being handled, the next checkpoint it crosses is where bouncer steps in.
- **Stepping in** means: everything the request has collected is wiped, the response is replaced with a denial carrying an error code and message, and the connection is thrown out, right then.
- **Afterwards** it remembers, so the next attempt from the same source, session, account, or client dies at the door.

---

## 2. What bouncer-io is not

- **Not a rate limiter with a different name.** Rate and concurrency limits are one of its tools, not its purpose. An earlier draft drifted that way; this plan corrects it.
- **Not the detection brain.** Deep correlation and scoring over time live in `sentinel-sec`. bouncer has fast local heuristics of its own (section 9) and enforces what sentinel decides.
- **Not a protocol parser or validator.** It is protocol-free: it decides on addresses, keys, counts, rates, and revocations. Protocol adapters supply the bytes of a denial; `customs-sec` judges content.
- **Not authentication.** It enforces revocations that `gate-net` issues (logout, password change, admin action) but does not check credentials.

---

## 3. Where it sits

```
accept ─▶ [door] ─▶ PROXY ─▶ [door: real peer] ─▶ TLS ─▶ [fingerprint] ─▶ parse ─▶ customs ─▶ gate-net
   ─▶ [identity] ─▶ gate-sec ─▶ customs ─▶ handler stages ─▶ [checkpoint between every stage]
   ─▶ [before commit] ─▶ customs export ─▶ [egress, enforced by net-io] ─▶ write
```

| Checkpoint | Called by | Knows | Cost when nothing is revoked |
|---|---|---|---|
| door | net-io admission hook, right after accept | peer address, prefix, connection counts and rates | one lookup per key class |
| door, real peer | net-io, after a trusted PROXY header | the client's real address | same |
| fingerprint | the TLS adapter, after ClientHello | client fingerprint, SNI | one lookup |
| identity | the pipeline, after gate-net | session and account | one lookup |
| between stages | the pipeline (web layer, service-kernel workers) | the ticket's epoch | one atomic load |
| before commit | handlers, immediately before a database commit | the ticket's epoch | one atomic load |
| egress | net-io egress hook, before every socket write | the ticket's epoch | one atomic load |

The egress checkpoint is enforced by net-io itself, so a pipeline that forgets every other checkpoint still cannot send a byte for a revoked ticket.

---

## 4. The ticket

Every connection and every request carries a ticket. It is created at accept and grows as the request learns more about who is on the other end.

| Field | Set at | Source |
|---|---|---|
| `ConnectionId` | accept | net-io |
| peer address and prefix keys | accept, updated after PROXY | net-io |
| client fingerprint | TLS handshake | TLS adapter |
| `RequestId` | request start | protocol adapter |
| session id | after authentication | gate-net |
| account id | after authentication | gate-net |
| epoch seen | each checkpoint | bouncer |
| cancel flag | creation | bouncer |

A revocation can target any of these keys. Revoking a session or an account reaches every in-flight request that carries it, on every connection.

---

## 5. The door: admission

At accept, before any byte is read:

1. Normalize the address (IPv4-mapped IPv6 becomes IPv4).
2. Check the ban memory for the exact address and every configured prefix of it.
3. Check the allowlist (our own infrastructure can never be refused by automation).
4. Check per-prefix concurrency and accept-rate budgets.
5. Allow, or refuse: the socket is closed abortively and nothing is read.

The same check runs again when a trusted PROXY header reveals the real client, and again at the fingerprint and identity checkpoints with the keys that become known there.

---

## 6. Inside: in-flight revocation

This is the feature that sets bouncer apart.

### 6.1 Revocation sets and the epoch

- Revocation sets are keyed by connection, request, session, account, fingerprint, and address prefix.
- A global `AtomicU64` epoch is bumped on every revocation.
- Each ticket remembers the epoch it last checked. A checkpoint is one atomic load and a compare. Only when the epoch has moved does it consult the sets, and then it records the new epoch.
- Nothing is slowed down until something is actually revoked; when something is, every in-flight request re-checks once at its next checkpoint.

### 6.2 Checkpoints

`checkpoint(&mut ticket) -> Verdict` is the whole API a pipeline needs. The web layer calls it between middleware stages and between handler steps; service-kernel workers call it between units of work. A stage returning to the pipeline is exactly where bouncer intercepts.

### 6.3 Cancellation

The ticket's cancel flag is set on revocation. Long-running handlers (large queries, report generation, uploads) poll it so a revoked request stops doing work, not just stops being answered.

### 6.4 Before commit

Handlers that write call `checkpoint` immediately before committing a transaction. A request revoked mid-flight then leaves no side effects. Most gate designs stop at refusing the response and miss this.

---

## 7. Wipe, replace, eject

When a checkpoint finds the ticket revoked:

1. **Cancel:** set the cancel flag.
2. **Wipe:** the request's collected response and scratch data are overwritten with zeroes, not just dropped, so nothing the request gathered survives in memory. To make this possible, the pipeline assembles responses in bouncer's `Collected` buffer type, which zeroizes on wipe and on drop.
3. **Replace:** the protocol adapter's `Denial` implementation supplies the bytes: HTTP `403` (or `401` / `429`, configurable) with a fixed error code and message, a database error frame, WebSocket close code `1008`. bouncer provides the code and message; the adapter only formats them.
4. **Eject:** the connection is closed abortively through net-io's kill handle (`SO_LINGER` 0), which frees its resources at once and wakes any blocked read or write.
5. **Remember:** the configured keys go into ban memory, so the next attempt is refused at the door.
6. **Report:** the action, its reason, and its evidence go out as an event (for `audit-trail` and `sentinel-sec`).

**The denial is silent.** It carries a generic code, a generic message, and an opaque reference id an administrator can look up. It is identical to an ordinary refusal and never says why. Nothing in it tells the subject they were flagged.

---

## 8. Ban memory

| Aspect | Design |
|---|---|
| keys | exact address; IPv4 /24; IPv6 /64, /56, /48; session; account; fingerprint |
| why prefixes | an IPv6 host usually owns a whole /64 and can rotate through it freely; addresses inside one IPv4 /24 often belong to one operator |
| escalation | repeat offences inside a prefix widen the ban to the next prefix, within configured limits |
| duration | time-boxed by default, growing with repeat offences; permanent only by an administrator or a definitive signal (a decoy touch) |
| allowlist | our own infrastructure and configured partners; automation can never ban them |
| bounds | a memory budget; permanent and allowlist entries are never evicted; the oldest short bans are evicted first and the eviction is reported |
| persistence | bans survive a restart (snapshot to disk, loaded before the first accept) |
| sharing | import and export of ban snapshots and deltas so nodes share what they learn; each node enforces locally, so the door keeps working if other nodes are unreachable |
| reversal | every entry records its reason and evidence; an administrator can lift it, and the lift is audited |

---

## 9. Strikes and local heuristics

bouncer reacts on its own to things it can see without the detection layer, so a scanner is stopped in milliseconds, not minutes.

| Signal | Reported by |
|---|---|
| connection rate and concurrency per prefix | bouncer (door) |
| handshake failures, PROXY violations, TLS alerts | net-io, TLS adapter |
| malformed protocol traffic | protocol engines (http-net, ws-net, fcgi-net) |
| contract violations | customs-sec |
| slow-peer kills (slowloris, slow read) | net-io |
| failed logins | gate-net |
| authorization denials | gate-sec |

Each signal is a strike against the ticket's keys. Thresholds trigger short automatic bans. Every strike is also forwarded to `sentinel-sec`, which scores over the long term.

---

## 10. Threats by attacker tier

| Tier | What bouncer does |
|---|---|
| automated scanners, script kiddies | strikes on malformed traffic and probing; prefix bans; decoy touches (from sentinel) are definitive |
| skilled individuals | prefix escalation defeats address rotation; fingerprint and account keys follow them across addresses; in-flight revocation cuts an attack off mid-session, before commit |
| organized groups (botnets, residential proxies) | fingerprint and behaviour keys instead of addresses; session and account revocation; global caps protect capacity; kernel-level drop for known-bad prefixes (parking lot) |
| stolen sessions, insiders | session and account revocation reaches requests already in flight, before commit and before egress |

---

## 11. What it does not cover

Stated plainly so nobody mistakes it for more than it is:

- **Bytes already sent cannot be recalled.** Responses that must be all-or-nothing are buffered, not streamed, so the egress checkpoint sees them whole.
- **Floods bigger than the network link** need upstream help (provider, CDN). bouncer protects the server's resources, not the pipe.
- **UDP source addresses are spoofable.** bouncer never bans or scores a UDP source until it has proven it can receive traffic.
- **Spoofed address framing:** an attacker could trigger bans on someone else's address only through a PROXY header or forwarded header, which net-io accepts only from trusted proxies.
- **Detection quality** depends on the signals fed in. Long-term correlation is sentinel-sec's job.

---

## 12. Architecture

### 12.1 Module map (planned)

```
src/
  lib.rs        crate docs, Tier-1 entry points
  ticket.rs     Ticket, keys, cancel flag
  keys.rs       address normalization, prefix keys, fingerprint and identity keys
  door.rs       admission: implements net-io's Admission hook
  revoke.rs     revocation sets, the epoch, checkpoint()
  egress.rs     implements net-io's Egress hook
  collected.rs  Collected: zeroizing response buffer
  denial.rs     Denial trait (protocol adapters implement), codes and messages
  bans.rs       ban memory, escalation, expiry, budget, persistence
  strikes.rs    strike counting and thresholds
  budgets.rs    per-prefix concurrency and rate budgets
  share.rs      snapshot and delta import/export
  events.rs     event types for audit-trail and sentinel-sec
  error.rs      BouncerError (#[non_exhaustive])
```

### 12.2 Concurrency

- The admission and checkpoint paths are lock-free for readers. Ban memory and revocation sets are read-mostly: readers take a snapshot pointer; writers build a new version and swap it in, so a reader never waits on a writer.
- Per-prefix counters are sharded to avoid a single hot cache line.

### 12.3 Hooks it implements and exposes

| Direction | Item |
|---|---|
| implements (net-io) | `Admission`, `Egress` |
| uses (net-io) | `KillHandle`, `ConnInfo`, `ConnectionId`, address and prefix types |
| exposes | `checkpoint`, `revoke`, `ban`, `lift`, `Collected`, `Denial`, strike intake, event sink |

---

## 13. Performance targets

Targets, to be confirmed by benchmarks at design lock:

| Path | Target |
|---|---|
| checkpoint, nothing revoked | one atomic load and compare; under 2 ns |
| door check with 1,000,000 bans | under 100 ns p99 |
| revocation visible to every in-flight request | at their next checkpoint; no polling thread |
| memory per ban entry | under 64 bytes |

---

## 14. Ecosystem and dependencies

| Crate | Relationship |
|---|---|
| `net-io` | dependency: hook traits, `ConnInfo`, addresses, kill handle |
| `clock-lib` | dependency: monotonic time, mockable for expiry tests |
| `sentinel-sec` | peer: receives strikes, sends decisions (ban, revoke, lift) |
| `gate-net` | peer: issues session and account revocations |
| `customs-sec`, protocol engines | report strikes |
| `audit-trail` | receives events through the event sink (no direct dependency) |
| `rate-net`, `better-bucket` | **not used for now**: they pull in third-party crates (tokio, ahash, governor). bouncer keeps its own small budgets until those crates are dependency-clean (see O-1) |

Runtime dependencies are first-party only.

---

## 15. Testing

- Unit and doc tests for every public item.
- Revocation tests: a request revoked at each checkpoint (door, between stages, before commit, egress) never sends a byte of its original response, never commits, and gets the configured denial.
- Wipe tests: after a revoke, the `Collected` buffer's memory holds only zeroes.
- Concurrency: loom models for the epoch and snapshot swap; a stress test with millions of checkpoints and concurrent revokes.
- Ban memory: escalation, expiry, budget eviction order, persistence round trip, allowlist immunity.
- Property tests for address normalization and prefix keys.
- Benchmarks for every target in section 13.

---

## 16. Open decisions

| Id | Question | Recommendation |
|---|---|---|
| O-1 | Clean `rate-net` and `better-bucket` of third-party dependencies so bouncer can use them, or keep bouncer's own budgets? | clean them; one limiter implementation in the portfolio |
| O-2 | Default denial status for revoked requests: 403, or 404 to hide that the resource exists? | 403 by default, configurable per route |
| O-3 | Publish `0.1.0` to crates.io to claim the name? | yes |

---

## 17. Ideas parking lot

- **Kernel-level drop (Linux eBPF/XDP):** export banned prefixes to an XDP filter so their packets are dropped before they cost a syscall.
- **Tarpit mode:** instead of closing, hold a flagged scanner's connection open and feed it nothing, slowly, to waste its time (bounded so it cannot exhaust our own resources).
- **Proof-of-work challenge:** a cheap-to-verify, costly-to-solve challenge for suspicious clients before admission, as an alternative to third-party captchas.
- **ASN-level keys** once an address-to-network data source is chosen.

---

## 18. Decision log

| Id | Date | Decision | Reason |
|---|---|---|---|
| D-001 | 2026-10-13 | bouncer-io is the door plus in-flight revocation with wipe-and-eject, not a rate limiter | James's original intent; an earlier draft had drifted |
| D-002 | 2026-10-13 | Epoch-gated checkpoints: one atomic load when nothing is revoked | revocation must reach every in-flight request without slowing normal traffic |
| D-003 | 2026-10-13 | Egress enforcement lives in net-io's write path | no pipeline can skip the last checkpoint |
| D-004 | 2026-10-13 | A checkpoint before commit is part of the contract | a revoked request must not leave side effects |
| D-005 | 2026-10-13 | Responses are assembled in a zeroizing `Collected` buffer | wiping means overwriting, not dropping |
| D-006 | 2026-10-13 | Denials are generic and silent; the reason goes only to the audit trail | subjects are never told they were flagged |
| D-007 | 2026-10-13 | Bans by prefix with escalation (IPv4 /24, IPv6 /64 to /48) | address rotation inside a prefix is free for attackers |
| D-008 | 2026-10-13 | Template aligned with net-io and http-net (edition 2024, MSRV 1.85, `Apache-2.0 OR MIT`, `dev/` committed) | portfolio consistency; the May scaffold was never published |
