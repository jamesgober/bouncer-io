# bouncer-io - Project Plan

> The design, strategy, and decision record for `bouncer-io`. A living document: every design decision, idea, or open question about bouncer-io is written here or in [`ROADMAP.md`](./ROADMAP.md) before it is acted on. The public API is locked in [`../docs/API.md`](../docs/API.md).
>
> **Read order:** [`../REPS.md`](../REPS.md) &rarr; [`DIRECTIVES.md`](./DIRECTIVES.md) &rarr; **this file** &rarr; [`ROADMAP.md`](./ROADMAP.md) &rarr; [`../docs/API.md`](../docs/API.md).
>
> **Status:** `0.6.0` optimisation (door -24%, ticket -47%, bind -70%, ban insert bounded) on the `0.5.0` feature set: persistence, sharing across nodes, escalation, offender memory, shared-address detection, lane and tenant budgets, posture, administration, metrics, and datagrams are built on the 0.4 crate. Design lock was `0.2.0`. Rewritten on 2026-10-22 from the crate's full specification; where the 2026-10-13 plan differed, the specification won and the change is in the decision log (D-009 onward).

---

## Contents

1. [Purpose](#1-purpose)
2. [What bouncer-io is not](#2-what-bouncer-io-is-not)
3. [Where it sits](#3-where-it-sits)
4. [Scope](#4-scope)
5. [Requirements](#5-requirements)
6. [Standards and adaptations](#6-standards-and-adaptations)
7. [Design](#7-design)
8. [Threats, defences, tests, costs](#8-threats-defences-tests-costs)
9. [What it does not cover](#9-what-it-does-not-cover)
10. [Parity](#10-parity)
11. [Performance](#11-performance)
12. [Testing](#12-testing)
13. [Ecosystem and dependencies](#13-ecosystem-and-dependencies)
14. [New defence ideas](#14-new-defence-ideas)
15. [Open decisions](#15-open-decisions)
16. [Ideas parking lot](#16-ideas-parking-lot)
17. [Decision log](#17-decision-log)

---

## 1. Purpose

bouncer-io is the door guy. Every connection that comes in goes past it, and everything that goes back out goes past it again.

- **At the door** it knows who is banned and refuses them before a single byte of their traffic is read.
- **Inside** it does not care where in the pipeline a request has got to. If the request, its session, its account, its tenant, its fingerprint, or its source is flagged while the request is still being handled, the next checkpoint it crosses is where bouncer steps in.
- **Stepping in** means: everything the request has collected is wiped, the response is replaced with a denial carrying a generic code and message, and the connection is thrown out, right then.
- **Afterwards** it remembers, so the next attempt from the same source, session, account, or client dies at the door. Every action is reported as a security event.

It is **consulted, not flowed through**: every connection and request is registered as a ticket, the pipeline calls bouncer at checkpoints (one atomic load while nothing is revoked), and the transport calls it before every write.

---

## 2. What bouncer-io is not

| It is not | Why | Where that job lives |
|---|---|---|
| a rate limiter | rate and concurrency budgets are one tool it uses at the door and per tenant; its purpose is admission and revocation (D-001) | `rate-net`, `better-bucket` provide the rate math (section 7.9) |
| the detection brain | long-term correlation, scoring, decoys | `sentinel-sec` and the security signals module |
| the policy engine | thresholds that turn scores into actions belong to the project | the security signals policy; bouncer acts on its directives |
| authentication | it enforces revocations the gates issue (logout, password change, ban) but never checks a credential | `gate-net` |
| a protocol parser | it never reads HTTP, WebSocket, or a database wire format | protocol engines; adapters format denials |
| overload admission | "can we take more work" is the gateway's question; bouncer asks "is this source behaving" | the gateway's admission |
| a kernel firewall | it runs in the process; kernel drop is an export idea | parking lot |
| a WAF | content inspection | `customs-sec` |

Any change that makes rate limiting the centre of this crate is a defect.

---

## 3. Where it sits

```
 client
   |
   v
 net-io accept --[B1 door: peer address]--> PROXY header --[B1' real client]--> TLS
   --[B2 fingerprint]--> parser --> request: REQUEST ticket
   --> inspection --[B4]--> AUTHENTICATE --[B3 identity: session, account, tenant]-->
   --> router --[B4]--> AUTHORIZE --[B4]--> handler stages --[B4 between every stage]-->
   --[B5 before commit]--> database commit
   --> response --[B6a pipeline egress: wipe/replace]--> encode
   --[B6b transport egress, before every socket write: mandatory]--> write
```

| Checkpoint | Called by | Keys it adds or checks | Cost when nothing is revoked |
|---|---|---|---|
| B1 door | net-io `Admission` hook right after accept | peer address, prefixes, connection budgets | ban lookups and budget check, under 100 ns p99 with 1,000,000 bans [est.] |
| B1' real client | net-io after a trusted PROXY header; the protocol adapter after a trusted forwarded header | real client address and prefixes | same |
| B2 fingerprint | TLS adapter after ClientHello | fingerprint digest | one hash probe |
| B3 identity | the pipeline right after authentication | session, account, tenant | up to three probes |
| B4 between stages | the pipeline, routers, handlers, workers | ticket epoch | one atomic load |
| B5 before commit | handlers immediately before a commit | ticket epoch, sequentially consistent | one atomic load |
| B6a pipeline egress | the response pipeline before encode | ticket epoch; on deny wipes `Collected` | one atomic load |
| B6b transport egress | net-io before every socket write, per chunk when streaming | connection or response ticket | one atomic load with the ticket in hand |

B6b is enforced by net-io itself, so a pipeline that forgets every other checkpoint still cannot send a byte for a revoked connection (D-003).

**Bouncer and admission are different questions.** `accept -> bouncer door (abuse: banned? over its budget?) -> admission (overload: room for this lane?)`. bouncer never refuses a well-behaved source because the server is busy. The one exception is the ticket registry: when it is full bouncer cannot track the connection and refuses (fail closed), reported as `RegistryFull`, never as a ban.

**Who uses it:** serve-net (fixed pipeline slots with a checkpoint between every pair), a private gateway, net-io (through its own hook traits; it never depends on bouncer), gate-net (revocations on logout, logout everywhere, password change, standing change), the security signals policy and sentinel-sec (throttle, ban, revoke directives), the back-channel (inbound "ban this address", "revoke this session"), a database's internal network layer (the second consumer, and the reason this is its own crate), and audit and metrics through sinks.

**It is never isolated.** A security component that cannot talk to the rest of the system is only a detour for a persistent attacker. bouncer joins the security signal bridge in both directions: every action goes out through the `EventSink`; decisions come back through `apply` from any thread; the revocation epoch can be the security core's own shared word; and bans and revocations travel between processes and nodes as mergeable deltas (section 7.13). Speed comes from where state lives (atomics read at checkpoints), never from isolation.

---

## 4. Scope

### 4.1 In scope

| Area | Contents |
|---|---|
| keys | normalization (IPv4-mapped IPv6 to IPv4), `Cidr`, prefix keys per family, session, account, tenant, fingerprint, connection and request ids |
| door | address-only check at accept, recheck after PROXY or forwarded headers, fingerprint and identity checks, UDP per-datagram checks |
| ban memory | exact and prefix bans for IPv4 and IPv6, identity bans, compound fingerprint-in-prefix keys, timed bans with growing durations, permanent bans by administrator or definitive signal, prefix escalation, offender memory with decay, bounded memory with a documented eviction order |
| allow list | immune and budget-exempt entries, trusted-proxy protection, compiled and swapped whole |
| tickets | registry with a fixed capacity, connection and request tickets, key binding, cancel state, generations against reuse, tags for transports |
| revocation | targets: connection, request, session, account, tenant, source prefix, fingerprint; global epoch; revocation tables with quiescence cleanup; eject-now sweeps; idle-ticket checks |
| wipe, replace, eject | `Collected` zeroizing buffer, `Denial`, `DenialFormat` for adapters, `Ejector` for the kill |
| budgets (a tool) | per-source accept rate and concurrency (address, prefix, global), per-tenant rate and in-flight, per-lane rate, throttle directives |
| strikes | intake from every layer, local thresholds (observe by default), forwarding to the bridge |
| directives | apply decisions from policy, sentinel, gates, administrators, other nodes |
| administration | list, add, lift, explain, with actor and reason recorded |
| events, metrics, health | an event for every action with signal ids; counters compiled out when unused; health and capacity reports |
| persistence | crash-safe snapshot plus journal behind a `Persistence` trait, loaded before the first accept |
| sharing | snapshot and delta export and import with mergeable records, including revocations; transport is the caller's |
| posture | normal and strict, switched by the caller |

### 4.2 Out of scope

| Item | Lives in |
|---|---|
| sockets, the kill handle, PROXY parsing, the trusted-proxy list's use at accept | `net-io` |
| reading `X-Forwarded-For` / `Forwarded` | the protocol adapter, with the same trusted list |
| TLS and fingerprint computation | `tls-net` (bouncer receives a digest) |
| long-term scoring, risk decay, decoys | `sentinel-sec`, the security signals module |
| policy thresholds and per-category switches for directives | the security signals policy |
| session store, credential checks | `gate-net` |
| overload admission, lanes | the gateway |
| the urgent alert line | the platform kernel; it calls `set_posture` |
| audit storage | `audit-trail` through the event sink |
| cluster transport and membership | the node core, a replicated log, or the back-channel |
| kernel-level drop | a P3 export from bouncer; the loader lives elsewhere |
| challenge pages and proof-of-work UI | the protocol adapter; bouncer only decides "challenge" (after 1.0) |

---

## 5. Requirements

### 5.1 Functional

| Id | Requirement | Grade |
|---|---|---|
| FR-1 | The door decides from the peer address alone, before any byte is read. | P0 |
| FR-2 | IPv4-mapped IPv6 is normalized to IPv4 before every lookup and key derivation. | P0 |
| FR-3 | Bans can target an exact address, any IPv4 prefix /0 to /32 (administrator) and the automatic lengths (default /32, /24), any IPv6 prefix /0 to /128 (administrator) and the automatic lengths (default /64, /56, /48). | P0 |
| FR-4 | Automatic IPv6 bans and budgets are keyed at /64 by default, never /128. | P0 |
| FR-5 | Bans are timed by default; durations grow for repeat offenders with a cap and random jitter; permanent bans only from an administrator, the application, or a definitive directive. | P0 |
| FR-6 | Allow-list entries can never be banned, throttled, or revoked by automation; an administrator ban of one is refused with `AllowListed`. | P0 |
| FR-7 | A trusted proxy is never a ban, strike, or budget target; strikes and bans for proxied traffic go to the real client. | P0 |
| FR-8 | The door re-runs for the real client after a trusted PROXY or forwarded header; the provenance is recorded on the ticket. | P0 |
| FR-9 | Every admitted connection gets a connection ticket; every request gets a request ticket naming its connection as parent. | P0 |
| FR-10 | A ticket binds, once each: client address (only from a trusted provenance), fingerprint, session, account, tenant, lane. Binding checks the new key and returns a verdict. | P0 |
| FR-11 | Revocation targets: connection, request, session, account, tenant, source prefix, fingerprint. Revoking a request ejects its connection unless the directive says `keep_connection`. | P0 |
| FR-12 | A checkpoint on a ticket whose keys are not revoked costs one atomic load and one compare. | P0 |
| FR-13 | A checkpoint that begins after `revoke` has returned on any thread observes the revocation (ordering in 7.5). | P0 |
| FR-14 | On a revoked verdict the caller can wipe `Collected` (whole capacity), obtain the denial, have it formatted, and eject; `deny_and_eject` does all of it. | P0 |
| FR-15 | The before-commit checkpoint fails closed: a stale or unknown ticket is denied. | P0 |
| FR-16 | Denials are generic: a code from a fixed set, a message from a table fixed at build, an opaque reference. | P0 |
| FR-17 | The transport egress check denies every write on a revoked connection or response and requests an abortive close. | P0 |
| FR-18 | A revocation directive can carry a ban; those keys enter ban memory. | P0 |
| FR-19 | Every action produces an event with actor, reason, evidence, and signal id; refusal events under flood are sampled with exact counts. | P0 |
| FR-20 | Local heuristics default to observe: they report "would ban" and act only when enforcement is switched on per category. Explicit commands always act. | P0 |
| FR-21 | Prefix escalation within limits, never across allow-list entries, trusted proxies, or shared addresses. | P1 |
| FR-22 | Offender memory with exponential decay drives durations and escalation. | P1 |
| FR-23 | Budgets: door accept rate and concurrency (address, prefix, global); tenant rate and in-flight; lane rate; throttle directives. | P1 |
| FR-24 | Admin API: list with filter and paging, add, lift, explain. | P1 |
| FR-25 | Persistence: bans and offender memory survive a restart, are loaded before the first accept, corrupt data is detected and reported. | P1 |
| FR-26 | Sharing: snapshot and delta export and import of bans and revocations; deterministic merge; each node enforces locally when others are unreachable. | P2 |
| FR-27 | Posture: strict tightens budgets and switches the configured observe categories to enforce. | P2 |
| FR-28 | Shared-address detection: an address with many distinct sessions is marked shared so automation prefers identity keys and throttling over address bans. | P2 |
| FR-29 | UDP per-datagram door check; an unverified UDP source is never banned or struck. | P2 |
| FR-30 | Eject-now: a revocation can sweep and close matching connections that are not crossing checkpoints. | P1 |
| FR-31 | Health and capacity reports: table loads, registry use, detached tickets, journal backlog, maintainer state, reserved bytes. | P1 |
| FR-32 | Challenge verdict and a pluggable proof-of-work verifier. | P3 |
| FR-33 | Kernel-drop export of the banned prefix set. | P3 |

### 5.2 Non-functional

| Id | Requirement | Measured by |
|---|---|---|
| NFR-1 | Checkpoint fast path at most 2 ns median, 5 ns p99 [est.]. | criterion `checkpoint_fast` |
| NFR-2 | Door at most 100 ns p99 with 1,000,000 bans over all automatic lengths and 10,000 administrator prefixes [est.]. | criterion `door_1m` |
| NFR-3 | Ticket issue and release at most 40 ns median with 32 threads [est.]. | criterion `ticket_cycle` |
| NFR-4 | Checkpoint slow path (epoch moved, not revoked) at most 150 ns with 7 keys [est.]. | criterion `checkpoint_slow` |
| NFR-5 | `revoke` at most 1 µs; visible to every core within hardware coherence time. | criterion and loom |
| NFR-6 | At most 48 bytes per ban entry including index at 7/8 load [est.]; 64 bytes is the hard limit. | `tests/memory.rs` with a counting allocator |
| NFR-7 | No allocation on door, checkpoint, egress, bind, or strike paths. | counting-allocator tests |
| NFR-8 | Zero CPU when idle: no ticker; the optional maintainer parks until work is queued. | maintainer parked after 1 s idle |
| NFR-9 | Every table has a capacity fixed at construction; no input grows memory past configuration. | property and flood tests |
| NFR-10 | The door is at least 20% faster than the same-job composition: the same ban lookup and per-address rate check, plus an allow-list check, a trusted-proxy check, and a revocable handle per connection, built from the best Rust crates for each part. The lookup-only composition (ban lookup and rate check alone) is measured and published beside it, labelled as such. Decided by James on 2026-10-26 (D-081). | `benches/comparison.rs` (`door_1m/equal_job`, `door_1m/composition`) |
| NFR-11 | Readers (door, checkpoint, egress) never wait on writers (ban, revoke, lift, import). | loom, contention benchmark |
| NFR-12 | Deterministic: the same calls with the same clock and seed give the same verdicts on every platform. | proptest with `ManualClock` and fixed seed |
| NFR-13 | 24-hour soak at 100,000 connections per second with continuous bans and revocations: no growth past configured tables, no missed revocation. | soak harness (0.7) |
| NFR-14 | Zero cost for unused features: metrics compiled out; no sink means one predictable branch on cold paths. | benchmark with and without |

### 5.3 Enterprise and distributed

bouncer-io is **stateful** (bans, offender memory, revocations, budgets), so it takes the stateful row of the portfolio standard:

| Point | How bouncer meets it |
|---|---|
| correct under concurrency and load | lock-free readers, sharded registry, loom models L-1 to L-6, 24-hour soak |
| observable | an event for every action with stable signal ids; `metrics` feature; `health` and `capacity`; stable error variants |
| operable | every limit configurable with a safe default; overload refuses cleanly (`RegistryFull`, `BanTableFull` with documented eviction order); capacity numbers reported at build |
| secure and compliant | fail closed; generic denials; digests only; every action audited with actor and reason |
| state behind traits | in-memory tables are the hot structure; `Persistence` for durability (file, database, replicated store); deltas for sharing over any transport |
| clock skew | monotonic time for in-process expiry; hybrid logical clock stamps on shared records; imports stamped past `max_clock_skew` refused |
| idempotent under retries | every shared record keyed by `(origin node, origin sequence)`; revoking twice is one entry and two events; imports apply once |
| partition behaviour | each node keeps enforcing its own bans and revocations; deltas converge on reconnect in any order |
| multi-node tests | two-node convergence at 0.5; three-node simulation with partitions, skew, and reordering at 0.7 |

---

## 6. Standards and adaptations

The portfolio standard applies in full (`REPS.md`, `DIRECTIVES.md`). Adaptations, each with its reason:

| Standard | Adaptation | Reason |
|---|---|---|
| beat the best Rust competitor by 20% | judged against the best Rust composition of parts (prefix trie + keyed rate limiter + hash set) on compound paths; the single-load checkpoint must be within 10% of an `AtomicBool` load | no single crate does this job; one load cannot be beaten by 20% |
| `no_std` for OS-free cores | not offered (O-12) | tables, threads, files, and time need `std`; no consumer needs `no_std` |
| `#![forbid(unsafe_code)]` | kept, no exception | the guaranteed wipe is delegated to crypt-io (O-3); test crates may use `unsafe` for an inspecting allocator |
| zero third-party runtime dependencies | rate-net and better-bucket with default features off; crypt-io with `zeroize` and `mac-blake3` only | rate-net's `std` feature pulls `ahash` and `hashbrown`; crypt-io's `zeroize` and `subtle` are inside the cryptography exception |
| async runtime | none | sans-IO; any driver |
| Hot paths | door, checkpoint (fast and slow), before-commit, egress, bind, strike, ticket issue and release | cold paths (ban, lift, revoke, import, persist, explain) may take a writer lock and allocate, never blocking a hot path |
| Efficiency | lazy expiry, no timer per ban; time passed in by callers that already read it | zero idle CPU |
| Must-use | `Verdict`, `Ticket`, `Revocation`, `Ejected`, `Applied`, outcome types | ignoring a verdict is the bug this crate prevents |

---

## 7. Design

### 7.1 Module map

```
src/
  lib.rs          crate docs, re-exports, VERSION, constants
  error.rs        BouncerError, ConfigError, PersistError, ImportError, FormatError
  keys.rs         Cidr, Family, normalize, prefix keys, identity keys, constant-time digests
  hash.rs         keyed hash for fixed-size keys, probe bound, reseed
  time.rs         Now, wall conversion, hybrid logical clock stamps
  bouncer.rs      Bouncer, BouncerBuilder, Posture, Health, Capacity
  door.rs         door, door_at, datagram, Refusal, Provenance
  ticket.rs       Ticket, TicketTag, binding, cancel state
  registry.rs     sharded cells, tagged free lists, generations, connection index
  epoch.rs        RevocationEpoch
  revoke.rs       Target, Revocation, RevokeMode, revocation tables, quiescence, sweeps
  verdict.rs      Verdict, Denial, DenialCode, DenialTable, Reference
  collected.rs    Collected
  format.rs       DenialFormat, NoFormat
  eject.rs        Ejector, CloseKind, Ejected
  bans/
    mod.rs        BanSpec, LiftSpec, BanKey, BanRecord, DurationPolicy
    table.rs      dynamic table: one keyed open-addressing table per (family, length) + length bitmap
    compiled.rs   compiled prefix set for administrator lists and the allow list
    escalate.rs   escalation and folding
    offenders.rs  offender memory with decay
    shared.rs     shared-address sketch
  allow.rs        AllowList, AllowKind
  budgets.rs      Budgets, Rate, cells over rate-net Gcra and better-bucket BucketCore, hierarchical fallback
  strikes.rs      StrikeKind, StrikeRules, Enforcement, Mode
  directive.rs    Directive, Action, BanKeys, Actor, Reason, Evidence, Applied
  admin.rs        explain, list, Explanation, Filter, Page, Listing
  events.rs       EventSink, Event, SignalId, Category, Subject, signals catalog, sampling
  metrics.rs      MetricsSnapshot (feature "metrics")
  persist/
    mod.rs        Persistence, LoadFailure, load before first accept
    format.rs     snapshot and journal records, CRC32C, MAC (decoder fuzzed)
    file.rs       FilePersistence
  share.rs        Delta, Sequence, NodeId, merge
  maintain.rs     maintain(), the parked maintainer thread
  net_io.rs       Admission and Egress implementations (feature "net-io")
```

### 7.2 Data flow

```
                      cold path (writers: rare)                     hot path (readers: every connection / request)
 admin / back-channel --+
 gates (logout, ban) ---+--> Directive --> apply() --+--> ban memory (table, compiled set) <-- door(), bind_*()
 policy / sentinel -----+                            |
 other nodes (import) --+                            +--> revocation tables + epoch.fetch_add <-- checkpoint(): one load
 local strikes ---------+                            |                                         <-- egress(): two loads
                                                     +--> sweep queue (eject-now) --> maintainer --> Ejector::eject(conn)
                                                     +--> events --> EventSink (bridge, audit, sentinel)
                                                     +--> journal queue --> Persistence
                                                     +--> outbound delta log --> export_delta()
```

### 7.3 Keys and normalization

| Key | Type | Size | Source | Notes |
|---|---|---|---|---|
| connection id | `ConnId(u64)` | 8 B | the transport (net-io never reuses one in a process) | |
| request id | `RequestId(u128)` | 16 B | request layer (ULID) | opaque |
| source | `IpAddr`, normalized | 4 or 16 B | socket, PROXY, trusted forwarded header | `::ffff:0:0/96` mapped to IPv4 |
| prefix | `(family, len, bits)` | packed: 8 B up to /64 | derived | host bits cleared |
| session | `SessionKey([u8; 16])` | 16 B | gate-net: keyed digest of the token | constant-time equality, redacted |
| account | `AccountKey(u128)` | 16 B | user id (UUIDv7) | |
| tenant | `TenantKey(u64)` | 8 B | identity stamp | |
| fingerprint | `FingerprintKey([u8; 16])` | 16 B | TLS adapter digest | weak; automation uses compound keys |

Rules, applied once at every public entry that takes an address: IPv4-mapped becomes IPv4; IPv4-compatible, NAT64, Teredo, and 6to4 stay IPv6 (the embedded IPv4 is client-chosen and never a key); link-local and loopback are valid keys; prefixes clear host bits (`parse_strict` refuses them).

### 7.4 Tickets and the registry

A fixed array of **cells** split into shards (one per core, power of two, at most 256). Capacity fixed at construction (default 65,536; one cell per connection and one per in-flight request).

```
Cell (two cache lines, 128 B, align 64)
  header, 40 B
    state:    AtomicU64   generation (32) | flags (16): LIVE, REVOKED, CANCELLED, EJECT_REQUESTED, PENDING_CLIENT,
                          PROXY_HOP, SHARED_SOURCE, IMMUNE, DETACHED | denial code (8) | kind (8)
    link:     AtomicU32   request cells: parent connection index; connection cells: latest live request index
    present:  AtomicU32   bitmap of bound keys (Release after the key words are written)
    seen:     AtomicU64   last epoch fully checked (slow path; read by egress and quiescence cleanup)
    conn:     AtomicU64   ConnId
    born:     AtomicU64   epoch at issue
  keys, 88 B (each written once before its bit is set in `present`)
    source [2], request [2], session [2], account [2], tenant, fingerprint [2]   (AtomicU64 words)
```

The exact layout is fixed by measurement at 0.3; the 128-byte budget is a requirement.

The handle callers hold: `Ticket { shard: Arc<Shard>, index: u32, generation: u32, seen: u64, kind }`. A `Shard` is a small handle holding the epoch and `Arc<Shared>`; `Shared` holds every cell, one free list per shard, the tables, and the configuration. There is no reference cycle, and reference-count traffic is spread over shards (O-5). All cells live in one array partitioned into shards by index range, so a request can take a cell from another shard when its connection's shard is full (D-039).

- **Issue:** pop from the shard's free list, a Treiber stack whose head packs `index (32) | tag (32)`; the tag changes on every pop and push, so no ABA. Lock-free; loom L-2.
- **Shard choice:** a thread-local hint (the worker index, or a hash of the thread id). Request tickets are issued from their connection's shard.
- **Release:** `Drop` clears `LIVE`, advances the generation, clears `present`, returns budget slots, pushes the index. Dropping a connection ticket while its requests are live marks them `REVOKED` with reason `CONNECTION_CLOSED`. Release on any thread is allowed.
- **Generation wrap:** a cell whose generation reaches `u32::MAX` is retired, never reused.
- **Tags:** `TicketTag` packs the cell index and the generation into 64 bits (net-io's `GateTag`). `into_tag` marks the cell `DETACHED` and gives up the handle; `Bouncer::release(tag)` releases it. Stale tags fail closed.
- **Registry full:** `door` refuses with `RegistryFull`; `request` returns `Err(RegistryFull)`. Fail closed, sampled event.

### 7.5 Revocation: epoch, tables, ordering

**The epoch** is one `AtomicU64` alone on its cache line, owned by the bouncer or injected by the security core (O-2). Every revocation increments it; every checkpoint loads it.

**Checkpoint:**

```rust
// Sketch, not compiled.
#[inline]
pub fn checkpoint(&mut self) -> Verdict {
    let now = self.shard.epoch().load(Ordering::Acquire);       // the one atomic load
    if now == self.seen { return Verdict::Pass; }                 // the one compare
    self.slow_path(now)
}
fn slow_path(&mut self, now: u64) -> Verdict {
    let cell = self.cell();
    if cell.generation() != self.generation { return Verdict::deny(DenialCode::Unavailable); } // stale: fail closed
    if cell.flags() & REVOKED != 0 { return Verdict::deny_from(cell); }
    if cell.flags() & PENDING_CLIENT != 0 { return Verdict::deny(DenialCode::Unavailable); }
    if let Some(parent) = cell.parent() { if parent.flags() & REVOKED != 0 { return Verdict::deny_from(parent); } }
    if let Some(hit) = self.shard.revocations().matches(cell) {   // one probe per bound key kind with a non-empty table
        cell.mark_revoked(hit.code);                               // CAS; idempotent; parent too unless keep_connection
        return Verdict::deny(hit.code);
    }
    self.seen = now;
    cell.seen.store(now, Ordering::Release);
    Verdict::Pass
}
```

**Egress by tag (B6b):** the tag names a cell; the check loads the epoch and the cell's `seen` (two loads) and runs the slow path when they differ. A connection tag also checks the request named by the connection cell's `link` (its latest live request), which is exact for HTTP/1.1; a response tag from the transport is exact for multiplexed connections (D-015).

**Revoke:**

1. Validate the target (normalize; refuse allow-listed or trusted-proxy targets for automated actors).
2. Under the revocation writer lock (cold path), insert the key into the table of its kind with birth `E + 1`. Tables are open-addressing arrays of versioned slots; readers probe with atomic loads and check the version before and after (a seqlock per slot; loom L-3).
3. For connection and request targets, find the cell through the connection index and set `REVOKED` directly by CAS (and the parent unless `keep_connection`).
4. `epoch.fetch_add(1, Release)`, then `fence(SeqCst)`.
5. For `EjectNow`, push a sweep request onto the bounded, coalescing sweep queue and unpark the maintainer.
6. Emit `revoke.applied`; journal and outbound-delta records if a ban is attached or sharing is on.

**Ordering (FR-13).** The table insert happens before the Release increment, so a checkpoint whose Acquire load reads the new value sees the entry. A checkpoint that reads an older value is ordered before the revocation in the epoch's modification order. Before-commit uses a `SeqCst` load paired with the revoker's `SeqCst` fence, so a commit that starts after `revoke` returned in real time cannot miss it (loom L-1).

**Binding races (Dekker).** Binder: write key words, `present.fetch_or(bit, Release)`, `fence(SeqCst)`, then probe revocations and bans. Revoker: insert, `fence(SeqCst)`, then (for sweeps) read `present` and keys. At least one side sees the other (loom L-4).

**Cleanup by quiescence.** An entry born at `B` is needed only while a live ticket has `seen < B` and could match. The maintainer computes `min(seen)` over live cells when a table passes 50% load or every 10 s, and removes entries with `B <= min(seen)`. A ticket that has not crossed a checkpoint for `max_unchecked` (60 s) holds cleanup back, so the maintainer runs its slow path on its behalf, sets `REVOKED` on a match, ejects it, reports `checkpoint.missing`, and advances `seen`. Idle WebSockets and parked keep-alive connections are reached and the tables stay bounded.

**Table full (T-13):** the revocation is applied by a direct sweep that flags every matching live ticket, and `RevocationTableFull` is returned. Fail closed.

**Revocation is not a ban.** A revocation stops what is running; a ban refuses in future. `revoke_and_ban` does both, which is what wipe-and-eject-and-remember means.

### 7.6 Wipe, replace, eject, remember

`Ticket::deny_and_eject(&mut Collected)` performs, in order and with no early return:

| Step | Action | Who | Cost [est.] |
|---|---|---|---|
| 1 cancel | set `CANCELLED` (and `REVOKED` with `Forbidden` if not revoked yet) | bouncer | one CAS |
| 2 wipe | overwrite the whole capacity through crypt-io's guaranteed wipe; length 0 | bouncer | 30-60 ns per KiB |
| 3 replace | the formatter writes the protocol's denial (bounded by 1,024 bytes) | protocol adapter | about 100 ns |
| 4 eject | `Ejector::eject(conn, AfterFlush { 100 ms })`: abortive close after the denial flushes or the deadline passes | the transport | one system call |
| 5 remember | insert bans from enforced strike thresholds (directive bans were inserted at revoke time) | bouncer | 200-500 ns |
| 6 report | `denial.wipe_eject` event with the denial's reference | bouncer | 20-50 ns |

Rules: denial bytes are identical to the ordinary refusal of the same code (same body, headers, length class); the reason goes only to events (D-006). `Reference` is 64 random bits from a per-bouncer stream. Bytes already sent cannot be recalled: all-or-nothing routes use buffered mode so egress sees the whole response; streamed responses leak at most one transport chunk (16 KiB proposed) after a revocation. `Collected` never reallocates in place (growth copies and wipes the old block). Idempotent: a second revocation records its event but never wipes or formats again; the stored code rises only by precedence (`Forbidden` > `Unauthorized` > `TooManyRequests` > `NotFound` > `Unavailable`).

### 7.7 The door

```rust
// Sketch, not compiled.
pub fn door_at(&self, conn: ConnId, peer: IpAddr, provenance: Provenance, now: Now) -> Result<Ticket, Refusal> {
    let peer = normalize(peer);
    if self.trusted_proxy(peer) && provenance == Provenance::Socket {
        return self.admit_proxy_hop(conn, peer);          // judge the real client later (B1')
    }
    if let Some(AllowKind::Immune) = self.allow.lookup(peer) { return self.admit(conn, peer, IMMUNE); }
    if self.posture_refuses(peer) { return Err(Refusal::Posture); }
    if let Some(ban) = self.bans.lookup(peer, now) { return Err(self.refuse_banned(ban)); }   // sampled event
    if let Some(retry) = self.budgets.door(peer, now) { return Err(Refusal::OverBudget { retry_after: retry }); }
    self.admit(conn, peer, 0)
}
```

- Called before the socket is registered for reading. Refusal is abortive and silent, identical on the wire for every reason.
- **Proxy hop:** a trusted-proxy peer is admitted as a hop with `PROXY_HOP` and no source. With the PROXY protocol, the transport binds the real client on the connection under its handshake deadline. With forwarded headers, the adapter binds a client on each request, because one pooled proxy connection can carry many clients. A request under a hop with no client bound carries `PENDING_CLIENT` and every checkpoint on it denies; strikes against it go nowhere (FR-7). A hop that never resolves raises `door.proxy_hop_unresolved`.
- **Recheck:** `bind_client` runs allow, ban, and budget steps for the real client and moves the concurrency count from the proxy.

### 7.8 Ban memory

| Structure | Holds | Changes | Lookup |
|---|---|---|---|
| dynamic table | automatic and directive bans at the configured lengths, identity bans, compound fingerprint keys | often | one keyed-hash probe per length in use |
| compiled set | administrator lists of any length, imported feeds, the allow list | rarely | one multibit-trie walk; rebuilt and swapped whole |

**Dynamic table (as built at 0.3, D-036).** One open-addressing table for every kind and length (the kind and length are part of the key); a mask per family records which lengths hold entries, so a lookup probes only those (typically 2 for IPv4, 3 for IPv6), and the probes for all lengths are prepared first so their cache misses overlap. Slots are grouped by eight with one tag word per group (a byte per slot: seven bits of the key's hash, empty, or deleted), probed with triangular steps over groups, at most 32 groups: a miss reads a few tag words from one contiguous array and touches no slot. Each slot is a sequence lock, so readers never wait on the writer; since 0.8 a slot is 32 bytes (D-105). Expired entries read as absent. When an insert finds no room within the bound, it fails as `BanTableFull`; rebuilding with a fresh seed moves to 0.6 with O-8 (D-038).

**Compiled set (as built at 0.3, D-037).** A multibit trie with a six-bit stride and population-count bitmaps in the style of Poptrie (Asai and Ohara, SIGCOMM 2015): each node has a child mask and a leaf mask, children and leaves stored contiguously, and each leaf slot holds a chain of every prefix ending there that covers the slot, longest first. IPv4 lookups visit at most 6 nodes and IPv6 at most 22, whatever the number of prefixes or lengths. Built off the hot path and published by swapping an `Arc` behind a version word, read through a per-thread cache, so readers take no lock in the steady state.

| Approach | Lookup | Memory per prefix | Update | Fit |
|---|---|---|---|---|
| binary radix trie | up to 32 / 128 dependent loads | about 80 B [est.] | in place | poor |
| tree bitmap (`prefix-trie`) | a few loads per stride | tens of bytes [est.] | moderate | good for mixed lengths |
| Poptrie-style | IPv4 depth 4-6, IPv6 up to 11 for /64 | a few bytes amortized [est.] | rebuild | best for rarely changing lists |
| DIR-24-8 | 1-2 loads | 32 MiB fixed for IPv4 [est.] | fast | too large; IPv4 only |
| hash per length + length mask | one probe per length in use | 40-48 B [est.] | O(1) | best for frequent changes at few lengths |

Decision O-4: dynamic table for automatic bans, compiled set for administrator lists and the allow list; confirmed by benchmark at 0.6 against `prefix-trie`.

**Entry layout (target 48 bytes with index):** key 8; until 4 (seconds since start, 0 = permanent); issued 4; wall issued 4 (offset from a 2026 base); reason 2, actor 1, flags 1; offences 2, level 1, length 1; evidence reference 4; origin node 2, sequence 2; index slot about 9 at 7/8 load. About 45 bytes [est.]. Comparison: nginx `limit_req` 128 B and `limit_conn` 64 B per state; HAProxy stick tables about 50 B (IPv4) and 60 B (IPv6); rate-net about 138 B per key.

**Durations:** `min(base * factor^min(offences, step_cap), max) + uniform(0, jitter)`, saturating; defaults 10 minutes, 2, 20, 7 days, 60 s (fail2ban's `bantime.increment` with `maxtime` and `rndtime`).

**Eviction when full (T-4):** (1) expired entries; (2) fold: if the parent already holds `fold_threshold` children, escalate instead of inserting, which frees the children; (3) the automatic ban with the earliest end among a bounded scan of 32 slots; (4) if only permanent, administrator, or directive bans remain, refuse with `BanTableFull`, still eject, event and metric. Administrator and permanent entries are never evicted. Per-parent quota: no /48 holds more than 64 /64 entries and no IPv4 /16 more than 256 /32 entries; beyond it, escalation is forced.

### 7.9 Budgets: the rate-limiting tool

| Budget | Key | Default | Checked at | Algorithm |
|---|---|---|---|---|
| accept rate | address, then prefix, then global | 20/s burst 40 per address; 200/s per /24 or /64; global off | door | `rate_net::Gcra` |
| concurrency | address, then prefix | 64 per address, 512 per /24 or /64 | door; release | atomic counter, saturating |
| lane rate | session or address, per lane | off | `bind_lane` | `Gcra` |
| tenant rate | tenant | off | `bind_tenant` | `better_bucket::BucketCore` |
| tenant in-flight | tenant | off | `bind_tenant`; release | atomic counter |
| throttle | any key | none until a directive | as the key's class | divides the quota for a duration |

No rate math is re-implemented. Keyed storage is bouncer's own bounded table (O-1). Eviction never resets a limit: only fully recovered keys are evicted; a newcomer in a full table is charged against its parent, then the global cell, so availability holds and a key cannot reset itself by flooding. The public `Rate` type is bouncer's own (D-014).

### 7.10 Escalation, offender memory, shared addresses

**Escalation.** Ladders IPv4 /32 to /24 and IPv6 /64 to /56 to /48. A parent is banned when 8 (IPv4) or 4 (IPv6) distinct children are banned inside it within an hour; duration is the longest remaining child times 2, capped. Children fold into it. Refused, with an event, over an allow-list entry, a trusted proxy, a shared address, or past the widest prefix (/24, /48).

**Offender memory.** A bounded table keyed like bans holding a decayed offence score (half-life 24 h) and the last offence time; it survives ban expiry and is persisted and shared.

**Shared addresses (T-5).** Per source address, a 64-bit sketch of distinct sessions seen in the last hour. Past 16 distinct sessions the address is flagged `SHARED_SOURCE` for 24 h: automation prefers identity keys, address bans from local heuristics become throttles, escalation stops at the address. Administrators and high-confidence directives can still ban it.

### 7.11 Strikes, directives, enforcement

Strikes come from every layer (handshake failures, PROXY violations, TLS alerts, malformed traffic, contract violations, slow-peer kills, failed logins, authorization denials, reuse of revoked session tokens, decoy touches). `Ticket::strike` adds weight in a windowed counter (default 5 within 10 minutes) and forwards the strike to the sink.

| Actor | Default mode |
|---|---|
| local heuristics (strike thresholds) | **observe**: `threshold.reached` with the ban that would have been applied (D-010) |
| policy directives, sentinel-sec, gates, administrators, the application, other nodes | enforce |

Safety rules regardless of configuration: a directive below confidence 30 cannot ban by itself (it throttles); experimental rules only observe; every action records its cause; a decoy touch is definitive.

**Posture.** `Strict` divides door budgets (default by 2), switches the categories listed in `Enforcement::strict` to enforce, and revokes nothing unless `strict_revokes_unauthenticated` is set.

### 7.12 Persistence

- **Format:** snapshot (magic `BNCR`, format version, created wall time, entry count, entries, trailer with length and checksum) plus an append-only journal of ban, lift, offence, and escalation records (length, type, payload, CRC32C). With a key configured, a keyed BLAKE3 MAC over snapshot and journal (O-9).
- **Load** runs inside `try_build`, before any door. Checksum or MAC failure returns `Persist(Corrupt | Mac)` and the service refuses to start unless `LoadFailure::LoadEmpty` was chosen explicitly. A torn journal tail is tolerated and reported.
- **Time across restarts:** remaining = `until_wall - now_wall`, never more than the original duration; a backward clock step never lengthens or resurrects a ban, and a forward jump past `max_wall_jump` (1 h) is reported (with `strict_wall_jump` the bans are kept).
- **Crash-safe write:** temp file, `sync_all`, rename, directory sync on Unix; Windows rename replaces the target; tested on all three platforms.
- **Off the hot path:** a bounded journal queue (65,536); full means dropped from persistence (never from memory) and reported. Synced every second or on `flush`; compacted past 16 MiB.

### 7.13 Sharing across nodes

bouncer provides the data, never the transport. `export_delta(since)`, `export_snapshot()`, `import(delta, from)`.

- Records: ban, lift (tombstone), offence, escalation, **revocation**. Each carries origin node, origin sequence, and a hybrid logical clock stamp (wall milliseconds, counter, node), so merge order does not depend on clocks agreeing (D-017).
- **Merge** (commutative, associative, idempotent; D-096): records keyed by `(origin, sequence)`; each origin's ban on a key is kept apart, and of one origin's bans the latest stamp wins; the effective ban is the merge of every origin's ban in force (latest end, permanent wins); a lift covers the bans stamped at or before it of its own origin, or of every origin for an administrator's lift delivered by an administrator; a later ban wins over a lift. Revocations are applied to local running requests and kept only while they can match a live ticket.
- Stamps more than `max_clock_skew` (5 minutes) ahead are refused (`ClockSkew`).
- Each node enforces locally; a partitioned node keeps protecting itself and converges on reconnect.
- Authentication of deltas is the transport's job (mutual TLS on node links or the back-channel). Imports from `Actor::Channel` are rate limited, never touch the allow list, carry only that channel's node's own records (nothing is relayed; D-101), and its lifts reach only that node's bans. An administrator's lift reaches every node's bans through the administration channel (`import(.., Actor::Admin(..))`).
- Works over gossip-style exchange or a replicated log; the choice belongs to the node core, not to bouncer (O-7).

### 7.14 Events and metrics

Every action emits an `Event` (fixed size, borrowed evidence, no allocation) to the sink. Refusals are sampled per ban per 10 s with exact counts. Generator id 2 (below 1000, the platform range); the catalog is in `docs/API.md` and its ids never change meaning. Categories and the severity, confidence, and risk axes follow the security signals vocabulary. Metrics (feature `metrics`) are per-shard relaxed counters on the shard's own line, summed on read.

### 7.15 Maintenance without idle CPU

Sweeps, revocation cleanup, idle-ticket checks, expired-entry reclamation, journal sync and compaction, compiled-set rebuilds. Either the caller drives `maintain(now)` (bounded work, returns the next due time) or `maintainer(true)` spawns one thread that parks with `park_timeout(next_due)` and is unparked by sweep requests; with nothing pending it never wakes.

### 7.16 Integration with net-io (D-015)

bouncer implements net-io's single `Gate` trait (agreed with the net-io session on 2026-10-23): `type Ticket` (bouncer's `ConnectionGate`, stored by net-io beside the connection), `admit(&ConnectionInfo, AdmitStage) -> Result<Admitted<Ticket>, Refusal>`, `readmit(&mut Ticket, &ConnectionInfo)` after a trusted PROXY header, `check(&mut Ticket, &WriteCheck) -> Result<(), Denial { code }>` before every write, and `closed(Ticket, &ConnectionInfo, CloseReason)` exactly once. net-io's session formats the denial for the code; ejection from bouncer's maintainer uses `ServerHandle::kill(ConnectionId, KillReason)`. Because the ticket is in hand, the egress fast path is one atomic load (the last-seen epoch lives in the ticket). Close reasons that mean misbehaviour become strikes. bouncer asked for two additions: an opaque `GateTag(u64)` returned in `Admitted` and readable by the session through `ConnectionInfo`, so the protocol engine can open request tickets with `Bouncer::request(tag, id)` without being generic over the gate; and `WriteCheck.response: Option<GateTag>`, set by `Output::begin_response`, so multiplexed connections are judged per request. Without the second, bouncer follows each connection's latest request (exact for HTTP/1.1).

---

## 8. Threats, defences, tests, costs

| Id | Threat | Defence | Test (must fail to get through) | Cost |
|---|---|---|---|---|
| T-1 | Address spoofing behind proxies to evade a ban or frame someone | PROXY only from trusted proxies; forwarded headers bound only with a trusted provenance; automation bans only trusted-provenance addresses; the proxy is never a target | `test_door_forwarded_header_from_untrusted_peer_not_bound`, `test_strike_on_proxy_hop_ignored_and_real_client_struck`, `test_ban_trusted_proxy_refused`, `test_proxied_request_without_client_denies_every_checkpoint` | about 1 ns |
| T-2 | Ban evasion by IPv6 /64 rotation (RFC 8981 temporary addresses) | automatic keys at /64; escalation /64 to /56 to /48; strikes also counted at the widest escalation prefix, so rotating before any /64 reaches its threshold is caught there (D-108); budgets per /64 and parent | `test_ban_ipv6_rotation_within_64_refused`, proptest over banned /64s, `test_escalation_four_64s_bans_56_then_48`, `test_replay_credential_stuffing_from_a_48_bans_the_48` | one more strike counter per prefix and kind |
| T-3 | Rotation inside an IPv4 provider block | /24 escalation after 8 distinct /32 | `test_escalation_ipv4_eight_hosts_bans_24` | one probe |
| T-4 | Ban table exhaustion | fixed capacity; per-parent quota forces escalation (folding); evict shortest automatic bans only; refuse with event when full | flood: 10x capacity unique /64s from 64 /48s; table stays at capacity, every flooding /48 banned, admin bans intact | scan bounded to 32 slots |
| T-5 | Banning shared NAT addresses (RFC 6598 carrier-grade NAT, offices, mobile) | shared-address detection; identity keys preferred; throttle instead of ban; no escalation or prefix strike ban over a shared address; a shared address held to its prefix's door budget, not one client's (D-109); low confidence cannot ban; observe by default | `test_shared_source_strikes_throttle_not_ban`, `test_shared_source_blocks_escalation`, `test_replay_cgnat_population_keeps_its_users_and_loses_its_attacker`: 500 sessions (and 2,000 users) behind one address with one attacker: only the attacker's keys banned, no user refused | 8 B per tracked address |
| T-6 | Revocation races (checkpoint, bind, release) | Release/Acquire epoch; SeqCst fence pairing; generations; idempotent revoked state | loom L-1 to L-5; 32 threads, 10^8 checkpoints, random revokes, no checkpoint started after `revoke` returned passes | zero on the fast path |
| T-7 | Bytes leaving a revoked connection | mandatory transport egress check per write and per chunk; request revocation flags the connection; eject-now; buffered mode for all-or-nothing | `test_egress_after_revoke_writes_only_denial`; loopback: revoke during a 10 MiB stream, at most one chunk leaves | two loads per write |
| T-8 | Timing side channels on ban, allow, or revocation state | every refusal is the same abortive close with no work after the decision; denials byte-identical to ordinary refusals; wipe over the whole constant capacity; keyed hashing; constant-time digests | `test_timing_admitted_does_not_reveal_neighbour_bans`, `test_timing_bind_does_not_reveal_near_banned_digests` (KS at p < 0.01, D-093; `--ignored`, release, quiet machine); byte equality of denials; the abortive close at the transport with net-io (0.8) | wipe 0.5-1 µs per 16 KiB [est.] |
| T-9 | Hash flooding | keyed hash with a random per-process seed; probe bound; reseed and rebuild with event | 10^6 keys colliding under a known seed, run with a random seed: probes stay bounded; forced seed triggers reseed | 3-10 ns per key [est.] (O-8) |
| T-10 | Stale ticket handles | generations; tagged free list; stale denies | `test_ticket_stale_generation_denied`, loom L-2 | one compare on the slow path |
| T-11 | Collateral fingerprint bans | automation bans only fingerprint-within-prefix; bare fingerprint bans need an administrator | `test_bind_fingerprint_compound_ban` | none |
| T-12 | Revocation storm pushing every checkpoint onto the slow path | bounded slow path; per-actor revocation rate limit (default 10,000/s for gates) with event; coalesced sweeps | 100,000 revocations/s while serving: p99 checkpoint under 300 ns | bounded |
| T-13 | Revocation table exhaustion | capacity bound; quiescence cleanup; idle checks; when full, direct sweep flags matching live tickets and the error returns | fill with no maintainer: the next revoke still denies matching live tickets | sweep cost |
| T-14 | Registry exhaustion by connection flood | fixed capacity; per-address and per-prefix concurrency at the door; transport global cap below registry capacity | flood from 1,000 addresses: a legitimate address is still admitted within its budget | none |
| T-15 | Forged ban persistence | keyed MAC; refuse on MAC failure | `test_snapshot_tampered_byte_refused` | MAC about 1 GB/s at load [est.] |
| T-16 | Torn writes and crashes | temp, sync, rename, directory sync; CRC32C records; tolerant tail | kill at 1,000 random points during writes; reload succeeds or refuses cleanly, never loads a corrupt entry | off the hot path |
| T-17 | Malicious import delta | per-channel rate limit; allow list untouchable; bounded deltas; fuzzed decoder; channels lift only their own node's bans; skew bound | fuzz `delta_decode`; `test_import_cannot_touch_allowlist_and_foreign_lifts_refused`; `test_node_a_day_ahead_cannot_poison_the_cluster` | cold |
| T-18 | Secrets in logs or events | digests only; redacted `Debug`; no evidence variant for digests | `test_debug_never_prints_key_bytes` | none |
| T-19 | Clock manipulation | monotonic in-process expiry; wall rules across restarts; HLC across nodes | `ManualClock` steps back and forward a day, across a reload and an import | none |
| T-20 | Unverified UDP sources framing victims | never strike or ban unverified datagram sources; charge them at the prefix under a key of their own, so they never spend a real source's budget (D-092) | `test_datagram_unverified_never_banned`, `test_datagram_forged_flood_does_not_starve_verified_sources` | one rotate and xor per unverified datagram |
| T-21 | Denial reveals detection | generic codes, fixed messages, reason only in events | byte-equality tests (T-8) | none |
| T-22 | Wipe removed by the optimizer | volatile writes through crypt-io; never `fill(0)` alone | inspecting global allocator: every freed `Collected` block is all zero in release builds | as 7.6 |
| T-23 | Stale reallocation copies | `Collected` never reallocates in place | allocator inspection on growth | one copy on growth |
| T-24 | A request reaches content before identity is bound | `present` bitmap; the gateway's stage types guarantee the identity checkpoint; `require(keys)` debug assertion in tests | integration test in the gateway | none |
| T-25 | Escalation weaponized against neighbours | widest-prefix limit; refused over shared or allow-listed addresses; observe by default for local heuristics | `test_escalation_blocked_by_allow_list_and_proxy_and_shared` | none |
| T-26 | A pipeline that forgets checkpoints | transport egress (B6b) is mandatory; idle revoked tickets are found by the maintainer and reported as `checkpoint.missing` | `test_idle_ticket_checked_on_its_behalf_and_reported` | rides on the quiescence scan |
| T-27 | A node with a broken or hostile clock poisons the cluster | HLC stamps; future stamps past the skew bound refused; tombstones ordered by stamp, not by arrival | three-node simulation with one node 1 day ahead | none |

---

## 9. What it does not cover

- Bytes already flushed cannot be recalled (7.6).
- Floods larger than the network link need upstream help (provider, CDN). bouncer protects the server's resources, not the pipe.
- Detection quality depends on the signals fed in; long-term correlation is sentinel-sec's job.
- A compromised process can disable its own bouncer; containment is shield-sec's job.

---

## 10. Parity

Every competitor (fail2ban, nginx `limit_req` / `limit_conn`, HAProxy stick tables, Cloudflare rate limiting, governor, CrowdSec bouncers) stops at the door or at the request's first phase. None revokes a request already being handled, wipes what it collected, blocks the commit, or checks egress. Those are P0 here and have no parity target.

| Capability | Best existing | bouncer-io |
|---|---|---|
| refuse before reading a byte | fail2ban (firewall), HAProxy `tcp-request connection reject`, CrowdSec firewall bouncers | yes (B1) |
| dynamic bans without reload | fail2ban, HAProxy, CrowdSec | yes |
| CIDR bans | static lists in nginx and HAProxy; CrowdSec ranges | any length |
| IPv6 /64-aware automatic keys | partial (Cloudflare "IP with NAT support") | default /64 |
| prefix escalation | none | yes |
| growing durations, jitter | fail2ban `bantime.increment`, `rndtime` | yes, with offender memory and decay |
| allow list, proxy-aware real client | all, with configuration | compiled, provenance tracked, fail closed |
| per-key rate and concurrency | nginx, HAProxy, governor | yes, as a tool |
| per-tenant budgets | manual keys at best | yes |
| observe / dry-run | nginx `*_dry_run`, Cloudflare `log` | default for local heuristics |
| in-flight revocation, wipe, before-commit, egress | none | yes |
| persistence | fail2ban (SQLite), CrowdSec (LAPI) | crash-safe journal, MAC |
| sharing across nodes | HAProxy peers (values overwrite), CrowdSec central lists, Cloudflare | mergeable deltas including revocations |
| explain why | partial everywhere | every cause per key |
| bounded memory | nginx LRU, HAProxy `size` | yes; never evicts admin or permanent; folds |
| when the decision source is unreachable | CrowdSec passes through by default | local enforcement continues |
| memory per entry | nginx 128 B / 64 B, HAProxy about 50-60 B | 45-48 B target |
| zero third-party runtime dependencies | governor needs hashbrown | yes |

Sources: fail2ban `jail.conf`; nginx `ngx_http_limit_req_module` and `ngx_http_limit_conn_module` docs; HAProxy stick-table introduction; Cloudflare rate limiting rule parameters; governor 0.10 docs; CrowdSec remediation component specification.

---

## 11. Performance

| Path | Target [est. until 0.6] |
|---|---|
| checkpoint, nothing revoked | median under 2 ns, p99 under 5 ns |
| checkpoint slow path | under 150 ns with 7 keys |
| before commit | under 5 ns |
| transport egress | under 3 ns |
| door, 1,000,000 bans, 10,000 admin prefixes | under 100 ns p99 |
| ticket issue and release | under 40 ns median, 32 threads |
| bind | under 30 ns each |
| revoke | under 1 µs |
| ban insert | under 500 ns |
| eject-now sweep, 65,536 cells | under 1 ms |
| memory per ban | 45-48 B, hard limit 64 B |
| idle CPU | zero wake-ups with nothing pending |

| Benchmark | bouncer path | Compared with |
|---|---|---|
| `checkpoint_fast` | `Ticket::checkpoint` | an `Arc<AtomicBool>` load (must be within 10%) |
| `door_1m` | `door_at` | `prefix-trie` longest match + `governor` keyed check + `HashSet` exact lookup |
| `ban_insert` | `ban` | `prefix-trie` insert + `HashMap` insert |
| `budget_check` | door budget step | rate-net keyed `RateLimiter::check`, governor keyed check |
| `ticket_cycle` | issue + release | one `Arc` allocation per connection |
| `revoke_storm` | checkpoints under 100,000 revocations/s | none exists |
| `wipe_16k` | `Collected::wipe` | `zeroize` on a `Vec<u8>` |
| `memory` | bytes per ban | nginx, HAProxy documented figures |

### 11.1 Measured at 0.3 (first measurement)

Host: AMD Ryzen 9 9950X3D (16 cores, 128 MiB L3), Windows 11, Rust stable, release profile (fat LTO). The machine was running other build jobs, so runs varied by up to half; `Instant` on Windows resolves to 100 ns, so per-call percentiles below that are not meaningful. Method: `examples/door_p99.rs` (fixture of 1,000,000 bans over /32, /24, /64, /56, /48 plus 10,000 administrator prefixes at other lengths; 1,000,000 distinct random peers; door samples include ticket issue and release) and a per-case breakdown run.

| Path | Measured | Target |
|---|---|---|
| `checkpoint`, nothing revoked | 1.1 ns per call (mean of batches of 1,000) | 2 ns median |
| door, no bans (ticket issue and release only) | 66-120 ns per call | part of 100 ns |
| door, 500 bans (cache resident), IPv4 | 117-197 ns per call | |
| door, 1,000,000 bans, IPv4, random peers | 231-347 ns per call | 100 ns p99 |
| door, 1,000,000 bans, IPv6, random peers | 312-358 ns per call | 100 ns p99 |
| door, full fixture, p50 / p99 (100 ns timer) | 300 / 1,000 ns admitted; 400 / 900 ns banned | 100 ns p99 |
| memory, full fixture | 63 MiB for every table | 45-48 B per ban |

The door target is not met at 0.3. Where the time goes: about 70 ns of ticket issue and release (four atomic read-modify-writes and the reference count), about 30 ns per probe of hashing, and the misses of random access into a 60 MiB table (mostly TLB misses with 4 KiB pages). The plan for 0.6, recorded in ROADMAP: 8-byte keys and 32-byte slots (the table halves), the keyed-hash decision O-8, fewer atomic operations per ticket (O-5 measured), and measurement on a quiet reference machine with percentiles from a nanosecond timer. With realistic traffic the probed tag words of recurring clients stay in cache, which the cache-resident row shows.

### 11.2 Measured at the start of 0.6

Same host, still shared with other build jobs; criterion medians from `benches/comparison.rs`, where bouncer and the composition run on the same data in the same process. Ratios matter more than absolutes here.

| Bench | bouncer | Compared with | Ratio |
|---|---|---|---|
| `checkpoint_fast` | 0.40 ns | `Arc<AtomicBool>` load, 0.40 ns | 1.0 (target met) |
| `door_1m`, admitted, warm | 142 ns | `prefix-trie` per family + `HashSet`, 26 ns | 5.5 |
| `door_1m`, banned | 65 ns | 12 ns | 5.3 |
| `door_1m`, random peers | 156 ns | 45 ns | 3.4 |
| `budget_check` | 79 ns | `governor` keyed, 19 ns | 4.1 |

Where the door's time goes (`door_parts`): ticket issue and release about 78 ns; the judgement on empty tables 12 ns; against 1,000,000 bans 53 to 62 ns (ban memory about 40 to 50 ns); one `Bouncer::now()` 26 ns on Windows. The composition does less (no ticket, no allow list, no trusted proxies, no revocation hookup), but ban lookup alone is still about 5 times slower. NFR-10 is not met; the 0.6 work is fewer atomic operations per ticket, cheaper probes (the keyed hash O-8, smaller slots), and a cheaper clock on the hot path.

### 11.3 Measured at the end of 0.6

Pinned to one logical core (D-088); `docs/PERFORMANCE.md` has every table, the method, and the 0.5.0 comparison. Against the same-job composition (NFR-10): admitted 113.4 against 109.3 ns, random peers 151.2 against 118.1 ns; the target (20% faster: about 87 and 94 ns) is not met; the plan is in `dev/ROADMAP.md`. Against the lookup-only composition: 46.6 and 66.6 ns. Every other PLAN 11 target is met except the door's p99 (not met), ticket issue and release at 32 threads (not measured), and memory per ban (56 B, within the 64 B limit). At 0.8 (0.7.0 against the branch, alternating on one core): `door_at` admitted 92.1 against 110.7 ns, random peers 133.3 against 115.9 ns; memory per ban 37.7 B (NFR-6 met, D-105). NFR-10 is met by neither case yet; the remaining steps are in `dev/ROADMAP.md`.

NFR-10 is judged on `door_1m` and `budget_check`. Numbers are published in `docs/PERFORMANCE.md` with host, OS, CPU, Rust version, and profile; p99 and p99.9 from a harness over 10^7 operations; baselines committed; a regression over 5% blocks the change.

---

## 12. Testing

### 12.1 Unit and integration

Every public function and every `Ok` and `Err` path, tests at the bottom of each file, names `test_<subject>_<condition>_<expected>`. Integration tests: `door.rs`, `revoke.rs`, `wipe.rs` (inspecting allocator), `persistence.rs` (kill tests), `share.rs`, `escalation.rs`, `budgets.rs`, `events.rs`, `memory.rs` (counting allocator), `net_io.rs` (loopback, feature `net-io`).

### 12.2 Property tests

- `normalize(normalize(a)) == normalize(a)`; IPv4-mapped and plain IPv4 give the same verdict for every operation sequence.
- Every address inside a banned prefix is refused until expiry; every address outside every ban is admitted (budgets off).
- `Cidr::parse(c.to_string()) == c`.
- No sequence of ban, lift, expire, escalate leaves an allow-listed or trusted-proxy address banned by automation.
- The ban table never exceeds capacity; admin and permanent entries are never evicted.
- A revoked ticket never returns `Pass` until released.
- `deny_and_eject` always leaves `Collected` all zero before formatting.
- Delta merge is commutative, associative, idempotent, including revocation records and skewed stamps.
- Durations never overflow and never exceed `max + jitter`.
- Budget admissions per key never exceed the rate bound, including across eviction and fallback.
- Snapshot encode then decode is identity; any single-byte corruption is detected.

### 12.3 Fuzz targets

`cidr_parse`, `snapshot_decode`, `journal_replay`, `delta_decode`, `directive_sequence` (operation sequences against an oracle model). Corpus kept outside the repository.

### 12.4 Loom models

| Model | Checks |
|---|---|
| L-1 epoch | revoke (insert, Release increment, SeqCst fence) vs checkpoint (Acquire) vs before-commit (SeqCst) |
| L-2 free list | concurrent issue and release on one shard: no double hand-out, no ABA |
| L-3 versioned slot | reader vs writer on a revocation slot and a ban slot: no torn key |
| L-4 bind vs revoke | Dekker fences |
| L-5 release vs revoke | a revocation never lands on the next generation |
| L-6 budget counters | concurrency increment and decrement never underflow or leak |

### 12.5 Edge cases

**Addresses and prefixes**
1. `0.0.0.0/0` and `::/0` as administrator bans (refuse everything except immune); refused for automation.
2. Prefix length 0, 1, 31, 32, 33 for IPv4; 0, 1, 63, 64, 65, 127, 128, 129 for IPv6.
3. Host bits set (`10.0.0.5/24`): normalized by `parse`, refused by `parse_strict`.
4. IPv4-mapped `::ffff:203.0.113.7` against bans on `203.0.113.7` and `203.0.113.0/24`.
5. IPv4-compatible `::203.0.113.7`: not converted.
6. NAT64 `64:ff9b::cb00:7107` against a ban on `203.0.113.7`: no match, by design.
7. Teredo and 6to4: plain IPv6 keys.
8. Zone id in text (`fe80::1%eth0`): parse error with position.
9. Whitespace, leading zeros in IPv4 octets (`010.0.0.1`): refused.
10. Text length 64 and 65 bytes.
11. Same address allowed and banned: allow wins; automation refused; admin ban returns `AllowListed`.
12. Allow entry inside a banned prefix: the allowed address admitted, the rest refused.
13. Trusted proxy inside a banned prefix: the hop admitted, real clients judged.

**Door and tickets**
14. Registry capacity 1: second door refused `RegistryFull`; after release, admitted.
15. Capacity n-1, n, n+1 concurrent issues from 32 threads.
16. Ticket dropped on a different thread and shard than issued.
17. Connection ticket dropped before its request tickets: children revoked with `CONNECTION_CLOSED`.
18. `request()` on a request ticket: `NotAConnectionTicket`.
19. `request()` on a revoked connection: `Revoked`.
20. `bind_session` twice: second denies, first key kept.
21. `bind_client` after a socket-provenance source: refused; on a proxy hop: allowed once from a trusted provenance.
22. Proxy hop that never binds a client: every request checkpoint denies; strikes ignored; event after the handshake deadline (`max_unchecked`, at the next maintenance run; D-097).
23. A `now` earlier than the last one: treated as the later time (nothing expires early).
24. Ban ending exactly at `now`: expired (`until <= now`).
25. Old handle after release and reissue: stale deny.
26. Generation at `u32::MAX` (forced): the cell is retired.
27. Tag used after `release`: `Stale` from `Bouncer::request`, `Deny` from `egress`.
28. `release` twice: second returns `false`.

**Revocation**
29. Concurrent revoke and write: the write completes before the epoch increment or is denied; never a byte after a deny.
30. A second revocation while `deny_and_eject` runs: event recorded, no second wipe or format, code precedence applied.
31. Revocation of a key while it is being bound (Dekker case).
32. Revoke a connection id never issued or already released: receipt returned, nothing matched, entry cleaned at the next cleanup.
33. Revoke the same target twice: idempotent, two events, one entry.
34. Epoch started at `u64::MAX - 2` in a test build, three revocations: every ticket sees each change (equality compare; a real wrap needs 2^64 increments, over 584 years at 10^9 per second).
35. Revocation table full with the maintainer stopped: the new revocation still reaches live tickets by direct sweep; error returned.
36. Idle ticket past `max_unchecked`: the maintainer runs its slow path, ejects on match, reports `checkpoint.missing`.
37. Request revoked with `keep_connection`: the connection continues; later requests unaffected.
38. Revoke by `Source` covering a trusted proxy: the hop is not revoked; real clients inside are.
39. Revoke by tenant at its in-flight cap: the count returns on release, never negative.
40. Before-commit on a stale ticket: deny.
41. Egress on a connection tag whose latest request is revoked by session: deny.

**Wipe, replace, eject**
42. `Collected` empty, one byte, exactly capacity, capacity plus one (growth), limit, limit plus one (`CollectedFull`).
43. Growth from 16 KiB to 1 MiB: every intermediate block wiped before free.
44. A formatter returning `TooLarge`: no bytes, eject proceeds.
45. A formatter that panics: documented (`panic = "abort"` in release); bouncer's state is consistent before the call (cell revoked, buffer wiped).
46. No `Ejector`: `ejected: false`; the caller closes; the event notes it.
47. Flush deadline passed with a slow reader: abort without the denial (bouncer hands the `Ejector` `AfterFlush` with a 100 ms deadline, tested at 0.7; the transport's abort is tested over loopback with the net-io feature at 0.8).

**Bans, escalation, memory**
48. Table at capacity with only permanent entries: `BanTableFull`, event, connection still ejected.
49. Per-parent quota reached: forced escalation.
50. Escalation blocked by an allow-listed address inside the parent: children kept, event.
51. Escalation to the widest prefix and one step beyond: stops at the widest.
52. Lift of a child inside a banned parent: the parent stands; `explain` shows both.
53. Lift of a parent: folded children are not resurrected.
54. Offender decay after 1, 2, 10 half-lives; durations follow.
55. Duration at `step_cap`, at `max`, factor 1, jitter 0.
56. Shared-source flag set and expired.

**Clock**
57. Monotonic expiry only; `ManualClock` past a ban's end: admitted.
58. Wall clock back one day between save and load: remaining never exceeds the original.
59. Wall clock forward one day between save and load: expired bans expired; a jump past `max_wall_jump` reported; with `strict_wall_jump` kept.
60. Leap second or NTP slew: no effect on monotonic expiry.

**Persistence and sharing**
61. Snapshot truncated at every byte boundary: refused or fully loaded, never partially (except the journal tail rule).
62. Journal with a corrupt middle record: replay stops there; later records reported lost.
63. MAC'd snapshot loaded without the key: refused.
64. Delta from a future format: `UnsupportedFormat`.
65. Same delta twice: no change the second time.
66. A lift imported for a ban this node issued after the lift's stamp: the ban stays.
67. A delta stamped past the skew bound: `ClockSkew`, event.
68. A revocation imported for a session with a request running here: the request is denied at its next checkpoint.

**Load and failure**
69. 32 threads on one shard while another thread bans and lifts at 10^5 per second.
70. Maintainer thread lost (a panicking sink under `panic = "unwind"` in tests): bouncer keeps enforcing; `maintain` still works; `health` reports `Stopped`.
71. A blocking sink (contract violation): door latency rises only on event-emitting paths (sampled), never on checkpoints.

### 12.6 Attack tests and CI

Every row of section 8 has its named test. A replay harness (`tests/replay.rs`) drives hostile traffic (scanner, slowloris, credential stuffing from a /48, a CGNAT population) through the door, tickets, binds, and strikes the way net-io's gate and a protocol engine drive them, with innocent traffic beside it, on a manual clock; the same traffic through serve-net waits for serve-net's first release (ROADMAP 0.8). CI: Linux, macOS, Windows on stable and 1.85; fmt; clippy in default, all, and no-default modes under `-D warnings`; tests in the same three modes; `cargo doc -D warnings` with default and all features; `cargo audit`; `cargo deny check`; a loom job; a fuzz build job.

---

## 13. Ecosystem and dependencies

| Crate | Version | Use |
|---|---|---|
| `clock-lib` | 1.1 | monotonic and wall time; `ManualClock` in tests |
| `rate-net` | 2.0, `default-features = false` | `Gcra` inside budget cells |
| `better-bucket` | 1.1, `default-features = false` | `BucketCore` for tenant budgets |
| `crypt-io` | 1.2 (needs the public `wipe`, O-3), `default-features = false`, features `zeroize`, `mac-blake3` | guaranteed wipe; snapshot MAC |
| `net-io` | 0.3+, optional (feature `net-io`) | hook implementations |

Dev-dependencies: `criterion`, `proptest`, `loom` (under `cfg(loom)`). Peers without a dependency: gate-net, sentinel-sec, customs-sec, serve-net, audit-trail, the security signals module (all through traits or directives).

---

## 14. New defence ideas

One per version, as hypothesis, method, expected cost.

| Version | Hypothesis | Method | Expected cost |
|---|---|---|---|
| 0.2 | Recording where a revocation was caught (the checkpoint's call site through `#[track_caller]`, written only on the slow path) and reporting revoked tickets that never reach a checkpoint finds integration gaps in production before an attacker does | slow path stores the `Location`; maintainer scan reports `checkpoint.missing` with the last caught-at site; test with a pipeline that skips stages | zero on the fast path (measure the hidden caller argument at 0.6); a pointer store on the slow path |
| 0.3 | Compound keys (fingerprint within prefix) cut collateral bans to near zero while keeping rotation resistance | replay a scanner trace with and without compound keys; count innocent sessions refused | 16 B per compound entry |
| 0.4 | Running the slow path on behalf of idle tickets closes the idle-WebSocket gap without a timer | loom plus soak with 10,000 idle WebSockets and random revocations | one scan per cleanup interval |
| 0.5 | The shared-address sketch separates NAT from attacker rotation | simulation of CGNAT populations | 8 B per address |
| 0.6 | Prefetching the next probe's slot during the door check lowers p99 with 1M bans | benchmark | none |
| 0.7 | Byte-identical denials plus constant-capacity wipes remove a measurable timing signal | statistical timing test (T-8) | wipe cost |
| 0.8 | Tarpit mode for confirmed scanners wastes their time at bounded cost | bounded tarpit slots (256) holding sockets without reading | one socket per slot |
| 0.9 | Kernel-drop export of permanent prefixes moves flood cost out of the process | XDP prototype outside the crate | none in process |

---

## 15. Open decisions

Every decision from the specification is answered below (and logged in section 17).

| Id | Question | Answer | Status |
|---|---|---|---|
| O-1 | How bouncer uses rate-net and better-bucket | rate-net `Gcra` and better-bucket `BucketCore` with default features off, inside bouncer's own bounded keyed table; revisit when rate-net's keyed store drops `ahash` and `hashbrown` | decided (D-019) |
| O-2 | Who owns the epoch word | bouncer by default, injectable with `BouncerBuilder::epoch` | decided (D-020) |
| O-3 | Wipe under `forbid(unsafe_code)` | crypt-io 1.2 adds a public `wipe(&mut [u8])` over its existing volatile-write helper | decided (D-021); crypt-io 1.2.0 published 2026-10-23 and used by 0.4 |
| O-4 | Prefix lookup structure | hash per length in use for the dynamic table; compiled Poptrie-style set for admin lists and the allow list; confirmed at 0.6 by measurement (D-085) | decided (D-085) |
| O-5 | Per-shard `Arc` or `&Bouncer` per call | per-shard `Arc` (shard holds the shared state, no cycle); confirmed at 0.6 by measurement (D-085) | decided (D-085) |
| O-6 | net-io hook shape | net-io's `Gate` trait with an associated ticket and the two additions, agreed with net-io 2026-10-23 | decided (D-015, D-055) |
| O-7 | Sharing across nodes | transport-agnostic mergeable deltas with HLC stamps, including revocations; gossip or a replicated log is the node core's choice | decided (D-017) |
| O-8 | Keyed hash | SipHash-1-3 under a random key, over two words for prefix keys; a multiply-mix waits for the table reseed (D-082) | decided (D-082) |
| O-9 | Snapshot integrity | keyed BLAKE3 MAC through crypt-io when a key is configured, CRC32C always | decided (D-018) |
| O-10 | Signal generator id | 2, held as `GENERATOR`; registered in the signals catalog when that module exists | decided (D-025) |
| O-11 | Default denial for revoked requests | `Forbidden`; `NotFound` per directive with `deny_with` | decided (D-026) |
| O-12 | `no_std` | not offered | decided (D-027) |
| O-13 | Default mode of local heuristics | observe by default, switchable per category and by strict posture (decided by James 2026-10-21) | decided (D-010) |
| O-14 | Request revocation on multiplexed connections | eject the connection by default; `keep_connection` for one request | decided (D-028) |
| O-15 | Name of the gates crate | bouncer only sees `Actor::Gate`; no API impact | decided (D-029) |
| O-16 | Publish 0.2.0 to crates.io (the name is free; nothing is published yet) | yes, approved by James 2026-10-23; every release since is published | decided |

---

## 16. Ideas parking lot

- **Kernel-level drop (Linux eBPF/XDP):** export banned prefixes to an XDP filter so their packets are dropped before they cost a system call (feature `kernel-export`, after 1.0).
- **Tarpit mode:** hold a confirmed scanner's connection open and feed it nothing, slowly, bounded.
- **Proof-of-work challenge:** a cheap-to-verify, costly-to-solve challenge before admission (`Verdict::Challenge`, `Challenger` trait, after 1.0).
- **ASN-level keys** once an address-to-network data source is chosen.

---

## 17. Decision log

| Id | Date | Decision | Reason |
|---|---|---|---|
| D-001 | 2026-10-13 | bouncer-io is the door plus in-flight revocation with wipe-and-eject, not a rate limiter | James's original intent; an earlier draft had drifted |
| D-002 | 2026-10-13 | Epoch-gated checkpoints: one atomic load when nothing is revoked | revocation must reach every in-flight request without slowing normal traffic |
| D-003 | 2026-10-13 | Egress enforcement lives in the transport's write path | no pipeline can skip the last checkpoint |
| D-004 | 2026-10-13 | A checkpoint before commit is part of the contract | a revoked request must not leave side effects |
| D-005 | 2026-10-13 | Responses are assembled in a zeroizing `Collected` buffer | wiping means overwriting, not dropping |
| D-006 | 2026-10-13 | Denials are generic and silent; the reason goes only to the audit trail | subjects are never told they were flagged |
| D-007 | 2026-10-13 | Bans by prefix with escalation (IPv4 /24, IPv6 /64 to /48) | address rotation inside a prefix is free for attackers |
| D-008 | 2026-10-13 | Template aligned with net-io and http-net (edition 2024, MSRV 1.85, `Apache-2.0 OR MIT`, `dev/` committed) | portfolio consistency |
| D-009 | 2026-10-22 | The crate's full specification replaces the 2026-10-13 plan; the roadmap follows the portfolio's version series (0.3 core, 0.4 extended, 0.5 feature complete, 0.6 optimisation, 0.7 hardening, 0.8 alpha, 0.9 beta) | one standard for every crate; the old split (0.3 door, 0.4 inside, 0.5 memory, 0.9 hardening) maps onto it without dropping anything |
| D-010 | 2026-10-22 | Local heuristics observe by default (O-13) | James decided 2026-10-21: detection on, enforcement off until a project enables it; the old plan's "thresholds trigger short automatic bans" is superseded |
| D-011 | 2026-10-22 | `door` returns `Result<Ticket, Refusal>` instead of a separate `Entry` enum | reads plainly (`let conn = bouncer.door(peer)?;`), works with `?` and `let else`; one fewer type |
| D-012 | 2026-10-22 | The request-path calls live on `Ticket`: `strike`, `deny_and_eject`, `bind_client` (which also covers the PROXY recheck, so there is no separate `recheck`). `deny_and_eject` takes only the buffer: the denial comes from the ticket, the formatter and ejector from the builder (`deny_and_eject_with` for a second protocol) | the simple-API rule: Tier 1 calls take one or two arguments and need no other object in hand |
| D-013 | 2026-10-22 | `lift` takes `impl Into<LiftSpec>`, symmetric with `ban`; Tier 1 calls act as `Actor::App`, a new actor for the application's own code | `bouncer.lift(addr)` is one line; audit records still name who acted, and `App` is not confused with a named administrator |
| D-014 | 2026-10-22 | Budgets take bouncer's own `Rate` type instead of re-exporting rate-net's `Quota` and better-bucket's `BucketConfig` | one type for callers to learn; a major release of either crate never forces one of bouncer |
| D-015 | 2026-10-22, revised 2026-10-23 | net-io hook: bouncer implements net-io's single `Gate` trait with an associated ticket (`ConnectionGate`), `closed()` returning the ticket and close reason, `Denial { code }` formatted by net-io's session, and `ServerHandle::kill` for ejection; bouncer asks net-io to keep an opaque `GateTag` in `Admitted` and `ConnectionInfo` and to add a per-response tag to `WriteCheck`. bouncer keeps `Ticket::tag`/`into_tag`, `Bouncer::request(tag, id)`, `Bouncer::egress(tag)`, `Bouncer::release(tag)` for transports that store only a number, and a latest-request link in connection cells | the ticket-in-hand check is one load per write; the close notice and kill by id are what releasing tickets and ejecting idle connections need; formatting in the session keeps protocol knowledge out of both crates; the tag lets protocol engines name a connection and judge multiplexed requests exactly |
| D-016 | 2026-10-22 | `Directive` is built by reading methods (`Directive::revoke_and_ban(session).by(Actor::Sentinel).because(Reason::DECOY).eject_now()`); `BanKeys` names which ticket keys a connection or request ban takes | readable directives; no struct literals with many fields |
| D-017 | 2026-10-22 | Shared records carry origin node, origin sequence, and a hybrid logical clock stamp; revocations are shared too; imports past `max_clock_skew` are refused; channels lift only their own node's bans | bans and revocations are state and must work across nodes (distributed by default); HLC makes merge independent of clocks agreeing; a logout on one node must stop the session's requests on every node |
| D-018 | 2026-10-22 | Persistence is a `Persistence` trait with `FilePersistence` always compiled; snapshot MAC with keyed BLAKE3 through crypt-io when a key is set (O-9) | state behind a trait (file, database, replicated store); tamper evidence for bans |
| D-019 | 2026-10-22 | O-1: rate-net and better-bucket with default features off, bouncer's own keyed table | no third-party crates; no rate math re-implemented |
| D-020 | 2026-10-22 | O-2: epoch owned by bouncer, injectable | simple standalone use; a security core can own the shared word |
| D-021 | 2026-10-22 | O-3: wipe through a public crypt-io `wipe` (crypt-io 1.2), bouncer keeps `forbid(unsafe_code)` | volatile writes need `unsafe`; crypt-io already has the helper privately and is the accepted cryptography exception |
| D-022 | 2026-10-22 | O-4: hash per length for dynamic bans, compiled Poptrie-style set for rare-change lists | best fit for each workload; benchmark at 0.6 |
| D-023 | 2026-10-22 | O-5: tickets hold a per-shard `Arc`; the shard holds `Arc<Shared>` | `request.checkpoint()` needs nothing passed in; reference-count traffic spread over shards; no cycle |
| D-024 | 2026-10-22 | O-8: keyed hash chosen at 0.6 by benchmark and the T-9 adversarial test | the API does not depend on it |
| D-025 | 2026-10-22 | O-10: generator id 2 as `GENERATOR` | platform range below 1000 |
| D-026 | 2026-10-22 | O-11: revoked requests deny with `Forbidden`; `Directive::deny_with(DenialCode::NotFound)` for routes that hide existence | unchanged intent of the earlier plan's 403-by-default |
| D-027 | 2026-10-22 | O-12: no `no_std` | no consumer; tables, time, files, threads need `std` |
| D-028 | 2026-10-22 | O-14: a request revocation ejects its connection unless `keep_connection` | James's intent is "eject the connection"; administrators can end one request on a multiplexed connection |
| D-029 | 2026-10-22 | O-15: gates appear only as `Actor::Gate` | no API impact from the crate name |
| D-030 | 2026-10-22 | Features are only `metrics` and `net-io`, both off by default. Persistence, sharing, and administration are always compiled; there is no `std` feature | distributed operation is the default, not an option, and costs no dependency; a feature that is always required is noise; a transport-free gate should not pull a transport by default (the spec suggested `net-io` on by default; serve-net and the gateway turn it on) |
| D-031 | 2026-10-22 | `Bouncer::health()` and `Bouncer::capacity()` added; a `checkpoint.missing` signal (id 14) reports revoked tickets that went `max_unchecked` without a checkpoint | enterprise operation needs health and capacity numbers; pipeline gaps must be visible |
| D-032 | 2026-10-22 | `Collected` keeps the spec's shape and adds `Default`; `Ejected` reports `wiped` as well | the caller can assert each step |
| D-033 | 2026-10-22 | A forwarded-header client is bound per request ticket; a PROXY-protocol client on the connection ticket. Requests under a trusted proxy hop with no client bound deny every checkpoint | a proxy can pool many clients over one connection; fail closed until the real client is known |
| D-034 | 2026-10-22 | `Verdict::Challenge` and `Action::Challenge` are left out until after 1.0 instead of being cfg-gated variants | the enums are non-exhaustive, so adding them later is not breaking; feature-gated variants break under feature unification |
| D-035 | 2026-10-22 | Posture: `strict_budget_divisor` (default 2) and `strict_revokes_unauthenticated` replace the spec's "refuses guests on admin listeners" | listeners are the transport's concept; net-io already refuses listeners not marked for lockdown |
| D-036 | 2026-10-23 | The dynamic ban table groups slots by eight with one tag word per group and probes groups with triangular steps (the SwissTable layout), instead of plain linear probing | at 7/8 load, linear probing averages about 32 probes on a miss and its tail runs to hundreds of slots, which broke the 32-probe bound in the first fill test; with tags a miss reads only tag words (1 byte per slot, contiguous) and the bound holds |
| D-037 | 2026-10-23 | The compiled set is a six-bit-stride multibit trie with popcount masks and per-slot chains (Poptrie style), built at 0.3 instead of a per-length sorted array | the per-length layout cost one probe per distinct length, about 100 for a realistic IPv6 administrator list, and measured several times the door budget; the trie's cost does not depend on the number of lengths |
| D-038 | 2026-10-23 | Tables hash with SipHash-1-3 under a per-bouncer random key until O-8 is decided at 0.6; rebuilding a table with a fresh seed when the probe bound is reached moves to 0.6 | a keyed PRF means colliding keys can only be chosen by someone who knows the key (the T-9 test floods a known-key table and shows the same keys fit under a random key); a rebuild needs a lock-free whole-table swap, which belongs with the hash decision; until then an insert past the bound fails cleanly as `BanTableFull` |
| D-039 | 2026-10-23 | All ticket cells live in one array in the shared state, partitioned into shards by index range with one free list each; tickets hold a small per-shard handle; `TicketId` and `TicketTag` are `index (32) | generation (32)` | requests could otherwise be refused while other shards had room (found by the proxy test with many shards); the per-shard handle keeps reference-count traffic spread out |
| D-040 | 2026-10-23 | The loom models build under `--cfg bouncer_loom`, not `--cfg loom` | a global `--cfg loom` also reaches dependencies, and the published clock-lib 1.1.0 then fails to build |
| D-041 | 2026-10-23 | Administrator prefixes at non-automatic lengths are kept in a list and the compiled set is rebuilt on every change (about a millisecond with 10,000 prefixes); bulk loading arrives with persistence and import at 0.5 | administrator changes are rare and cold; the readers never wait |
| D-042 | 2026-10-23 | If a ban slot on the probe path is being rewritten for longer than the spin bound, the door refuses with `Refusal::Banned` and a reference of zero | fail closed; a writer holds a slot for a handful of stores, so this happens only if the writer thread is descheduled mid-write |
| D-043 | 2026-10-23 | `BanRecord.actor` is an `ActorKind`; the full `Actor` (with its id) goes to events | compact records: the ban entry keeps four bits for the actor |
| D-044 | 2026-10-23 | A ticket that revokes itself (its own failed `bind_client`, or finding its connection gone) forces its own slow path from then on | such a revocation does not move the epoch, so the fast path alone would have passed it |
| D-045 | 2026-10-23 | `#[must_use]` stays on `Verdict` and `Ticket` only; receipts (`Revocation`, `Applied`, `Lifted`, `Ejected`, `StrikeOutcome`, `MaintenanceReport`) drop it | ignoring a verdict is the bug this crate prevents; ignoring a receipt is not, and with the attribute the Tier 1 line `bouncer.revoke(session, Reason::LOGOUT)?;` warned |
| D-046 | 2026-10-23 | A ban directive below confidence 30 is applied as a throttle and reported in `Applied::downgraded` instead of failing with `LowConfidence` (the variant is removed) | the caller still gets a defence and a clear record; an error would drop the signal entirely |
| D-047 | 2026-10-23 | A revocation's birth is taken and the epoch moved under the revocation writer lock | with births taken outside the lock, two concurrent revokers could share a birth and cleanup could remove an entry a ticket had not checked yet |
| D-048 | 2026-10-23 | Idle tickets are found by sampling (epoch, time) at each maintenance run: a live ticket whose last check is at or before an epoch sampled `max_unchecked` ago is checked on its behalf | cells have no room for a time stamp; the samples cost one small queue per bouncer |
| D-049 | 2026-10-23 | Strike counters, door budget cells, and throttles live in a lock-free claim table keyed by a 64-bit keyed hash (no stored key); a slot is taken over only when its payload is idle (an expired window, a recovered budget with no connections) | the strike and door paths stay lock-free and allocation-free; a 64-bit keyed hash makes a counting collision negligible, and the action uses the ticket's real keys |
| D-050 | 2026-10-23 | Door budgets key an IPv4 client at /32 with its /24 prefix, and an IPv6 client at /64 with its /48 prefix | FR-4 (one host controls its /64); the spec's "/24 or /64" prefix line conflicted with FR-4 for IPv6 |
| D-051 | 2026-10-23 | A request revoked by a session, account, tenant, or fingerprint revocation takes its connection with it unless the revocation keeps it; a request revoked with `keep_connection` carries a flag so `deny_and_eject` formats the denial without ejecting | James's intent is "eject the connection"; administrators can end one request on a multiplexed connection |
| D-052 | 2026-10-23 | Throttle directives take source targets only at 0.4; identity throttles arrive with lane and tenant budgets at 0.5 (`InvalidTarget` meanwhile) | an identity throttle needs the identity budgets to act on |
| D-053 | 2026-10-23 | `Posture` exists as a type from 0.4 (`Enforcement::mode` takes it); `set_posture` and its effects arrive at 0.5 | the enforcement API is final now; the posture switch belongs with the rest of 0.5 |
| D-054 | 2026-10-23 | The revocation rate limit reports a storm but still applies every revocation | revocations are security actions; dropping some to save checkpoint time would let an attacker hide in the storm |
| D-055 | 2026-10-23 | The net-io hook is net-io's `Gate` trait with the two additions agreed by net-io (D-018, D-051 there): `GateTag` in `Admitted` and `ConnectionInfo`, `Output::begin_tagged_response` and `WriteCheck::response` | confirmed by the net-io session; closes O-6 |
| D-056 | 2026-10-23 | `Collected` keeps a zero-initialized fixed block and a length instead of a `Vec`'s spare capacity | in-place writes (`spare`) need initialized memory without `unsafe`; growth stays allocate, copy, wipe |
| D-057 | 2026-10-23 | A lane or tenant budget refusal revokes the ticket with `TooManyRequests`; a request keeps its connection, so the denial is an ordinary 429. Allow-listed sources skip lane and tenant budgets | the pipeline stops the request at its next checkpoint without killing a keep-alive connection; cost one claim probe per bind (about 20 ns [est.]) |
| D-058 | 2026-10-23 | The lane key is the session when bound, else the client (IPv4 address, IPv6 /64). The cost of one charge is the largest throttle factor on the source, session, account, tenant, or fingerprint. An identity throttle acts where an identity budget exists (a lane or the tenant rate) | one throttle on an account slows every session of it; with no identity budget configured there is nothing to divide |
| D-059 | 2026-10-23 | Tenant rates use better-bucket's `BucketCore` (64 B per tenant, caller time, no default features). Planned tenants sit in a sorted table built once; other tenants share the keyed table under the default rate. In-flight slots are returned on release through a cell flag | a plan never competes for a keyed slot; no dependency enters (better-bucket without features has none) |
| D-060 | 2026-10-23 | `Posture::Strict` makes each door admission cost `strict_budget_divisor` tokens and shrinks door concurrency limits by it. `strict_revokes_unauthenticated` revokes request tickets with no session, not connections | revoking connections would also end authenticated users' keep-alive connections; a request without a session is the unauthenticated work |
| D-061 | 2026-10-23 | The allow list is a published value: a lock-protected `Arc` plus a version word, read through a per-thread copy. `replace_allow` swaps first, then lifts address, prefix, and compound bans inside new immune entries | readers never wait; the door pays one atomic load and a thread-local lookup (2 to 3 ns [est.]); a ban racing the swap is checked against the new list |
| D-062 | 2026-10-23 | Compound fingerprint keys (stored as keyed digests) keep their originals beside the table, by digest | listings, persistence, and sharing restore the real key; about 50 B per compound ban |
| D-063 | 2026-10-23 | Escalation is tracked under the ban writer lock. A parent is refused when an allow entry, a trusted proxy, or a shared-flagged address overlaps it (sorted span lists beside the compiled sets, 24 B per prefix); a refusal is a `ban.escalated` event in observe mode. Lifted children stop counting; evicted or expired children still count | no cost at the door; an attack that was banned and expired still happened, a lifted ban was a mistake |
| D-064 | 2026-10-23 | An automated ban that a wider, longer ban already covers is not stored; an explicit ban (administrator, application, gate, sentinel) is stored anyway | keeps the table compact under a flood (T-4); lifting the prefix later keeps the administrator's address ban |
| D-065 | 2026-10-23 | Offender memory is a map inside the writer lock, sized at build to a quarter of `ban_capacity` (at least 1,024; about 10 MiB at the default). It decays with `DurationPolicy::half_life` (default 24 h); offences are the decayed score rounded. Once a ban has expired, only offender memory sets the next ban's length | the decay the spec asks for (FR-22) replaces the expired entry's count, which never decayed |
| D-066 | 2026-10-23 | Shared-address detection keeps a 64-bit bitmap of hashed identities per client for an hour and flags more than 16 bits for 24 hours (constants at 0.5). Enforced local thresholds on a shared address throttle it and ban the session and account (`StrikeOutcome::Throttled`). Local, channel, and policy (confidence under 70) bans of a shared address become throttles; escalation stops there | one `fetch_or` per identity bind; punishing a NAT punishes everyone behind it (T-5) |
| D-067 | 2026-10-23 | `datagram` charges an unverified source only at its prefix rate, never its client rate, and never strikes it | a forged UDP source cannot spend a real client's budget or get it banned (T-20) |
| D-068 | 2026-10-23 | One record format (length, body, CRC32C) serves the snapshot, the journal, and deltas. The snapshot's keyed BLAKE3 MAC covers all of it; each journal batch's MAC covers the previous MAC and the batch, so batches cannot be dropped, reordered, or spliced without the key. Batches carry the snapshot epoch; a damaged tail found at load starts a new snapshot | one decoder to fuzz; a crash during compaction leaves old batches that are skipped, never applied twice; new appends are never hidden behind garbage |
| D-069 | 2026-10-23 | A MAC on one side only (key without MAC, or MAC without key) fails as `Mac` | no downgrade from MAC to CRC by deleting the trailer |
| D-070 | 2026-10-23 | Persisted bans store wall times and their original length. On load the remaining time is `until - now`, never more than the original length; a clock stepped back past the issue time keeps the original length from now; `strict_wall_jump` counts from the last save across a forward jump past `max_wall_jump` | a clock step can neither lengthen, resurrect, nor (with strict) shorten a ban (T-19) |
| D-071 | 2026-10-23 | Stamps are hybrid logical clock values (Unix milliseconds in the top 48 bits, a counter in the low 16). A ban is compared with a lift by its issue time at one-second resolution; a merged ban keeps the later issue time | a lift removes only bans issued before it, whatever the delivery order (edge case 64) |
| D-072 | 2026-10-23 | Imports skip records seen before by (origin, sequence), remembering a million; full exports are merged without that check (merges are idempotent). Channels may import 100,000 records per second. Refusals of single records (allow list, clock skew, foreign lift) are counted in `rejected` and reported; refusals of a whole delta are errors | duplicates never re-run a revocation; a hostile peer is bounded (T-17) |
| D-073 | 2026-10-23 | Revocations travel between nodes, except those of connection and request ids (their meaning is local). Revocations are never persisted | logging out on one node stops the session everywhere; after a restart nothing is running to revoke |
| D-074 | 2026-10-23 | With the `metrics` feature, counters live per shard on their own cache line; fast checkpoints are counted in the ticket handle and added at its next slow path and when it is dropped | the one-load fast path stays one load |
| D-075 | 2026-10-23 | Events take their wall time from the bouncer's clock | `ManualClock` tests control it; one clock for everything |
| D-076 | 2026-10-23 | New signals 5 `bouncer.budget.refused`, 15 `bouncer.posture.changed`, 52 `bouncer.persist.wall_jump`; new reasons `LOCKDOWN` (11) and `BUDGET` (12) | each new action reports, per FR-19 |
| D-077 | 2026-10-23 | Bans evicted, folded, or lifted by the allow list are journaled as removals | after a restart they stay gone (edge case 51) |
| D-078 | 2026-10-23 | The kill test runs 12 rounds in CI on Linux, macOS, and Windows, and 1,000 rounds (`BOUNCER_KILL_ROUNDS=1000`) before a release | CI time stays reasonable; the release gate keeps the spec's number |
| D-079 | 2026-10-26 | The escalation tracker evicts the parent noted longest ago through an insertion-order queue (amortized constant time); it never scans when full | found while measuring for 0.6: with 65,536 parents tracked, each new parent scanned all of them, so a ban took about 270 µs under the writer lock; now about 1.4 µs [measured, shared machine] |
| D-080 | 2026-10-26 | RUSTSEC-2026-0385 (ctutils 0.4.2) is ignored in `.cargo/audit.toml`, and CI fails if ctutils ever enters the compiled graph | ctutils comes only through crypt-io's optional `hmac` and `sha2` features, which bouncer does not enable (`cargo deny`, feature-aware, passes); the fix needs Rust 1.87, above the 1.85 MSRV. crypt-io users who enable those features on Rust below 1.87 are exposed: raised with crypt-io |
| D-081 | 2026-10-26 | NFR-10 compares the door with the same-job composition (ban lookup, rate check, revocable per-connection handle, allow list, trusted proxies) and targets 20% faster than it; the lookup-only numbers stay published, labelled. Decided by James | the lookup-only composition does less than the door: it has no ticket that can be revoked in flight, no allow list, no trusted proxies. Measured at the start of 0.6: door 157 ns admitted and 204 ns random, same-job 112 and 138, lookup-only 50 and 74; the target is about 90 and 110 ns |
| D-082 | 2026-10-26 | O-8 closed: tables keep SipHash-1-3 under a random key, over two words for prefix keys (one word is always zero) and three for the rest; a keyed multiply-mix is not adopted | the multiply-mix is safe only with the table reseed at the probe bound (T-9), which is not built; measured, the hash is about 6 ns of the 12 ns per probe, and computing each hash once (D-083) recovers more than the mix would |
| D-083 | 2026-10-26 | The door computes each prefix's keyed hash once per check and shares it between the ban lookup and the door budgets: the budgets use the ban table's key and encoding. The budget step hashes nothing when no budget is configured | two to three SipHashes saved per door; one key now serves both tables, whose collisions an attacker cannot choose without it |
| D-084 | 2026-10-26 | Ticket path: a connection's latest request lives in its own word (`K_LATEST`, the unused request-key slot), written with a plain store and not cleared on release (the egress check verifies it); release reads the present bits with a load; door-generated connection ids are the cell's index and generation; connections are marked as holding concurrency slots only when there are some | four fewer atomic read-modify-writes per request cycle and one per connection; ticket issue and release 84.5 -> 45.0 ns [measured, pinned] |
| D-085 | 2026-10-26 | O-4 confirmed (a hash per automatic length plus a compiled set) and O-5 confirmed (a per-shard `Arc` in each ticket): measured, each probe costs about 12 ns warm and the `Arc` count about 8 to 10 ns of a ticket; the alternatives (one structure for a family's automatic lengths; a lifetime on `Ticket`) are the next levers and are planned in ROADMAP, not built at 0.6 | the second would break the API every transport uses |
| D-086 | 2026-10-26 | A bind reads the clock only when a ban of its kind may exist; shared-address detection counts with the door's latest whole second (`seen_secs`) and a multiply-mix of the identity words instead of a second clock read and a SipHash | bind about 76 -> 24 ns; the detector's windows are an hour, so a time as old as the latest door check is enough |
| D-087 | 2026-10-26 | Offender memory evicts, of the two records noted longest ago, the one with the lower decayed score (compared by `log2(score) + last / half_life`, the log approximated from the float's bits); lift tombstones evict the oldest through an insertion-order queue | the full-map scan made ban inserts slow down without bound once offender memory was full (median 3.5 µs at 1.2 million bans; now 457 ns) |
| D-088 | 2026-10-26 | Performance is measured pinned to one logical core (fastest of 61 rounds); regressions are gated by Callgrind instruction counts in CI (5% limit, `benches/gate.rs`, `scripts/gate.py`) | unpinned runs on this CPU move between its two core complexes and swing by 30% or more; pinned runs agree within a few percent; instruction counts repeat exactly |
| D-089 | 2026-10-26 | `#[track_caller]` on a checkpoint wrapper costs nothing measurable (0.73 ns with and without); using it to report where a denied checkpoint was called is left for 0.7 hardening | measured as the 0.2 defence idea asked; adopting it is an API choice |
| D-090 | 2026-10-26 | The comparison gives bouncer's budget tables as many keys as the run uses | the composition's map grows without bound; bouncer's tables are fixed at build, and a full table takes the evict-an-idle-slot path, which is not the comparison's subject |
| D-091 | 2026-10-26 | CI runs on a pull request are grouped by branch; a new push cancels the older run. Pushes to main all run to the end | stacked runs on one branch competed for runners and delayed the result that matters (the branch head); main keeps a complete record per commit |
| D-092 | 2026-10-26 | Unverified datagrams are charged at their prefix under a key of their own (derived from the prefix's keyed hash), not the prefix key real sources use. Found by the 0.7 review, fixed test-first | before, forged datagrams naming a victim's /24 (or /48) drained the prefix budget shared with that prefix's connections and verified datagrams, so forged UDP could get the victim's TCP connections refused (`test_datagram_forged_flood_does_not_starve_verified_sources`). Cost: one rotate and xor per unverified datagram, and one more claims slot per prefix under forged traffic |
| D-093 | 2026-10-26 | T-8 is tested on what a client cannot already learn from the verdict: admitted latency against neighbours' ban state, and bind latency for digests near a banned one; Kolmogorov-Smirnov at p < 0.01 over interleaved batch means, three measurements, failing when two or more separate; a control pair (banned against admitted) must separate. Refusal reasons are not equalised in time, and the network-level check (the same abortive close after the decision) moves to 0.8 with the net-io feature | the reason of a refusal is visible by behaviour (a banned client is refused every time, an over-budget one only above its rate), so equal refusal timing would cost the refusal path work and hide nothing; what timing could leak is ban state the verdict does not show. A shared machine makes about one run in six separate by chance at p < 0.01; a real difference separates every time. Measured: D 0.002 to 0.023 against a critical 0.036; the control 0.37 to 0.68 |
| D-094 | 2026-10-26 | Full budget tables: an admission whose prefix finds no slot is charged to one global cell at the prefix rate (the design of 7.9, which 0.3 to 0.6 did not build); the door's concurrency tables hold at least twice the ticket capacity; `Health::budget_load` counts slots holding a key that has not recovered. Found by the 0.7 review, fixed test-first | before, once both rate tiers were full of keys still limiting (frozen time, or a flood of new /48s), every newcomer was admitted uncharged (`test_full_budget_tables_charge_the_global_cell`: 1,000 of 1,000); a concurrency table smaller than the registry let held connections fill it and lifted the per-address limit (`test_concurrency_limits_hold_with_every_ticket_in_use`); and `budget_load` counted claimed slots, which reach 1 in normal use with many clients because recovered keys are reclaimed only on demand, so `is_ok` was false for a healthy bouncer (seen in the soak). Costs: the global cell is one more GCRA, touched only past a full table (contended then, which is the point: newcomers share one budget); concurrency tables at the default 65,536 tickets grow from 65,536 to 131,072 slots per tier (+1.5 MiB); `health` scans the budget tables, 0.85 ms at the default sizes (measured) |
| D-095 | 2026-10-26 | The decoder fuzz targets frame part of their inputs: valid magic, lengths, and CRC32C around fuzzed contents (MAC off), beside the raw inputs | raw inputs stop at the checksum: `delta_decode` reached 53 coverage points in 15 minutes; framed, 858 in 60 seconds, and the snapshot and journal targets passed in a minute what the raw targets reached in fifteen. The MAC path keeps its raw inputs (a forged MAC must be refused, which raw inputs test) |
| D-096 | 2026-10-26 | Sharing keeps each origin's ban per key apart (a ledger beside the ban table, on nodes with a node id), with its stamp; lifts are scoped to one origin or to every origin (an administrator's or the application's lift), and a node channel carries only its own node's lifts, which reach only its own bans; a trusted delivery (`Actor::Admin`, `Actor::App`) applies an administrator's lift to every origin. Escalation folds a node's own children with own-origin lifts. Record format 2 (a lift record with its scope); format 1 is read, legacy lifts as lifts of every origin, and a format-1 snapshot is rewritten as format 2 on load. Found by the 0.7 three-node simulation, fixed test-first | before, a lift was ordered against the held ban's local issue time in whole seconds (clamped to the node's start), and one merged entry per key could not apply "a channel lifts only its own node's bans" in an order-independent way: the simulation diverged within 15 steps. Each rule is now a per-origin last-writer-wins register (proved order-independent by `ledger::tests::test_ledger_order_never_matters` and the simulation over 5,000 seeds, partitions, a clock 30 seconds ahead, reordering, duplication). Two more order dependences found on the way: equal stamps from two nodes (a lift now covers a ban stamped at or before it in both directions), and the dedupe skipping an administrator's lift already seen over a node channel. Cost: on sharing nodes 151 bytes per ban held (measured, 100,000 bans: a 48-byte key, two short lists, one 40-byte entry per origin), counted in `capacity().total_bytes`; keying the ledger by the 24-byte table key would save about 27 bytes; the hot path is unchanged (the door reads the ban table only) |
| D-097 | 2026-10-26 | A proxied request still waiting for its client is reported (`door.proxy_hop_unresolved`) by the first maintenance run at least `max_unchecked` after a run first saw it, or at its release if that comes first; never twice. Edge case 22 | the handshake deadline needs a time anchor, and tickets carry no issue time (the door reads no clock for them); a timer per proxied request would cost an atomic pair on every proxied request, against NFR "no wake-ups with nothing pending". The maintenance run already scans the registry: one more check per cell, a map entry per pending request (rare: adapters bind the client at once). A request hung with no maintenance due is reported at its release |
| D-098 | 2026-10-26 | Sampled signals (door refusals by ban, budget, and full registry; identity budget refusals; expiries) reach the sink at most 100 times a second each; each event's `count` carries the occurrences it stands for. Edge case 71 | the catalog documented them as sampled since 0.4, but every occurrence called the sink: under a flood of banned sources, one sink call per refusal, and a slow sink slowed the refusal path. Cost: two relaxed atomics per sampled occurrence (and one clock read, which the event needed anyway); found by the edge-case audit |
| D-099 | 2026-10-26 | An enforced strike threshold whose ban cannot be stored (the table full of bans it may not evict) still revokes the ticket and its connection: `StrikeOutcome::RevokedNotBanned`, with `ban.table_full` reported. A revoked ticket's code rises when a stronger revocation matches it later (precedence, as `DenialCode` documents). Edge cases 48 and 30 | before, the striking peer carried on unbanned and unrevoked once the table was full; and a second, stronger revocation was recorded but the ticket kept reporting the first code. Cost: none on live tickets; a revocation-table look on checkpoints of tickets already denied |
| D-100 | 2026-10-26 | The revocation epoch never takes the value `u64::MAX` (the mark of tickets that check at every checkpoint): `bump` is a compare-and-swap that steps from `u64::MAX - 1` to 0. Edge case 34 | starting the epoch at `u64::MAX - 2` showed a self-revoked ticket would pass the fast path while the epoch equalled its mark. Unreachable in practice (2^64 moves), but the edge case asks for it, and a compare-and-swap on the revocation path costs a few nanoseconds there and nothing on checkpoints |
| D-101 | 2026-10-26 | Fixes from the 0.7 adversarial review, each with its test: a node channel carries only its own node's records (another origin, or origin 0, is refused before it is remembered as seen; records are no longer relayed; full exports carry only the node's own bans); a record is remembered as seen only when it was not refused; sequence numbers and log positions start from the node's persisted clock, and a log that does not hold all this node exported answers a peer behind it with a snapshot; a ban an import evicts leaves the ledger; one key holds at most 64 origins; a channel's ban is held to its actor's placement rules and never covers a whole address family; a request issued while its connection is released or revoked is revoked (fence and recheck, loom model L-7); revoking a connection from a request moves the epoch. Persistence rollback by someone who can write the state files is documented as not covered | the review found that a hostile node could forge another node's records (shorten or erase its bans, pin bans it could not lift, poison the seen-set), that a restart made peers drop the node's new records, that evictions grew the ledger without bound, that origins per key were unbounded, that imported bans skipped the placement rules, and two ticket races (a request outliving its connection on the fast path; a connection revoked from a request while its siblings kept passing). Costs: none on the door or checkpoints; a fence and a load per request issue (about 1 ns); nodes exchange deltas with every other node, since nothing is relayed |
| D-102 | 2026-10-26 | The ban table hashes with a keyed multiply mix (two folded 64-by-64-bit multiplies under the per-bouncer random key) instead of SipHash-1-3, and is rebuilt under a fresh key when an insert reaches the probe bound while the table has room (T-9; `table.reseeded`). Readers reach the table through a handle with a per-thread copy and one version word, so a rebuild never makes them wait. The door budgets hash under a key of their own, so a reseed cannot reset them. References and stored digests keep SipHash | NFR-10 (0.8 plan): SipHash cost about half of each probe. A/B on one core (0.7 base against this): judgement with 1,000,000 bans -27%, `door_at` admitted -11%, banned -11%. The multiply mix is not a proven pseudo-random function, so the probe bound and the rebuild are the defence if keys ever pile up (an attacker still needs the key to choose collisions); a rebuild costs one pass over the table and a second table's memory while it runs (writer side, under the writer lock) |
| D-103 | 2026-10-26 | Connection release keeps its swap of the link word (the plan's "release without the link swap" is dropped) | the swap orders the release against a request counting itself: both read-modify-write one word. A plain load and store fails loom model L-7 (a request issued during the release kept passing on its fast path); making it correct needs a sequentially consistent fence, which on x86 costs more than the locked exchange it would replace |
| D-104 | 2026-10-26 | Address keys at or past their family's shortest automatic length (the anchor: /24, /48 by default) live in the anchor's probe sequence, each with the tag of its own hash; a door lookup loads one group's tag word for all of an address's lengths. A key that does not fit its anchor's sequence (a prefix with many banned hosts) lives in its own sequence and sets the anchor group's overflow bit, which sends lookups there too. Reseeds keep the anchors | NFR-10: the door probed one group per length in use (two for IPv4, three for IPv6), each a cache miss for unknown peers. Probe chains are unchanged (1.86 groups per miss at the fixture's load, with or without anchors). A/B on one core: `door_at` random peers -15%, admitted -8.5% (with D-102). Cost: an overflow bitmap of one bit per group (20 KB at 1,000,000 bans); a crowded prefix's lookups probe the spilled lengths a second time. Reseeding cannot spread a crowded prefix (its keys share an anchor under any key), so overflow, not reseed, handles it |
| D-105 | 2026-10-26 | Ban table slots are 32 bytes (four words, two slots per cache line, aligned so none straddles a line): the meta word carries the slot's sequence-lock version in its low 19 bits beside a one-byte code (kind and prefix length), flags, actor, reason, and offences. A key that fits one word (IPv4, IPv6 at /64 or shorter, tenant, connection) is stored exactly; a longer one (session, account, fingerprint, compound fingerprint, request, IPv6 past /64) is stored as a 64-bit SipHash-1-3 fingerprint under a key derived from the table's hash key. The ban table's writer keeps each long key's original in a map beside the table for listings, persistence, and sharing, and an insert whose fingerprint equals a stored key's is refused and rebuilds the table under a fresh key (as at the probe bound). The revocation table keeps no originals: it needs only each key's kind and length, which the code carries | NFR-6 and NFR-10: slots were 48 bytes with a separate 64-bit version word and two key words. A/B on one core against the previous 0.8 commit (10 alternating runs, fastest of each): memory per ban 56.0 -> 37.7 B (NFR-6's 48 B target met); account revocation 136 -> 109 ns; ban insert +4%; the door's rows within the run's noise (+1 to +3% admitted, random peers flat, while the composition rows, which run none of this code, moved -2.5 to +1%). Smaller slots do not speed a miss, which reads tag words only. Limits: a reader that stalls between its two meta loads while one slot is rewritten 2^18 times and ends with the same meta could keep a torn read (the 64-bit version ruled this out); slot writes run under the writer lock, so this needs a stall of tens of milliseconds inside a few-instruction window during a write storm on one slot. A long key that is not stored but shares a stored key's fingerprint reads as banned (about 2^-64 per stored long key per lookup; choosing one needs the table key and a second preimage); in the revocation table two such keys share one entry, which over-revokes and never under-revokes. The originals cost about 48 B per long ban (counted in `table_bytes`); a long-key lookup computes one SipHash, out of line and only once a slot's tag matches |
| D-106 | 2026-10-28 | Keyed budget slots carry their payload beside the key word (`Claims<P>`): a rate key holds only its GCRA arrival time, under parameters shared by the tier (`Pace`, rate-net's integer math, checked against `rate_net::Gcra` on 120,000 random checks), and a concurrency key its count. Token buckets, strike windows, and the source detector keep parallel arrays | NFR-10: a rate tier kept its key words in one array and a whole 80-byte `Gcra` per key in another, so an unknown peer missed the cache twice per tier, four times for the two door tiers. Now once per tier, and a rate key costs 16 bytes instead of 88. A/B on one core against the 0.8 head (8 alternating runs, the machine under full load from other work, so relative only): `door_at` random peers -13%, `door` random peers -18%, `door_at` admitted -13%, account revocation -17%; the composition rows moved -4 to +6%. Cost: the GCRA math was a second copy of rate-net's, pinned to it by a differential test, until rate-net 2.1's shared-parameter API replaced it (D-110). A slot with a payload relies on the allocator's 16-byte alignment to stay within one cache line (speed only) |
| D-107 | 2026-10-28 | The net-io gate (feature `net-io`, net-io 0.3): `admit` is `door_at` with net-io's connection id and accept time and refuses every reason with one reset code (`REFUSED`); a peer with no IP address enters as 127.0.0.1 with `Provenance::Local`; `readmit` binds the PROXY header's client with `Provenance::ProxyProtocol`; `check` is the egress check by tag (the session's response tag, else the connection, which also covers its latest request); `closed` turns slow-peer, PROXY, and TLS failures into strikes and releases the ticket. `NetIoEjector` is attached to the server after both are built (the bouncer takes its ejector at build, the server takes the bouncer as its gate) | the design-lock shape kept the last-seen epoch in the ticket for a one-load check, but a connection ticket's own epoch does not cover its latest request, which the egress check must; the egress check by tag does, measured at 1.3 ns. Accept times convert through the bouncer's clock base, so a bouncer under net-io uses the system clock. Unix-socket and pipe peers share one source: banning 127.0.0.1 refuses them all, which is what a local peer is. net-io 0.3 parses no PROXY header yet, so `readmit` is tested by calling the gate |
| D-108 | 2026-10-28 | A source's strikes also count at its widest escalation prefix (IPv4 /24, IPv6 /48 by default), against the kind's threshold times the strikes escalation would need to get there (each level's fan-in multiplied: 8 for IPv4, 4 x 4 for IPv6, so 40 and 80 at the default threshold of 5). Reaching it bans the prefix as escalation would: not with escalation off, not over an address flagged as shared, and the ban itself refuses allow-list entries and trusted proxies. Found by the 0.8 replay harness, fixed test-first | credential stuffing that moves to a new /64 for every attempt kept every /64 counter at one: 6,000 attempts from one /48 in ten minutes and no ban (escalation counts banned children, and no child was ever banned). Now the /48 is banned after exactly 80 attempts, what escalation needs when the attacker does not rotate. Cost: one more counter update per strike (strikes are off the door's path) and one counter slot per prefix and kind; a /24 or /48 with 40 or 80 strikes of one kind in a window is banned even when the strikes came from many people behind different addresses, which is the case escalation already accepts |
| D-109 | 2026-10-28 | A door budget's address tier gives way for an address flagged as shared (likely a NAT): over the address limit, it is charged to its prefix tier only, throttled or not. The flag is read only when the address tier would refuse. Found by the 0.8 replay harness, fixed test-first | 2,000 people behind one carrier-grade NAT address at 100 connections a second against the default 20 per address: 80% refused. With the relief, none; the attacker among them still loses its session and account (T-5). A throttled shared address gives way too: otherwise one person behind a NAT could get everyone behind it refused with five failed logins (the replay showed 92% refused). Cost: an attacker who binds more than 16 identities from one address in an hour is held to the prefix budget (200 a second and 512 concurrent by default) instead of 20 and 64; the flag already stopped bans of that address. Nothing on the door's fast path |
| D-110 | 2026-10-28 | The door and lane rate tiers use rate-net 2.1's `GcraParams` over each slot's arrival-time word, in place of bouncer's own copy of the GCRA math (`Pace`, D-106); rate-net's own differential test against its 2.0.1 code pins the math | one copy of the math, maintained where the algorithm lives; the decisions are the same (bouncer's copy had matched `rate_net::Gcra` on all 120,000 checks of its differential test). The arrival-time word is a plain atomic (no loom model reaches the budgets). rate-net 2.1 also brought new-key inserts at a full store back to 1.1.0's cost |
