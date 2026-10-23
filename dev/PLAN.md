# bouncer-io - Project Plan

> The design, strategy, and decision record for `bouncer-io`. A living document: every design decision, idea, or open question about bouncer-io is written here or in [`ROADMAP.md`](./ROADMAP.md) before it is acted on. The public API is locked in [`../docs/API.md`](../docs/API.md).
>
> **Read order:** [`../REPS.md`](../REPS.md) &rarr; [`DIRECTIVES.md`](./DIRECTIVES.md) &rarr; **this file** &rarr; [`ROADMAP.md`](./ROADMAP.md) &rarr; [`../docs/API.md`](../docs/API.md).
>
> **Status:** `0.2.0` design lock. Rewritten on 2026-10-22 from the crate's full specification; where the 2026-10-13 plan differed, the specification won and the change is in the decision log (D-009 onward).

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
| B6b transport egress | net-io before every socket write, per chunk when streaming | connection or response ticket | two atomic loads |

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
| NFR-10 | At least 20% faster than the best Rust composition for the same job at equal or stronger security, measured and published. | `benches/comparison.rs` |
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

The handle callers hold: `Ticket { shard: Arc<Shard>, index: u32, generation: u32, seen: u64, kind }`. A `Shard` holds `Arc<Shared>` (epoch, tables, configuration, sink, ejector), so there is no reference cycle and reference-count traffic is spread over shards (O-5).

- **Issue:** pop from the shard's free list, a Treiber stack whose head packs `index (32) | tag (32)`; the tag changes on every pop and push, so no ABA. Lock-free; loom L-2.
- **Shard choice:** a thread-local hint (the worker index, or a hash of the thread id). Request tickets are issued from their connection's shard.
- **Release:** `Drop` clears `LIVE`, advances the generation, clears `present`, returns budget slots, pushes the index. Dropping a connection ticket while its requests are live marks them `REVOKED` with reason `CONNECTION_CLOSED`. Release on any thread is allowed.
- **Generation wrap:** a cell whose generation reaches `u32::MAX` is retired, never reused.
- **Tags:** `TicketTag` packs shard, index, and generation into 64 bits (net-io's `GateTag`). `into_tag` marks the cell `DETACHED` and gives up the handle; `Bouncer::release(tag)` releases it. Stale tags fail closed.
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

**Dynamic table.** One open-addressing table per (family, length) sharing one entry arena; a 128-bit mask per family records which lengths hold entries, so a lookup probes only those (typically 2 for IPv4, 3 for IPv6). Keys up to /64 stored in 8 bytes. Versioned slots for lock-free reads; one writer lock per family. Expired entries read as absent. Probe length bounded at 32; exceeding it rebuilds with a fresh seed and an event (T-9).

**Compiled set.** A multibit trie with population-count bitmaps in the style of Poptrie (Asai and Ohara, SIGCOMM 2015), built off the hot path and published by swapping an `Arc` behind a version word, with per-shard reader caches.

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
- **Merge** (commutative, associative, idempotent): records keyed by `(origin, sequence)`; for one key the effective ban has the latest end (permanent wins); a lift removes bans stamped before it; a later ban wins over a lift. Revocations are applied to local running requests and kept only while they can match a live ticket.
- Stamps more than `max_clock_skew` (5 minutes) ahead are refused (`ClockSkew`).
- Each node enforces locally; a partitioned node keeps protecting itself and converges on reconnect.
- Authentication of deltas is the transport's job (mutual TLS on node links or the back-channel). Imports from `Actor::Channel` are rate limited, never touch the allow list, and can lift only bans that originated on that channel's node.
- Works over gossip-style exchange or a replicated log; the choice belongs to the node core, not to bouncer (O-7).

### 7.14 Events and metrics

Every action emits an `Event` (fixed size, borrowed evidence, no allocation) to the sink. Refusals are sampled per ban per 10 s with exact counts. Generator id 2 (below 1000, the platform range); the catalog is in `docs/API.md` and its ids never change meaning. Categories and the severity, confidence, and risk axes follow the security signals vocabulary. Metrics (feature `metrics`) are per-shard relaxed counters on the shard's own line, summed on read.

### 7.15 Maintenance without idle CPU

Sweeps, revocation cleanup, idle-ticket checks, expired-entry reclamation, journal sync and compaction, compiled-set rebuilds. Either the caller drives `maintain(now)` (bounded work, returns the next due time) or `maintainer(true)` spawns one thread that parks with `park_timeout(next_due)` and is unparked by sweep requests; with nothing pending it never wakes.

### 7.16 Integration with net-io (D-015)

bouncer adopts net-io's hook shape: `Admission::admit(&ConnInfo, AdmitStage) -> AdmitVerdict { Admit { lane, gate: GateTag } | Refuse(..) }` and `Egress::check(&EgressContext) -> EgressVerdict { Allow | Deny { code } }`, with the denial formatted by net-io's session. The `GateTag` is bouncer's `TicketTag`. bouncer asks net-io's 0.2 for: (1) a close notice to the admission hook so the ticket is released exactly once; (2) a per-response gate tag in `EgressContext`, so multiplexed connections are judged per request; (3) kill by connection id from outside a worker, for eject-now sweeps and idle checks. Without (2), bouncer follows each connection's latest request (exact for HTTP/1.1). The `Ejector` is implemented in the integration over (3).

---

## 8. Threats, defences, tests, costs

| Id | Threat | Defence | Test (must fail to get through) | Cost |
|---|---|---|---|---|
| T-1 | Address spoofing behind proxies to evade a ban or frame someone | PROXY only from trusted proxies; forwarded headers bound only with a trusted provenance; automation bans only trusted-provenance addresses; the proxy is never a target | `test_door_forwarded_header_from_untrusted_peer_not_bound`, `test_strike_via_proxy_hop_attributed_to_real_client`, `test_ban_trusted_proxy_refused`, `test_proxied_request_without_client_denies_every_checkpoint` | about 1 ns |
| T-2 | Ban evasion by IPv6 /64 rotation (RFC 8981 temporary addresses) | automatic keys at /64; escalation /64 to /56 to /48; budgets per /64 and parent | `test_ban_ipv6_rotation_within_64_refused`, proptest over banned /64s, `test_escalation_four_64s_bans_56` | none extra |
| T-3 | Rotation inside an IPv4 provider block | /24 escalation after 8 distinct /32 | `test_escalation_ipv4_eight_hosts_bans_24` | one probe |
| T-4 | Ban table exhaustion | fixed capacity; per-parent quota forces escalation (folding); evict shortest automatic bans only; refuse with event when full | flood: 10x capacity unique /64s from 64 /48s; table stays at capacity, every flooding /48 banned, admin bans intact | scan bounded to 32 slots |
| T-5 | Banning shared NAT addresses (RFC 6598 carrier-grade NAT, offices, mobile) | shared-address detection; identity keys preferred; throttle instead of ban; no escalation from a shared address; low confidence cannot ban; observe by default | `test_shared_source_strikes_throttle_not_ban`, `test_shared_source_blocks_escalation`, 500 sessions behind one address with one attacker: only the attacker's keys banned | 8 B per tracked address |
| T-6 | Revocation races (checkpoint, bind, release) | Release/Acquire epoch; SeqCst fence pairing; generations; idempotent revoked state | loom L-1 to L-5; 32 threads, 10^8 checkpoints, random revokes, no checkpoint started after `revoke` returned passes | zero on the fast path |
| T-7 | Bytes leaving a revoked connection | mandatory transport egress check per write and per chunk; request revocation flags the connection; eject-now; buffered mode for all-or-nothing | `test_egress_after_revoke_writes_only_denial`; loopback: revoke during a 10 MiB stream, at most one chunk leaves | two loads per write |
| T-8 | Timing side channels on ban, allow, or revocation state | every refusal is the same abortive close with no work after the decision; denials byte-identical to ordinary refusals; wipe over the whole constant capacity; keyed hashing; constant-time digests | 10^6 refusals per reason, Kolmogorov-Smirnov does not separate them at p < 0.01; byte equality of denial and ordinary 403 | wipe 0.5-1 µs per 16 KiB [est.] |
| T-9 | Hash flooding | keyed hash with a random per-process seed; probe bound; reseed and rebuild with event | 10^6 keys colliding under a known seed, run with a random seed: probes stay bounded; forced seed triggers reseed | 3-10 ns per key [est.] (O-8) |
| T-10 | Stale ticket handles | generations; tagged free list; stale denies | `test_ticket_stale_generation_denied`, loom L-2 | one compare on the slow path |
| T-11 | Collateral fingerprint bans | automation bans only fingerprint-within-prefix; bare fingerprint bans need an administrator | `test_local_strike_bans_compound_fingerprint_only` | none |
| T-12 | Revocation storm pushing every checkpoint onto the slow path | bounded slow path; per-actor revocation rate limit (default 10,000/s for gates) with event; coalesced sweeps | 100,000 revocations/s while serving: p99 checkpoint under 300 ns | bounded |
| T-13 | Revocation table exhaustion | capacity bound; quiescence cleanup; idle checks; when full, direct sweep flags matching live tickets and the error returns | fill with no maintainer: the next revoke still denies matching live tickets | sweep cost |
| T-14 | Registry exhaustion by connection flood | fixed capacity; per-address and per-prefix concurrency at the door; transport global cap below registry capacity | flood from 1,000 addresses: a legitimate address is still admitted within its budget | none |
| T-15 | Forged ban persistence | keyed MAC; refuse on MAC failure | `test_snapshot_tampered_byte_refused` | MAC about 1 GB/s at load [est.] |
| T-16 | Torn writes and crashes | temp, sync, rename, directory sync; CRC32C records; tolerant tail | kill at 1,000 random points during writes; reload succeeds or refuses cleanly, never loads a corrupt entry | off the hot path |
| T-17 | Malicious import delta | per-channel rate limit; allow list untouchable; bounded deltas; fuzzed decoder; channels lift only their own node's bans; skew bound | fuzz `delta_decode`; `test_import_cannot_touch_allowlist`; `test_import_lift_foreign_ban_refused`; `test_import_future_stamp_refused` | cold |
| T-18 | Secrets in logs or events | digests only; redacted `Debug`; no evidence variant for digests | `test_debug_never_prints_key_bytes` | none |
| T-19 | Clock manipulation | monotonic in-process expiry; wall rules across restarts; HLC across nodes | `ManualClock` steps back and forward a day, across a reload and an import | none |
| T-20 | Unverified UDP sources framing victims | never strike or ban unverified datagram sources | `test_datagram_unverified_never_banned` | none |
| T-21 | Denial reveals detection | generic codes, fixed messages, reason only in events | byte-equality tests (T-8) | none |
| T-22 | Wipe removed by the optimizer | volatile writes through crypt-io; never `fill(0)` alone | inspecting global allocator: every freed `Collected` block is all zero in release builds | as 7.6 |
| T-23 | Stale reallocation copies | `Collected` never reallocates in place | allocator inspection on growth | one copy on growth |
| T-24 | A request reaches content before identity is bound | `present` bitmap; the gateway's stage types guarantee the identity checkpoint; `require(keys)` debug assertion in tests | integration test in the gateway | none |
| T-25 | Escalation weaponized against neighbours | widest-prefix limit; refused over shared or allow-listed addresses; observe by default for local heuristics | `test_escalation_refused_over_shared_source` | none |
| T-26 | A pipeline that forgets checkpoints | transport egress (B6b) is mandatory; idle revoked tickets are found by the maintainer and reported as `checkpoint.missing` | `test_revoked_ticket_without_checkpoint_reported_and_ejected` | rides on the quiescence scan |
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
22. Proxy hop that never binds a client: every request checkpoint denies; strikes ignored; event after the handshake deadline.
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
47. Flush deadline passed with a slow reader: abort without the denial.

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

Every row of section 8 has its named test. A replay harness drives recorded hostile traffic (scanner, slowloris, credential stuffing from a /48, a CGNAT population) through serve-net at 0.7. CI: Linux, macOS, Windows on stable and 1.85; fmt; clippy in default, all, and no-default modes under `-D warnings`; tests in the same three modes; `cargo doc -D warnings` with default and all features; `cargo audit`; `cargo deny check`; a loom job; a fuzz build job.

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

Every decision from the specification is answered below (and logged in section 17). One item waits on another repository and one on James.

| Id | Question | Answer | Status |
|---|---|---|---|
| O-1 | How bouncer uses rate-net and better-bucket | rate-net `Gcra` and better-bucket `BucketCore` with default features off, inside bouncer's own bounded keyed table; revisit when rate-net's keyed store drops `ahash` and `hashbrown` | decided (D-019) |
| O-2 | Who owns the epoch word | bouncer by default, injectable with `BouncerBuilder::epoch` | decided (D-020) |
| O-3 | Wipe under `forbid(unsafe_code)` | crypt-io 1.2 adds a public `wipe(&mut [u8])` over its existing volatile-write helper | decided (D-021); **needs a crypt-io 1.2 release before bouncer 0.4** |
| O-4 | Prefix lookup structure | hash per length in use for the dynamic table; compiled Poptrie-style set for admin lists and the allow list; confirm at 0.6 | decided (D-022) |
| O-5 | Per-shard `Arc` or `&Bouncer` per call | per-shard `Arc` (shard holds the shared state, no cycle); measure at 0.6 | decided (D-023) |
| O-6 | net-io hook shape | net-io's `GateTag` shape, with three additions asked of net-io (7.16) | decided on bouncer's side (D-015); **net-io's 0.2 must confirm the additions** |
| O-7 | Sharing across nodes | transport-agnostic mergeable deltas with HLC stamps, including revocations; gossip or a replicated log is the node core's choice | decided (D-017) |
| O-8 | Keyed hash | in-house keyed multiply-mix for fixed-size keys with probe bound and reseed if the T-9 test passes, else SipHash; API-neutral | decided at 0.6 by test (D-024) |
| O-9 | Snapshot integrity | keyed BLAKE3 MAC through crypt-io when a key is configured, CRC32C always | decided (D-018) |
| O-10 | Signal generator id | 2, held as `GENERATOR`; registered in the signals catalog when that module exists | decided (D-025) |
| O-11 | Default denial for revoked requests | `Forbidden`; `NotFound` per directive with `deny_with` | decided (D-026) |
| O-12 | `no_std` | not offered | decided (D-027) |
| O-13 | Default mode of local heuristics | observe by default, switchable per category and by strict posture (decided by James 2026-10-21) | decided (D-010) |
| O-14 | Request revocation on multiplexed connections | eject the connection by default; `keep_connection` for one request | decided (D-028) |
| O-15 | Name of the gates crate | bouncer only sees `Actor::Gate`; no API impact | decided (D-029) |
| O-16 | Publish 0.2.0 to crates.io (the name is free; nothing is published yet) | yes, as the release routine says, once the design lock is approved | **James** |

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
| D-015 | 2026-10-22 | net-io hook: adopt net-io's `GateTag(u64)` shape (the tag is bouncer's `TicketTag`), drop the spec's associated `Token` and replacement-bytes proposal, and ask net-io for a close notice, a per-response gate tag, and kill by id. bouncer adds `Ticket::tag`/`into_tag`, `Bouncer::request(tag, id)`, `Bouncer::egress(tag)`, `Bouncer::release(tag)`, and a latest-request link in connection cells | net-io's spec already carries an opaque `GateTag` through `ConnInfo` and `EgressContext`, which gives the same one-lookup egress check; formatting the denial in net-io's session keeps protocol knowledge out of both crates; the three additions are what releasing tickets, judging multiplexed requests, and ejecting idle connections need |
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
