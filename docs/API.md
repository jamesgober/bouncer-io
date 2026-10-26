<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br><b>bouncer-io</b><br>
    <sub><sup>API REFERENCE</sup></sub>
</h1>
<div align="center">
    <sup>
        <a href="../README.md" title="Project Home"><b>HOME</b></a>
        <span>&nbsp;│&nbsp;</span>
        <span>API</span>
        <span>&nbsp;│&nbsp;</span>
        <a href="../dev/PLAN.md" title="Design and decisions"><b>PLAN</b></a>
        <span>&nbsp;│&nbsp;</span>
        <a href="../dev/ROADMAP.md" title="Roadmap"><b>ROADMAP</b></a>
    </sup>
</div>
<br>

The complete public API of `bouncer-io`, locked at `0.2.0` (design lock). Every item lists its tier, its grade, the version that brings it, and what it costs. The rustdoc on [docs.rs](https://docs.rs/bouncer-io) becomes the exhaustive reference as each item lands; until then this file is the contract.

> **Status: `0.6.0` (optimisation; 0.7 hardening in progress).** Built and tested: everything of 0.4 (the door, ban memory, tickets, in-flight revocation, wipe-replace-eject, strikes, door budgets, events, maintenance), plus persistence, sharing across nodes, escalation, offender memory, shared-address detection, lane and tenant budgets, posture, administration (`explain`, `list`, `replace_allow`, `health`), metrics, and datagrams. Items marked with a later version (the net-io feature at 0.8) are the agreed shape; their examples become doctests when they land.

**Reading the item headers.** *Tier 1* is the simple surface (one-line constructors, no builder), *Tier 2* is configuration, *Tier 3* is the full surface for integrations and other libraries. *P0* is required for the crate's job, *P1* is what users of the best existing tools expect, *P2* is high value for serious deployments, *P3* comes after 1.0. Costs are targets, marked `[est.]` until they are measured at 0.6.

## Table of contents

- [What bouncer-io does](#what-bouncer-io-does)
  - [The checkpoints](#the-checkpoints)
- [Installation and features](#installation-and-features)
- [Quick start](#quick-start)
- [`Bouncer`](#bouncer)
  - [`Bouncer::new`](#bouncernew) · [`Bouncer::builder`](#bouncerbuilder)
  - [`door`](#door) · [`door_at`](#door_at) · [`datagram`](#datagram)
  - [`ban`](#ban) · [`lift`](#lift) · [`revoke`](#revoke) · [`apply`](#apply)
  - [`request`](#request) · [`egress`](#egress) · [`release`](#release)
  - [`replace_allow`](#replace_allow) · [`explain`](#explain) · [`list`](#list)
  - [`set_posture` and `posture`](#set_posture-and-posture) · [`health`](#health) · [`capacity`](#capacity)
  - [`now`](#now) · [`maintain`](#maintain) · [`flush`](#flush) · [`metrics`](#metrics)
  - [`export_delta`, `export_snapshot`, `import`](#export_delta-export_snapshot-import)
- [`BouncerBuilder`](#bouncerbuilder-1)
- [Keys](#keys)
  - [`Family`](#family) · [`Cidr`](#cidr) · [`normalize` and `prefix_of`](#normalize-and-prefix_of)
  - [`ConnId`, `RequestId`, `AccountKey`, `TenantKey`](#connid-requestid-accountkey-tenantkey)
  - [`SessionKey` and `FingerprintKey`](#sessionkey-and-fingerprintkey) · [`BanKey`](#bankey)
- [The door](#the-door)
  - [`Refusal`](#refusal) · [`Provenance`](#provenance) · [`DatagramVerdict`](#datagramverdict)
- [`Ticket`](#ticket)
  - [Accessors](#ticket-accessors) · [`request`](#ticketrequest) · [`checkpoint`](#ticketcheckpoint) · [`before_commit`](#ticketbefore_commit) · [`is_cancelled`](#ticketis_cancelled)
  - [`bind_client`](#ticketbind_client) · [`bind_fingerprint`](#ticketbind_fingerprint) · [`bind_session`, `bind_account`, `bind_tenant`](#ticketbind_session-bind_account-bind_tenant) · [`bind_lane`](#ticketbind_lane)
  - [`strike`](#ticketstrike) · [`deny_and_eject`](#ticketdeny_and_eject) · [`tag` and `into_tag`](#tickettag-and-into_tag) · [Release on drop](#release-on-drop)
  - [`TicketId`, `TicketKind`, `TicketTag`, `LaneClass`](#ticketid-ticketkind-tickettag-laneclass)
- [Verdicts and denials](#verdicts-and-denials)
  - [`Verdict`](#verdict) · [`Denial`](#denial) · [`DenialCode`](#denialcode) · [`DenialTable`](#denialtable) · [`Reference`](#reference)
- [`Collected`](#collected)
- [Formatting and ejection hooks](#formatting-and-ejection-hooks)
  - [`DenialFormat` and `NoFormat`](#denialformat-and-noformat) · [`Ejector` and `CloseKind`](#ejector-and-closekind) · [`Ejected`](#ejected)
- [Revocation](#revocation)
  - [`Target`](#target) · [`RevokeMode`](#revokemode) · [`Revocation`](#revocation-1) · [`RevocationEpoch`](#revocationepoch)
- [Bans and the allow list](#bans-and-the-allow-list)
  - [`BanSpec`](#banspec) · [`BanDuration`](#banduration) · [`LiftSpec` and `Lifted`](#liftspec-and-lifted) · [`BanId` and `BanRecord`](#banid-and-banrecord)
  - [`DurationPolicy`](#durationpolicy) · [`EscalationPolicy`](#escalationpolicy) · [`AllowList` and `AllowKind`](#allowlist-and-allowkind)
- [Directives](#directives)
  - [`Directive`](#directive) · [`Action`](#action) · [`BanKeys`](#bankeys) · [`Actor`](#actor) · [`Reason`](#reason) · [`Evidence`](#evidence) · [`Applied`](#applied)
- [Strikes and enforcement](#strikes-and-enforcement)
  - [`StrikeKind`](#strikekind) · [`StrikeOutcome`](#strikeoutcome) · [`StrikeRules`](#strikerules) · [`Enforcement` and `Mode`](#enforcement-and-mode)
- [Budgets](#budgets)
  - [`Budgets`](#budgets-1) · [`Rate`](#rate)
- [Administration](#administration)
  - [`Explanation`](#explanation) · [`Filter`, `Page`, `Listing`](#filter-page-listing)
- [Events](#events)
  - [`EventSink` and `NoSink`](#eventsink-and-nosink) · [`Event`](#event) · [`SignalId`, `Category`, `Subject`](#signalid-category-subject) · [Signal catalog](#signal-catalog)
- [Persistence](#persistence)
  - [`Persistence`](#persistence-1) · [`FilePersistence`](#filepersistence) · [`LoadFailure`](#loadfailure) · [`PersistError`](#persisterror)
- [Sharing across nodes](#sharing-across-nodes)
  - [`NodeId`](#nodeid) · [`Delta` and `Sequence`](#delta-and-sequence) · [`ImportReport`](#importreport) · [Merge rules](#merge-rules)
- [Posture, time, maintenance, health](#posture-time-maintenance-health)
  - [`Posture`](#posture) · [`Now`](#now-1) · [`MaintenanceReport`](#maintenancereport) · [`Health` and `Capacity`](#health-and-capacity)
- [Metrics](#metrics-1)
- [net-io integration](#net-io-integration)
- [Errors](#errors)
  - [`BouncerError`](#bouncererror) · [`ConfigError`](#configerror) · [`FormatError`](#formaterror) · [`ImportError`](#importerror)
- [Constants](#constants)
  - [`VERSION`](#version)
- [The checkpoint contract for pipelines](#the-checkpoint-contract-for-pipelines)
- [Cost summary](#cost-summary)

---

## What bouncer-io does

bouncer-io is the door guy. It is **consulted, not flowed through**: the pipeline calls it at checkpoints and it answers with a verdict. It has four jobs.

1. **The door.** At accept, from the peer address alone and before a byte is read, it admits or refuses. It checks ban memory (the exact address and every configured prefix of it), the allow list, and the source's connection budgets. It checks again when a trusted PROXY header or forwarded header reveals the real client.
2. **Tickets.** Every admitted connection gets a connection ticket; every request on it gets a request ticket. A ticket grows as the request learns who is on the other end: source, fingerprint, session, account, tenant.
3. **In-flight revocation.** Any key a ticket carries can be revoked at any time, from any thread. The next checkpoint the request crosses sees it. While nothing is revoked, a checkpoint is one atomic load and one compare.
4. **Wipe, replace, eject, remember.** A revoked request has its collected response overwritten with zeroes, replaced with a generic denial, and its connection closed abortively; the offender goes into ban memory so the next attempt dies at the door. Every action is reported as a security event.

Rate and concurrency budgets are one tool inside the door. They are not the purpose of the crate.

### The checkpoints

| Checkpoint | Called by | Call | Cost while nothing is revoked |
|---|---|---|---|
| B1 door | the transport, right after accept | [`Bouncer::door`](#door) | ban lookups and budget check, under 100 ns p99 with 1,000,000 bans [est.] |
| B1' real client | the transport after a trusted PROXY header; the protocol adapter after a trusted forwarded header | [`Ticket::bind_client`](#ticketbind_client) | same as the door |
| B2 fingerprint | the TLS adapter after the ClientHello | [`Ticket::bind_fingerprint`](#ticketbind_fingerprint) | one hash probe |
| B3 identity | the pipeline right after authentication | [`Ticket::bind_session`](#ticketbind_session-bind_account-bind_tenant) and friends | one probe per key |
| B4 between stages | the pipeline, between every pair of stages | [`Ticket::checkpoint`](#ticketcheckpoint) | one atomic load and compare |
| B5 before commit | a handler, right before a database commit | [`Ticket::before_commit`](#ticketbefore_commit) | one sequentially consistent load |
| B6a pipeline egress | the response pipeline before encoding | [`Ticket::checkpoint`](#ticketcheckpoint) | one atomic load and compare |
| B6b transport egress | the transport before every socket write | the [net-io gate](#net-io-integration) (one atomic load) or [`Bouncer::egress`](#egress) by tag (two loads) | under 3 ns [est.] |

B6b is enforced by the transport itself, so a pipeline that forgets every other checkpoint still cannot send a byte for a revoked connection.

---

## Installation and features

```toml
[dependencies]
bouncer-io = "0.2"
# with the net-io hooks and metrics:
# bouncer-io = { version = "0.8", features = ["net-io", "metrics"] }
```

| Feature | Default | Enables | Grade | Ver |
|---|---|---|---|---|
| `metrics` | no | per-shard counters and [`Bouncer::metrics`](#metrics); without it the counters do not exist | P1 | 0.5 |
| `net-io` | no | implementations of net-io's `Admission` and `Egress` hooks and the id conversions ([net-io integration](#net-io-integration)) | P0 | 0.8 |

Persistence, sharing across nodes, and administration are always compiled in: distributed operation is the default, not an option, and none of it adds a dependency. The crate needs `std` (threads for the optional maintainer, files for persistence); `no_std` is not offered.

Runtime dependencies, all first-party at published versions: `clock-lib` (time), `rate-net` and `better-bucket` with default features off (the rate math inside budgets), `crypt-io` with only its `zeroize` and `mac-blake3` features (guaranteed wipe and the snapshot MAC). No third-party crate is reached except through crypt-io's audited cryptography.

---

## Quick start

The whole Tier 1 job in one place: the door, a request, a revocation from another thread, and the checkpoint that throws the request out.

```rust
use bouncer_io::{Bouncer, Collected, Reason, RequestId, Verdict};
use std::net::IpAddr;

let bouncer = Bouncer::new();
let peer: IpAddr = "203.0.113.7".parse()?;

// The door: before reading a byte. A refusal means close abortively.
let conn = bouncer.door(peer)?;

// A request on that connection, and the buffer its response is built in.
let mut request = conn.request(RequestId(1))?;
let mut reply = Collected::new();
reply.extend_from_slice(b"account balance: 1,204.00")?;

// Anywhere, any thread: an administrator throws this connection out.
bouncer.revoke(conn.conn(), Reason::ADMIN)?;

// Between pipeline stages: one atomic load until something is revoked.
if let Verdict::Deny(_) = request.checkpoint() {
    // Wipe the reply, replace it with the denial, eject, remember.
    let ejected = request.deny_and_eject(&mut reply);
    assert!(reply.as_slice().iter().all(|&b| b == 0));
    println!("denied, reference {}", ejected.reference);
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

Banning and lifting are one line each:

```rust
use bouncer_io::{Bouncer, Cidr};

let bouncer = Bouncer::new();
bouncer.ban("198.51.100.9".parse::<std::net::IpAddr>()?)?;       // timed, by the default policy
bouncer.ban("2001:db8:7::/48".parse::<Cidr>()?)?;                 // a whole IPv6 allocation
assert!(bouncer.door("198.51.100.9".parse()?).is_err());          // refused at the door
bouncer.lift("198.51.100.9".parse::<std::net::IpAddr>()?)?;
assert!(bouncer.door("198.51.100.9".parse()?).is_ok());
# Ok::<(), Box<dyn std::error::Error>>(())
```

A logout from the authentication gate stops every request of that session that is already running:

```rust
use bouncer_io::{Bouncer, Reason, SessionKey};

let bouncer = Bouncer::new();
let session = SessionKey::from_digest([7u8; 16]);   // a keyed digest of the token, never the token
bouncer.revoke(session, Reason::LOGOUT)?;
# Ok::<(), bouncer_io::BouncerError>(())
```

---

## `Bouncer`

```rust
#[derive(Clone)]
pub struct Bouncer { /* Arc inside */ }
impl Default for Bouncer { fn default() -> Self { Bouncer::new() } }
// Send + Sync, checked at compile time. Cloning is one reference-count increment.
```

The gate itself. One `Bouncer` serves a whole process (or one per listener group); clones share all state. Every method takes `&self` and may be called from any thread.

### `Bouncer::new`

```rust
pub fn new() -> Bouncer;
```

Tier 1 · P0 · 0.3 · one-time setup, about 10 ms for the default tables [est.]

A bouncer with safe defaults: 65,536 tickets, 1,048,576 ban entries, automatic keys at IPv4 /32 and /24 and IPv6 /64, /56, /48, door budgets of 20 connections per second (burst 40) and 64 concurrent connections per address, local heuristics in **observe** mode (they report what they would ban and ban nothing), no event sink, no persistence, no maintainer thread.

Allocation failure at construction aborts the process through the allocator, as it does for any `std` collection; nothing in bouncer panics.

```rust
let bouncer = bouncer_io::Bouncer::new();
let same_gate = bouncer.clone();         // shares every table
```

### `Bouncer::builder`

```rust
pub fn builder() -> BouncerBuilder;
```

Tier 2 · P0 · 0.3 · free

Starts a [`BouncerBuilder`](#bouncerbuilder-1) with the same defaults as `new`.

```rust
use bouncer_io::{Bouncer, Cidr, Enforcement};

let bouncer = Bouncer::builder()
    .tickets(262_144)
    .trusted_proxies(&["10.0.0.0/8".parse::<Cidr>()?])
    .enforcement(Enforcement::observe_all())
    .try_build()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

### `door`

```rust
pub fn door(&self, peer: IpAddr) -> Result<Ticket, Refusal>;
```

Tier 1 · P0 · 0.3 · under 100 ns p99 with 1,000,000 bans and 10,000 administrator prefixes [est.]; no allocation

Checkpoint B1. Normalizes the address (IPv4-mapped IPv6 becomes IPv4), then checks, in order: trusted proxy (the hop is admitted and the real client is judged later), allow list, ban memory (the exact address and every prefix length in use), and the door budgets (accept rate and concurrency, by address, then prefix, then global). On success it issues a connection ticket. Reads the clock once and numbers the connection from an internal counter; use [`door_at`](#door_at) when the transport already has both.

**Parameters:** `peer`, the TCP peer address as the socket reports it.

**Returns:** `Ok(Ticket)` for an admitted connection. `Err(Refusal)` says why it was refused, for logs and metrics only: the peer must see an abortive close and nothing else, whatever the reason. See [`Refusal`](#refusal).

```rust
use bouncer_io::{Bouncer, Refusal};

let bouncer = Bouncer::new();
match bouncer.door("192.0.2.44".parse()?) {
    Ok(ticket) => { /* register the socket for reading, keep the ticket with it */ drop(ticket) }
    Err(Refusal::Banned { reference }) => eprintln!("refused, ban {reference}"),
    Err(other) => eprintln!("refused: {other}"),
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

```rust
// IPv4-mapped IPv6 is the same client as plain IPv4.
let bouncer = bouncer_io::Bouncer::new();
bouncer.ban("203.0.113.7".parse::<std::net::IpAddr>()?)?;
assert!(bouncer.door("::ffff:203.0.113.7".parse()?).is_err());
# Ok::<(), Box<dyn std::error::Error>>(())
```

### `door_at`

```rust
pub fn door_at(&self, conn: ConnId, peer: IpAddr, provenance: Provenance, now: Now) -> Result<Ticket, Refusal>;
```

Tier 3 · P0 · 0.3 · as `door`, minus one clock read

The door for transports that already number their connections and read the time at accept (net-io does both). `provenance` is normally `Provenance::Socket`; `Provenance::Local` is for in-process and Unix-socket peers.

```rust
use bouncer_io::{Bouncer, ConnId, Provenance};

let bouncer = Bouncer::new();
let now = bouncer.now();
let ticket = bouncer.door_at(ConnId(41), "192.0.2.10".parse()?, Provenance::Socket, now)?;
assert_eq!(ticket.conn(), ConnId(41));
# Ok::<(), Box<dyn std::error::Error>>(())
```

### `datagram`

```rust
pub fn datagram(&self, source: IpAddr, verified: bool, now: Now) -> DatagramVerdict;
```

Tier 2 · P2 · 0.5 · 30-60 ns [est.]

Per-datagram door for UDP. The source is checked against ban memory, then the door rate budgets (no concurrency). `verified` says whether the source has proven it can receive (a completed handshake or a returned cookie). An unverified source is charged only at its prefix, never at its own client budget, and is never struck or banned, because UDP source addresses can be forged to frame a victim.

```rust
use bouncer_io::{Bouncer, DatagramVerdict};

let bouncer = Bouncer::new();
let verdict = bouncer.datagram("198.51.100.20".parse()?, false, bouncer.now());
assert_eq!(verdict, DatagramVerdict::Accept);
# Ok::<(), Box<dyn std::error::Error>>(())
```

### `ban`

```rust
pub fn ban(&self, spec: impl Into<BanSpec>) -> Result<BanId, BouncerError>;
```

Tier 1 · P0 · 0.3 · 200-500 ns [est.], takes the ban writer lock (cold path; never blocks the door)

Adds a ban. An address or a `Cidr` converts directly (timed by the [duration policy](#durationpolicy), actor [`Actor::App`](#actor)); a [`BanSpec`](#banspec) sets duration, actor, reason, and evidence. Takes effect at the next door check on every thread. Connections already admitted are not touched: to throw them out too, use [`apply`](#apply) with `Directive::revoke_and_ban`.

**Errors:** `AllowListed` (remove the allow entry first), `TrustedProxyTarget` (ban the real client instead), `InvalidPrefix`, `PermanentNotAllowed` (only administrators, the application, and definitive directives ban permanently), `InvalidDuration` (zero), `BanTableFull` (only permanent and administrator entries left to evict; raise `ban_capacity`).

```rust
use bouncer_io::{Actor, BanSpec, Bouncer, Reason};
use std::time::Duration;

let bouncer = Bouncer::new();
bouncer.ban("203.0.113.0/24".parse::<bouncer_io::Cidr>()?)?;
bouncer.ban(
    BanSpec::address("198.51.100.9".parse()?)
        .for_duration(Duration::from_secs(3600))
        .by(Actor::Admin(17))
        .because(Reason::ADMIN),
)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

```rust
// Identity bans: the next request carrying this account is refused at B3.
use bouncer_io::{AccountKey, BanSpec, Bouncer};
let bouncer = Bouncer::new();
bouncer.ban(BanSpec::key(AccountKey(0x0192_0000_0000_7000_8000_0000_0000_0001)).permanent())?;
# Ok::<(), bouncer_io::BouncerError>(())
```

### `lift`

```rust
pub fn lift(&self, spec: impl Into<LiftSpec>) -> Result<Lifted, BouncerError>;
```

Tier 1 · P0 · 0.3 · 200-500 ns [est.]

Removes the bans on exactly this key and records the lift, so a ban that arrives later from another node with an older stamp does not bring it back. On a node that shares, an administrator's or the application's lift removes every node's ban on the key here, and an automated actor's lift only this node's own (see [Merge rules](#merge-rules) for how it reaches other nodes). A prefix ban that covers the key is not lifted: `explain` shows it. The lift is an event with actor and reason.

**Errors:** `NotFound` (nothing was banned under this key), `InvalidPrefix`.

```rust
use bouncer_io::{Actor, Bouncer, LiftSpec, Reason};

let bouncer = Bouncer::new();
let addr: std::net::IpAddr = "198.51.100.9".parse()?;
bouncer.ban(addr)?;
let lifted = bouncer.lift(LiftSpec::key(addr).by(Actor::Admin(17)).because(Reason::ADMIN))?;
assert_eq!(lifted.removed, 1);
# Ok::<(), Box<dyn std::error::Error>>(())
```

### `revoke`

```rust
pub fn revoke(&self, target: impl Into<Target>, reason: Reason) -> Result<Revocation, BouncerError>;
```

Tier 1 · P0 · 0.4 · under 1 µs [est.]; visible to every core within the hardware coherence time (tens of nanoseconds)

Stops what is running now. Every ticket that carries the target key is denied at its next checkpoint; a checkpoint that begins after `revoke` has returned on any thread cannot miss it. The target converts from a [`ConnId`](#connid-requestid-accountkey-tenantkey), `RequestId`, `SessionKey`, `AccountKey`, `TenantKey`, `FingerprintKey`, `Cidr`, or address. The actor is [`Actor::App`](#actor), the mode is `AtCheckpoint`, a revoked request takes its connection with it, and no ban is added. For any other choice use [`apply`](#apply).

A revocation is not a ban: it ends running work. A connection that comes back is judged at the door as usual unless a ban was also set.

**Errors:** `AllowListed` (automated actors only), `TrustedProxyTarget`, `InvalidPrefix`, `RevocationTableFull` (the revocation still reaches every live matching ticket through a direct sweep before the error returns; check the maintainer is running).

```rust
use bouncer_io::{AccountKey, Bouncer, Reason};

let bouncer = Bouncer::new();
// Password changed: every running request of this account stops.
bouncer.revoke(AccountKey(42), Reason::PASSWORD_CHANGED)?;
# Ok::<(), bouncer_io::BouncerError>(())
```

```rust
// One connection, from an administrator console.
let bouncer = bouncer_io::Bouncer::new();
let conn = bouncer.door("192.0.2.5".parse()?)?;
let receipt = bouncer.revoke(conn.conn(), bouncer_io::Reason::ADMIN)?;
println!("revoked at epoch {}", receipt.epoch);
# Ok::<(), Box<dyn std::error::Error>>(())
```

### `apply`

```rust
pub fn apply(&self, directive: Directive) -> Result<Applied, BouncerError>;
```

Tier 2 · P0 · 0.4 · as the action it carries

The single entry for decisions made elsewhere: the security signals policy, sentinel-sec, the authentication gates, administrators, and other nodes over the back-channel. A [`Directive`](#directive) names the action (throttle, ban, revoke, revoke and ban, lift), the target, the actor, the reason, the confidence, and options. Safe from any thread; this is the mailbox the security core writes to.

Rules that hold whatever the directive says: automated actors never touch allow-listed keys or trusted proxies; a directive below the Medium confidence band (under 30) cannot ban by itself (it may throttle); every applied directive is an event naming its cause.

**Errors:** as [`ban`](#ban) and [`revoke`](#revoke), plus `InvalidTarget` when the action does not fit the target (a lift or a throttle of a connection or request id). A throttle of a session, account, tenant, or fingerprint divides that key's lane and tenant budgets; with no identity budget configured it has nothing to divide. A ban directive below confidence 30 is not an error: it is applied as a throttle and `Applied::downgraded` says so.

```rust
use bouncer_io::{Actor, Bouncer, Directive, Reason, SessionKey};
use std::time::Duration;

let bouncer = Bouncer::new();
let session = SessionKey::from_digest([3u8; 16]);

// Decoy token touched: throw out everything on that session now, and ban it.
bouncer.apply(
    Directive::revoke_and_ban(session)
        .by(Actor::Sentinel)
        .because(Reason::DECOY)
        .confidence(95)
        .eject_now(),
)?;

// Policy score crossed the throttle threshold for an address.
bouncer.apply(
    Directive::throttle("198.51.100.77".parse::<std::net::IpAddr>()?, 4, Duration::from_secs(600))
        .by(Actor::Policy(12))
        .because(Reason::POLICY)
        .confidence(60),
)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

### `request`

```rust
pub fn request(&self, connection: TicketTag, id: RequestId) -> Result<Ticket, BouncerError>;
```

Tier 3 · P0 · 0.4 · 20-40 ns [est.]

Issues a request ticket under a connection the caller holds only as a [`TicketTag`](#tickettag-and-into_tag), which is how a transport that stores a plain 64-bit value per connection (net-io's `GateTag`) works. Same as [`Ticket::request`](#ticketrequest) otherwise.

**Errors:** `Stale` (the connection was released, or the tag is from another bouncer), `Revoked`, `RegistryFull`, `NotAConnectionTicket`.

```rust
use bouncer_io::{Bouncer, RequestId};

let bouncer = Bouncer::new();
let tag = bouncer.door("192.0.2.8".parse()?)?.into_tag();   // the transport keeps only this u64
let request = bouncer.request(tag, RequestId(9))?;
assert_eq!(request.conn(), bouncer.request(tag, RequestId(10))?.conn());
bouncer.release(tag);
# Ok::<(), Box<dyn std::error::Error>>(())
```

### `egress`

```rust
pub fn egress(&self, ticket: TicketTag) -> Verdict;
```

Tier 3 · P0 · 0.4 · two atomic loads while nothing is revoked [est. under 3 ns]; slow path under 150 ns [est.]

Checkpoint B6b for a transport: call it before every socket write, and per chunk when streaming. Pass the tag of the request whose response is being written when the transport knows it (the exact answer, also for multiplexed connections), or the connection's tag otherwise. A connection tag checks the connection's own keys and flags, and the request most recently issued on it. A stale or unknown tag is a `Deny` (fail closed).

On `Deny` the transport overwrites its pending output with zeroes, writes the protocol's denial only if nothing of this response has left yet, and closes abortively. net-io does exactly this through its egress hook ([net-io integration](#net-io-integration)).

```rust
use bouncer_io::{Bouncer, Reason, Verdict};

let bouncer = Bouncer::new();
let ticket = bouncer.door("192.0.2.9".parse()?)?;
let conn = ticket.conn();
let tag = ticket.into_tag();                   // the transport keeps only this
assert!(bouncer.egress(tag).is_pass());
bouncer.revoke(conn, Reason::ADMIN)?;
assert!(matches!(bouncer.egress(tag), Verdict::Deny(_)));
bouncer.release(tag);
# Ok::<(), Box<dyn std::error::Error>>(())
```

### `release`

```rust
pub fn release(&self, connection: TicketTag) -> bool;
```

Tier 3 · P0 · 0.4 · 10-20 ns [est.]

Releases a connection ticket that was turned into a tag. Live request tickets under it are revoked with `ConnectionClosed` (a request cannot outlive its connection). Returns `false` when the tag was already released or stale. The transport calls this exactly once, when the connection closes; a tag that is never released holds its ticket until the bouncer is dropped and shows up in [`health`](#health) as a detached ticket.

```rust
let bouncer = bouncer_io::Bouncer::new();
let tag = bouncer.door("192.0.2.12".parse()?)?.into_tag();
assert!(bouncer.release(tag));
assert!(!bouncer.release(tag));
# Ok::<(), Box<dyn std::error::Error>>(())
```

### `replace_allow`

```rust
pub fn replace_allow(&self, list: AllowList) -> Result<(), BouncerError>;
```

Tier 2 · P1 · 0.5 · compile in milliseconds, swap is one pointer store

Compiles a new allow list and swaps it in whole. Readers never wait. Existing bans covered by the new list are lifted with an event; tickets of newly immune sources are not revoked.

**Errors:** `InvalidPrefix`, `Config(AllowListTooLarge)` (default limit 65,536 entries).

```rust
use bouncer_io::{AllowList, Bouncer};

let bouncer = Bouncer::new();
bouncer.replace_allow(
    AllowList::new()
        .immune("10.20.0.0/16".parse()?, "own infrastructure")
        .exempt_budgets("192.0.2.200".parse()?, "load balancer health checks"),
)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

### `explain`

```rust
pub fn explain(&self, key: impl Into<BanKey>) -> Explanation;
```

Tier 1 · P1 · 0.5 · microseconds, cold path, allocates

Everything bouncer knows about one key: whether the door would admit it now, every ban that covers it (including wider prefixes), allow entries, budget and strike state, offender history, shared-address flag, and live tickets. `Display` prints plain sentences for an administrator console.

```rust
let bouncer = bouncer_io::Bouncer::new();
bouncer.ban("203.0.113.0/24".parse::<bouncer_io::Cidr>()?)?;
let why = bouncer.explain("203.0.113.7".parse::<std::net::IpAddr>()?);
assert!(!why.admitted);
println!("{why}");   // 203.0.113.7 is refused: 203.0.113.0/24 banned until 2026-10-22 14:10:00 UTC by App, reason admin
# Ok::<(), Box<dyn std::error::Error>>(())
```

### `list`

```rust
pub fn list(&self, filter: &Filter, page: Page) -> Listing;
```

Tier 2 · P1 · 0.5 · cold path, allocates one page

A filtered, paged listing of bans. Each page is a consistent snapshot. See [`Filter`, `Page`, `Listing`](#filter-page-listing).

```rust
use bouncer_io::{Bouncer, Filter, Page};

let bouncer = Bouncer::new();
let mut page = Page::first(100);
loop {
    let listing = bouncer.list(&Filter::all(), page);
    for ban in &listing.items { println!("{} until {:?}", ban.key, ban.until); }
    match listing.next { Some(next) => page = next, None => break }
}
```

### `set_posture` and `posture`

```rust
pub fn set_posture(&self, posture: Posture);
pub fn posture(&self) -> Posture;
```

Tier 2 · P2 · 0.5 · one atomic store or load

Switches between `Posture::Normal` and `Posture::Strict` (lockdown). The integrator calls it when its security core raises a lockdown (for example from an urgent alert line read at the top of each worker loop). Strict halves the door budgets (`BouncerBuilder::strict_budget_divisor`, default 2) and switches the strike categories listed in `Enforcement::strict` from observe to enforce. Refusing whole listeners during a lockdown is the transport's job (net-io refuses listeners not marked for lockdown). Changing posture revokes nothing already admitted unless `BouncerBuilder::strict_revokes_unauthenticated(true)` is set, in which case every request ticket with no bound session is revoked (connections are not: they carry authenticated requests too). A change is reported as `bouncer.posture.changed`.

```rust
use bouncer_io::{Bouncer, Posture};
let bouncer = Bouncer::new();
bouncer.set_posture(Posture::Strict);
assert_eq!(bouncer.posture(), Posture::Strict);
```

### `health`

```rust
pub fn health(&self) -> Health;
```

Tier 2 · P1 · 0.5 · microseconds

Table loads, registry use, detached tickets, journal backlog, the last persistence failure, and the maintainer's state, for health endpoints and alerts. See [`Health`](#health-and-capacity).

```rust
let health = bouncer_io::Bouncer::new().health();
assert!(health.is_ok());
println!("tickets {}/{}", health.tickets_live, health.tickets_capacity);
```

### `capacity`

```rust
pub fn capacity(&self) -> Capacity;
```

Tier 2 · P1 · 0.3 · free

The memory every table reserved at construction, in bytes, and the entry limits. Memory never grows past these numbers.

```rust
let cap = bouncer_io::Bouncer::new().capacity();
println!("bouncer reserves {} bytes in total", cap.total_bytes);
```

### `now`

```rust
pub fn now(&self) -> Now;
```

Tier 3 · P0 · 0.3 · one clock read

The bouncer's monotonic time base (from the configured `clock-lib` clock), for the `_at` functions.

### `maintain`

```rust
pub fn maintain(&self, now: Now) -> MaintenanceReport;
```

Tier 3 · P0 · 0.4 · bounded per call

Does a bounded amount of every pending job: eject-now sweeps, revocation cleanup, checks on tickets that have not crossed a checkpoint for longer than `max_unchecked` (their slow path is run on their behalf and matching ones are ejected), reclaiming expired entries, journal sync and compaction, compiled-set rebuilds. Returns when more work is next due, or `None` when nothing is pending. Use it when the integrator's own kernel or worker drives maintenance; otherwise enable the parked maintainer thread with [`BouncerBuilder::maintainer`](#bouncerbuilder-1).

```rust
let bouncer = bouncer_io::Bouncer::new();
let report = bouncer.maintain(bouncer.now());
if report.next_due.is_none() { /* nothing to do until something is revoked or banned */ }
```

### `flush`

```rust
pub fn flush(&self) -> Result<(), BouncerError>;
```

Tier 2 · P1 · 0.5 · I/O

Writes and syncs every journal record queued so far. Call it before a planned shutdown.

**Errors:** `Persist(..)`.

### `metrics`

```rust
#[cfg(feature = "metrics")]
pub fn metrics(&self) -> MetricsSnapshot;
```

Tier 2 · P1 · 0.5 · microseconds (sums per-shard counters)

See [Metrics](#metrics-1).

### `export_delta`, `export_snapshot`, `import`

```rust
pub fn export_delta(&self, since: Sequence) -> Result<Delta, BouncerError>;
pub fn export_snapshot(&self) -> Result<Delta, BouncerError>;
pub fn import(&self, delta: &Delta, from: Actor) -> Result<ImportReport, BouncerError>;
```

Tier 3 · P2 · 0.5 · cold path

Sharing across nodes: bouncer provides the data, the caller provides the transport (a node link, the back-channel, or a replicated log). A delta carries bans, lifts, offender records, and revocations since a sequence number; `export_snapshot` carries everything for a node that is joining. Imports merge deterministically (see [Merge rules](#merge-rules)), so any order and any repetition of delivery converges. A revocation imported from another node reaches the requests already running here, so logging out on one node stops the session's requests on every node.

**Errors:** `NodeIdUnset` (export and import need [`BouncerBuilder::node`](#bouncerbuilder-1)), `Import(Corrupt | TooLarge | UnsupportedFormat | RateLimited | AllowListTouched | ClockSkew)`. Deltas are format 2 since 0.7 (lifts carry their scope); format 1 deltas from 0.5 and 0.6 are read, and 0.5 and 0.6 refuse format 2 with `UnsupportedFormat`.

```rust
use bouncer_io::{Actor, Bouncer, NodeId, Sequence};

let a = Bouncer::builder().node(NodeId(1)).try_build()?;
let b = Bouncer::builder().node(NodeId(2)).try_build()?;
a.ban("198.51.100.9".parse::<std::net::IpAddr>()?)?;

let delta = a.export_delta(Sequence::START)?;
let report = b.import(&delta, Actor::Channel(1))?;
assert_eq!(report.applied, 1);
assert!(b.door("198.51.100.9".parse()?).is_err());
# Ok::<(), Box<dyn std::error::Error>>(())
```

---

## `BouncerBuilder`

```rust
pub struct BouncerBuilder { /* private */ }
impl BouncerBuilder {
    pub fn tickets(self, capacity: u32) -> Self;
    pub fn shards(self, count: u16) -> Self;
    pub fn ban_capacity(self, entries: u32) -> Self;
    pub fn revocation_capacity(self, entries: u32) -> Self;
    pub fn ipv4_lengths(self, lengths: &[u8]) -> Self;
    pub fn ipv6_lengths(self, lengths: &[u8]) -> Self;
    pub fn durations(self, policy: DurationPolicy) -> Self;
    pub fn escalation(self, policy: EscalationPolicy) -> Self;
    pub fn allow(self, list: AllowList) -> Self;
    pub fn trusted_proxies(self, cidrs: &[Cidr]) -> Self;
    pub fn budgets(self, budgets: Budgets) -> Self;
    pub fn strikes(self, rules: StrikeRules) -> Self;
    pub fn enforcement(self, modes: Enforcement) -> Self;
    pub fn denials(self, table: DenialTable) -> Self;
    pub fn denial_format(self, format: Arc<dyn DenialFormat>) -> Self;
    pub fn ejector(self, ejector: Arc<dyn Ejector>) -> Self;
    pub fn event_sink(self, sink: Arc<dyn EventSink>) -> Self;
    pub fn epoch(self, epoch: Arc<RevocationEpoch>) -> Self;
    pub fn clock(self, clock: Arc<dyn clock_lib::Clock>) -> Self;
    pub fn seed(self, seed: [u8; 32]) -> Self;
    pub fn max_unchecked(self, idle: Duration) -> Self;
    pub fn maintainer(self, spawn: bool) -> Self;
    pub fn persistence(self, store: Box<dyn Persistence>) -> Self;
    pub fn mac_key(self, key: [u8; 32]) -> Self;
    pub fn on_load_failure(self, policy: LoadFailure) -> Self;
    pub fn node(self, id: NodeId) -> Self;
    pub fn strict_budget_divisor(self, divisor: u8) -> Self;
    pub fn strict_revokes_unauthenticated(self, revoke: bool) -> Self;
    pub fn max_wall_jump(self, jump: Duration) -> Self;
    pub fn strict_wall_jump(self, keep: bool) -> Self;
    pub fn revocation_rate_limit(self, per_second: u32) -> Self;
    pub fn max_clock_skew(self, skew: Duration) -> Self;
    pub fn try_build(self) -> Result<Bouncer, BouncerError>;
}
```

Tier 2 throughout, except `epoch`, `clock`, and `seed` (Tier 3). Every setter is optional; `try_build` validates everything at once, allocates every table, and loads persisted state before returning, so the first `door` already sees every ban.

| Setter | What it sets | Default | Errors at `try_build` | Grade | Ver |
|---|---|---|---|---|---|
| `tickets` | registry capacity; one cell per connection and one per in-flight request; 128 B per cell | 65,536 (8 MiB) | `Config(TooSmall/TooLarge)` | P0 | 0.3 |
| `shards` | registry shards, rounded up to a power of two | one per core, at most 256 | `Config(..)` | P0 | 0.3 |
| `ban_capacity` | dynamic ban table entries | 1,048,576 (about 45 MiB [est.]) | `Config(..)` | P0 | 0.3 |
| `revocation_capacity` | revocation table entries | 65,536 | `Config(..)` | P0 | 0.4 |
| `ipv4_lengths` | automatic key lengths for IPv4; must include 32 | `[32, 24]` | `Config(InvalidLength)` | P0 | 0.3 |
| `ipv6_lengths` | automatic key lengths for IPv6; 128 is refused (one host owns its whole /64) | `[64, 56, 48]` | `Config(InvalidLength)`, `Config(HostBansForbidden)` | P0 | 0.3 |
| `durations` | how long automatic bans last, growing for repeat offenders | [`DurationPolicy::default()`](#durationpolicy) | `Config(InvalidDuration)` | P0 | 0.3 |
| `escalation` | prefix escalation | [`EscalationPolicy::default()`](#escalationpolicy) | `Config(..)` | P1 | 0.5 |
| `allow` | the allow list, compiled at build | empty | `InvalidPrefix`, `Config(AllowListTooLarge)` | P0 | 0.3 |
| `trusted_proxies` | proxies whose PROXY and forwarded headers are believed; never banned, struck, or budgeted; the same list the transport uses | none | `InvalidPrefix` | P0 | 0.3 |
| `budgets` | door, lane, and tenant budgets | [`Budgets::default()`](#budgets-1) | `Config(..)` | P1 | 0.4 |
| `strikes` | strike weights, windows, thresholds | [`StrikeRules::default()`](#strikerules) | `Config(..)` | P0 | 0.4 |
| `enforcement` | observe or enforce, per strike category | [`Enforcement::observe_all()`](#enforcement-and-mode) | none | P0 | 0.4 |
| `denials` | the fixed message and application code per denial code | [`DenialTable::default()`](#denialtable) | `Config(MessageTooLong)` | P0 | 0.4 |
| `denial_format` | the protocol formatter `deny_and_eject` uses | `NoFormat` (close without a reply) | none | P0 | 0.4 |
| `ejector` | how a connection is closed from bouncer's side (sweeps, idle checks, `deny_and_eject`) | none: `deny_and_eject` reports `ejected: false` and the caller closes | none | P0 | 0.4 |
| `event_sink` | where every event goes (the security signal bridge, audit) | none | none | P0 | 0.4 |
| `epoch` | an epoch word owned by the security core, shared with other modules | bouncer's own | none | P1 | 0.4 |
| `clock` | the time source; `ManualClock` in tests | the system clock | none | P0 | 0.3 |
| `seed` | fixed seeds for hashing, jitter, and references, for tests and simulation only | random from the operating system | none | P1 | 0.3 |
| `max_unchecked` | how long a ticket may go without a checkpoint before the maintainer checks it on its behalf | 60 s | `Config(..)` | P1 | 0.4 |
| `maintainer` | spawn one maintenance thread that parks until work is due (no idle wake-ups) | `false` | `Spawn(kind)` | P1 | 0.4 |
| `persistence` | where bans and offender memory survive restarts | none (memory only) | `Persist(..)` when the load fails and the policy is `Refuse` | P1 | 0.5 |
| `mac_key` | key for the keyed BLAKE3 MAC over snapshot and journal (from the integrator's key store) | none (CRC32C only) | none | P1 | 0.5 |
| `on_load_failure` | what to do when persisted state is corrupt | `LoadFailure::Refuse` | none | P1 | 0.5 |
| `node` | this node's id, stamped on every record it exports | unset (sharing disabled) | `Config(..)` for id 0 | P2 | 0.5 |
| `max_clock_skew` | imported records stamped further in the future than this are refused | 5 minutes | `Config(..)` | P2 | 0.5 |
| `strict_budget_divisor` | how much `Posture::Strict` divides the door budgets by | 2 | `Config(InvalidFactor)` for 0 | P2 | 0.5 |
| `strict_revokes_unauthenticated` | whether entering `Posture::Strict` revokes every ticket with no bound session | `false` | none | P2 | 0.5 |
| `max_wall_jump` | a wall-clock jump between save and load larger than this is reported | 1 hour | none | P1 | 0.5 |
| `strict_wall_jump` | keep bans across such a jump instead of letting them expire | `false` | none | P1 | 0.5 |
| `revocation_rate_limit` | revocations per second accepted from each automated actor before further ones are observed only (a revocation storm defence) | 10,000 | `Config(TooSmall)` for 0 | P1 | 0.4 |

```rust
use bouncer_io::{Bouncer, DurationPolicy, Enforcement, FilePersistence, StrikeKind};
use std::time::Duration;

let bouncer = Bouncer::builder()
    .durations(DurationPolicy::default().base(Duration::from_secs(900)).max(Duration::from_secs(86_400)))
    .enforcement(Enforcement::observe_all().enforce(StrikeKind::ProxyViolation))
    .persistence(Box::new(FilePersistence::open("/var/lib/gate".as_ref(), "bans")?))
    .maintainer(true)
    .try_build()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

```rust
// Deterministic tests: a manual clock and fixed seeds.
use bouncer_io::Bouncer;
use clock_lib::ManualClock;
use std::sync::Arc;

let clock = Arc::new(ManualClock::new());
let bouncer = Bouncer::builder().clock(clock.clone()).seed([1; 32]).try_build()?;
# Ok::<(), bouncer_io::BouncerError>(())
```

---

## Keys

Everything bouncer bans, revokes, or budgets is one of these keys. Addresses are normalized once, at the entry point of every public function that accepts one.

### `Family`

```rust
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Family { V4, V6 }
impl Family { pub const fn max_len(self) -> u8; }   // 32 or 128
impl Display for Family;                            // "IPv4", "IPv6"
```

Tier 3 · P0 · 0.3

### `Cidr`

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Cidr { /* normalized network address and length; host bits cleared */ }
impl Cidr {
    pub fn new(addr: IpAddr, len: u8) -> Result<Cidr, BouncerError>;
    pub fn host(addr: IpAddr) -> Cidr;
    pub fn parse(text: &str) -> Result<Cidr, BouncerError>;
    pub fn parse_strict(text: &str) -> Result<Cidr, BouncerError>;
    pub fn contains(&self, addr: IpAddr) -> bool;
    pub fn family(&self) -> Family;
    pub fn len(&self) -> u8;
    pub fn network(&self) -> IpAddr;
    pub fn parent(&self, len: u8) -> Option<Cidr>;
}
impl FromStr for Cidr { type Err = BouncerError; }
impl Display for Cidr;
impl From<IpAddr> for Cidr;   // same as Cidr::host
```

Tier 1 · P0 · 0.3 · constructors and `contains` 1-3 ns, parsing 20-60 ns [est.]; no allocation

A network prefix. `new` and `parse` clear host bits (`10.0.0.5/24` becomes `10.0.0.0/24`); `parse_strict` refuses them. A bare address parses as a host prefix (/32 or /128). IPv4-mapped IPv6 input is normalized to IPv4. `contains` normalizes its argument. `parent(len)` widens to a shorter prefix, `None` if `len` is longer than the current length.

Text rules: at most 64 bytes; no whitespace; no zone ids (`fe80::1%eth0` is refused); no leading zeros in IPv4 octets (`010.0.0.1` is refused because it is ambiguous between decimal and octal).

**Errors:** `InvalidPrefix { len, family, host_bits_set }` for a length above 32 or 128, or host bits set under `parse_strict`; `ParseCidr { position }` with the byte offset of the first bad character.

```rust
use bouncer_io::Cidr;

let net: Cidr = "2001:db8:aa::/48".parse()?;
assert!(net.contains("2001:db8:aa:1::5".parse()?));
assert_eq!(net.parent(32).unwrap().to_string(), "2001:db8::/32");
assert_eq!("10.0.0.5/24".parse::<Cidr>()?.to_string(), "10.0.0.0/24");
assert!(Cidr::parse_strict("10.0.0.5/24").is_err());
assert!(Cidr::parse("010.0.0.1").is_err());
# Ok::<(), Box<dyn std::error::Error>>(())
```

### `normalize` and `prefix_of`

```rust
pub fn normalize(addr: IpAddr) -> IpAddr;
pub fn prefix_of(addr: IpAddr, len: u8) -> Result<Cidr, BouncerError>;
```

Tier 1 · P0 · 0.3 · about 1 ns

`normalize` maps IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to IPv4 and leaves everything else alone. The deprecated IPv4-compatible form (`::a.b.c.d`), NAT64 (`64:ff9b::/96`), Teredo, and 6to4 stay IPv6: the IPv4 address embedded in them is chosen by the client and is never used as a key, so a client cannot frame someone else's address. `prefix_of` normalizes and builds the prefix of the given length.

```rust
use bouncer_io::{normalize, prefix_of};
use std::net::IpAddr;

let mapped: IpAddr = "::ffff:203.0.113.7".parse()?;
assert_eq!(normalize(mapped), "203.0.113.7".parse::<IpAddr>()?);
assert_eq!(prefix_of("2001:db8::1234".parse()?, 64)?.to_string(), "2001:db8::/64");
let nat64: IpAddr = "64:ff9b::cb00:7107".parse()?;
assert_eq!(normalize(nat64), nat64);   // not 203.0.113.7
# Ok::<(), Box<dyn std::error::Error>>(())
```

### `ConnId`, `RequestId`, `AccountKey`, `TenantKey`

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)] pub struct ConnId(pub u64);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)] pub struct RequestId(pub u128);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)] pub struct AccountKey(pub u128);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)] pub struct TenantKey(pub u64);
```

Tier 1 · P0 · 0.3 (connection, request) / 0.4 (account, tenant)

Plain identifiers. `ConnId` comes from the transport (net-io's `ConnectionId` is never reused in a process); `RequestId` is opaque to bouncer (a ULID from the request layer fits); `AccountKey` holds a user id (a UUIDv7 as `u128`); `TenantKey` holds the tenant number from the identity stamp.

```rust
use bouncer_io::{AccountKey, RequestId, TenantKey};
let account = AccountKey(0x0192_5f3e_0000_7000_8000_0000_0000_002a);
let tenant = TenantKey(7);
let request = RequestId(0x0192_5f3e_1111_7abc_8000_0000_0000_0001);
# let _ = (account, tenant, request);
```

### `SessionKey` and `FingerprintKey`

```rust
#[derive(Clone, Copy)] pub struct SessionKey([u8; 16]);
#[derive(Clone, Copy)] pub struct FingerprintKey([u8; 16]);
impl SessionKey { pub const fn from_digest(bytes: [u8; 16]) -> SessionKey; }
impl FingerprintKey { pub const fn from_digest(bytes: [u8; 16]) -> FingerprintKey; }
// PartialEq and Eq compare in constant time. Hash is implemented.
// Debug and Display print "SessionKey(..)" and "FingerprintKey(..)", never the bytes.
```

Tier 1 · P0 · 0.4 · compare about 2 ns

Digests, never secrets: gate-net hands bouncer a keyed digest of the session token, and the TLS adapter a digest of the ClientHello fingerprint. Equality is constant time and the bytes never appear in `Debug`, `Display`, errors, or events.

A fingerprint is a weak identifier: every client of one browser build shares it. Automation therefore bans a fingerprint only together with a prefix ([`BanKey::FingerprintIn`](#bankey)); a bare fingerprint ban needs an administrator.

```rust
use bouncer_io::SessionKey;
let a = SessionKey::from_digest([9; 16]);
assert_eq!(a, SessionKey::from_digest([9; 16]));
assert_eq!(format!("{a:?}"), "SessionKey(..)");
```

### `BanKey`

```rust
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BanKey {
    Address(IpAddr), Prefix(Cidr), Session(SessionKey), Account(AccountKey),
    Tenant(TenantKey), Fingerprint(FingerprintKey), FingerprintIn(FingerprintKey, Cidr),
}
impl From<IpAddr> for BanKey; impl From<Cidr> for BanKey; impl From<SessionKey> for BanKey;
impl From<AccountKey> for BanKey; impl From<TenantKey> for BanKey; impl From<FingerprintKey> for BanKey;
impl Display for BanKey;   // digests print redacted
```

Tier 1 · P0 · 0.3

What a ban, lift, or explanation targets. Every key type converts into it, so `bouncer.ban(addr)` and `bouncer.explain(session)` read naturally. `Address` is normalized and stored as a host prefix.

---

## The door

### `Refusal`

```rust
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Banned { reference: Reference },
    OverBudget { retry_after: Duration },
    RegistryFull,
    Posture,
}
impl Display for Refusal; impl std::error::Error for Refusal;
```

Tier 1 · P0 · 0.3

Why the door refused, for the caller's logs and metrics. It is never shown to the peer: every refusal is the same abortive close with nothing read and nothing written, so a peer cannot tell a ban from a budget from a full registry by its behaviour or timing.

| Variant | Meaning | What the operator does |
|---|---|---|
| `Banned { reference }` | a ban covers the address; `reference` finds it in events and `explain` | nothing, or `lift` if it is wrong |
| `OverBudget { retry_after }` | over the accept rate or concurrency budget | nothing; raise `Budgets` if real users hit it |
| `RegistryFull` | no free ticket: bouncer cannot track the connection, so it refuses (fail closed). Never a ban | raise `tickets`, or cap connections lower in the transport |
| `Posture` | strict posture refuses this listener's guests | lower the posture when the incident ends |

### `Provenance`

```rust
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provenance { Socket, ProxyProtocol, ForwardedHeader, FastCgi, Local }
```

Tier 2 · P0 · 0.3

How a source address was learned, recorded on the ticket. `Socket` is the TCP peer. `ProxyProtocol` and `ForwardedHeader` are believed only from a trusted proxy (the transport and the protocol adapter check the same trusted list bouncer has). `FastCgi` is an address passed by a trusted front end. `Local` is an in-process or Unix-socket peer. Automation bans and strikes only addresses whose provenance is trusted.

### `DatagramVerdict`

```rust
#[must_use] #[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatagramVerdict { Accept, Drop }
```

Tier 2 · P2 · 0.5 · the answer of [`datagram`](#datagram)

---

## `Ticket`

```rust
#[must_use = "dropping a ticket releases it; keep it for the life of the connection or request"]
pub struct Ticket { /* shard handle, cell index, generation, last seen epoch, kind */ }
// Send + Sync. Not Clone: a ticket has one owner.
```

The handle a connection or request carries through the pipeline. It is small (24 bytes [est.]) and reaches the shared state through its shard, so checkpoints need nothing else passed in.

A connection ticket comes from [`Bouncer::door`](#door). A request ticket comes from [`Ticket::request`](#ticketrequest) on the connection ticket (or [`Bouncer::request`](#request) with its tag) and names that connection as its parent: revoking the connection denies the request, and dropping the connection ticket revokes its live requests.

### Ticket accessors

```rust
impl Ticket {
    pub fn id(&self) -> TicketId;
    pub fn kind(&self) -> TicketKind;
    pub fn conn(&self) -> ConnId;
    pub fn source(&self) -> Option<IpAddr>;
    pub fn provenance(&self) -> Provenance;
}
```

Tier 1 · P0 · 0.3 · about 1 ns each

`source` is `None` on a connection from a trusted proxy until the real client is bound.

### `Ticket::request`

```rust
pub fn request(&self, id: RequestId) -> Result<Ticket, BouncerError>;
```

Tier 1 · P0 · 0.3 · 20-40 ns [est.]; no allocation

Issues a request ticket under this connection ticket. Takes `&self` so multiplexed protocols can open several requests on one connection.

**Errors:** `NotAConnectionTicket`, `Revoked` (the connection is revoked), `RegistryFull` (answer the request with the `Unavailable` denial).

```rust
let bouncer = bouncer_io::Bouncer::new();
let conn = bouncer.door("192.0.2.30".parse()?)?;
let first = conn.request(bouncer_io::RequestId(1))?;
let second = conn.request(bouncer_io::RequestId(2))?;   // HTTP/2: both live at once
assert!(first.request(bouncer_io::RequestId(3)).is_err());
# drop((first, second));
# Ok::<(), Box<dyn std::error::Error>>(())
```

### `Ticket::checkpoint`

```rust
#[must_use] pub fn checkpoint(&mut self) -> Verdict;
```

Tier 1 · P0 · 0.3 (connection and request flags) / 0.4 (every target) · fast path median under 2 ns, p99 under 5 ns; slow path under 150 ns with 7 bound keys [est.]; no allocation

Checkpoints B4 and B6a. Loads the revocation epoch; if it equals the epoch this ticket last checked, the answer is `Pass` (one load, one compare). Only after a revocation somewhere does it look further: the ticket's own flags, its parent connection, and the revocation tables for each key it carries. A ticket whose generation no longer matches its cell (it was released and the cell reused) is denied.

Call it between every pair of pipeline stages and before encoding the response. On `Deny`, call [`deny_and_eject`](#ticketdeny_and_eject) and stop the request.

```rust
use bouncer_io::{Bouncer, Collected, Reason, RequestId, Verdict};

let bouncer = Bouncer::new();
let conn = bouncer.door("192.0.2.31".parse()?)?;
let mut request = conn.request(RequestId(1))?;
let mut reply = Collected::new();

for stage in ["route", "authorize", "load", "render"] {
    if let Verdict::Deny(_) = request.checkpoint() {
        request.deny_and_eject(&mut reply);
        break;
    }
    // ... run the stage ...
    # let _ = stage;
}
# bouncer.revoke(conn.conn(), Reason::ADMIN)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

### `Ticket::before_commit`

```rust
#[must_use] pub fn before_commit(&mut self) -> Verdict;
```

Tier 1 · P0 · 0.4 · 2-5 ns [est.]

Checkpoint B5, right before a database commit or any other side effect that cannot be undone. Uses a sequentially consistent load, paired with a fence in `revoke`, so a commit that starts after `revoke` returned in real time cannot pass. Fails closed: a stale or unknown ticket is denied.

```rust
# let bouncer = bouncer_io::Bouncer::new();
# let conn = bouncer.door("192.0.2.32".parse()?)?;
# let mut request = conn.request(bouncer_io::RequestId(1))?;
if request.before_commit().is_pass() {
    // tx.commit()?;
} else {
    // tx.rollback(); the request leaves no side effects
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

### `Ticket::is_cancelled`

```rust
pub fn is_cancelled(&mut self) -> bool;
```

Tier 1 · P0 · 0.4 · as `checkpoint`

`true` when a checkpoint now would deny. For loops inside long handlers (reports, large queries, uploads), so a revoked request stops doing work, not only stops being answered.

```rust
# let bouncer = bouncer_io::Bouncer::new();
# let conn = bouncer.door("192.0.2.33".parse()?)?;
# let mut request = conn.request(bouncer_io::RequestId(1))?;
for row in 0..1_000_000u32 {
    if row % 1024 == 0 && request.is_cancelled() { break; }
    // ... process the row ...
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

### `Ticket::bind_client`

```rust
#[must_use] pub fn bind_client(&mut self, addr: IpAddr, provenance: Provenance) -> Verdict;
```

Tier 2 · P0 · 0.3 · about the cost of the door

Checkpoint B1'. Sets the real client address learned from a trusted proxy and runs the door's allow, ban, and budget steps on it; the connection's concurrency count moves from the proxy to the client.

- **PROXY protocol:** the transport calls it on the connection ticket with `Provenance::ProxyProtocol` after the header is read under the handshake deadline.
- **Forwarded headers:** the protocol adapter calls it on each request ticket with `Provenance::ForwardedHeader`, because a proxy may carry different clients' requests over one pooled connection.

Until a client is bound under a trusted proxy hop, the request carries a pending mark and every checkpoint on it denies (fail closed), and strikes against it go nowhere (the proxy is never the target). Binding is allowed once, only from a trusted provenance, and only where the ticket's own source is unset or is a trusted proxy; anything else returns `Deny` with `DenialCode::Unavailable`.

```rust
use bouncer_io::{Bouncer, Cidr, Provenance, RequestId};

let bouncer = Bouncer::builder().trusted_proxies(&["10.0.0.0/8".parse::<Cidr>()?]).try_build()?;
let hop = bouncer.door("10.1.2.3".parse()?)?;          // our load balancer
assert_eq!(hop.source(), None);
let mut request = hop.request(RequestId(1))?;
// After parsing X-Forwarded-For from that trusted hop:
assert!(request.bind_client("198.51.100.4".parse()?, Provenance::ForwardedHeader).is_pass());
assert_eq!(request.source(), Some("198.51.100.4".parse()?));
# Ok::<(), Box<dyn std::error::Error>>(())
```

### `Ticket::bind_fingerprint`

```rust
#[must_use] pub fn bind_fingerprint(&mut self, key: FingerprintKey) -> Verdict;
```

Tier 2 · P1 · 0.4 · 15-30 ns [est.]

Checkpoint B2: the TLS adapter binds the ClientHello fingerprint digest on the connection ticket. Checks fingerprint bans (bare and within the source's prefixes) and revocations.

### `Ticket::bind_session`, `bind_account`, `bind_tenant`

```rust
#[must_use] pub fn bind_session(&mut self, key: SessionKey) -> Verdict;
#[must_use] pub fn bind_account(&mut self, key: AccountKey) -> Verdict;
#[must_use] pub fn bind_tenant(&mut self, key: TenantKey) -> Verdict;
```

Tier 1 · P0 · 0.4 · 15-30 ns each [est.]

Checkpoint B3, right after authentication. Each binds once per ticket and checks bans and revocations for the new key; `bind_tenant` also takes one slot of the tenant's in-flight budget, returned when the ticket is released. A key bound at the same moment as it is revoked on another thread is never missed by both sides (paired fences; loom model L-4).

```rust
use bouncer_io::{AccountKey, Bouncer, RequestId, SessionKey, TenantKey, Verdict};

let bouncer = Bouncer::new();
let conn = bouncer.door("192.0.2.40".parse()?)?;
let mut request = conn.request(RequestId(1))?;
// identity from the authentication gate:
let checks = [
    request.bind_session(SessionKey::from_digest([1; 16])),
    request.bind_account(AccountKey(42)),
    request.bind_tenant(TenantKey(7)),
];
if checks.iter().any(Verdict::is_deny) {
    // banned session, account, or tenant, or tenant over its budget
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

### `Ticket::bind_lane`

```rust
#[must_use] pub fn bind_lane(&mut self, lane: LaneClass) -> Verdict;
```

Tier 2 · P2 · 0.5 · about 20 ns [est.]

Selects the lane budget (`Budgets::lane_rate`) this request is charged against, keyed by session when one is bound, else by source.

### `Ticket::strike`

```rust
pub fn strike(&self, kind: StrikeKind) -> StrikeOutcome;
```

Tier 1 · P0 · 0.4 · 20-40 ns [est.]; no allocation

Reports misbehaviour seen by any layer (a failed handshake, malformed traffic, a contract violation, a failed login) against this ticket's keys. The strike is counted in a windowed counter and forwarded to the event sink for long-term scoring. When a threshold is reached, the outcome is `ThresholdObserved` in observe mode (the default: nothing is banned, an event says what would have been) or `Banned` in enforce mode. Strikes against a trusted proxy, an allow-listed source, or an unbound proxied request are `Ignored`.

```rust
use bouncer_io::{Bouncer, StrikeKind, StrikeOutcome};

let bouncer = Bouncer::new();
let conn = bouncer.door("198.51.100.66".parse()?)?;
match conn.strike(StrikeKind::Malformed) {
    StrikeOutcome::ThresholdObserved { would_ban } => eprintln!("would ban {would_ban}"),
    StrikeOutcome::Banned(id) => eprintln!("banned as {id:?}"),
    _ => {}
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

### `Ticket::deny_and_eject`

```rust
pub fn deny_and_eject(&mut self, collected: &mut Collected) -> Ejected;
pub fn deny_and_eject_with(&mut self, collected: &mut Collected, format: &dyn DenialFormat) -> Ejected;
```

Tier 1 · P0 · 0.4 · wipe 30-60 ns per KiB of capacity [est.] plus formatting and one close

Wipe, replace, eject, remember, in this order and with no early return:

| Step | What happens |
|---|---|
| 1 cancel | the ticket is marked cancelled (and revoked with `DenialCode::Forbidden` if it was not revoked already) |
| 2 wipe | the whole capacity of `collected` is overwritten with zeroes through crypt-io's guaranteed wipe; its length becomes 0 |
| 3 replace | the formatter writes the protocol's denial into `collected` (the builder's `denial_format`, or `format`) |
| 4 eject | the configured `Ejector` closes the connection abortively, after the denial bytes are flushed or after the flush deadline (100 ms), whichever is first |
| 5 remember | bans attached to the revocation are already in ban memory; bans from enforced strike thresholds are inserted here |
| 6 report | a `denial.wipe_eject` event with actor, reason, evidence, and the denial's reference |

The denial is byte-identical to an ordinary refusal of the same code: nothing in it says why. A second call on the same ticket records an event and changes nothing else. A formatter error skips the denial bytes and the eject still happens.

```rust
use bouncer_io::{Bouncer, Collected, Reason, RequestId};

let bouncer = Bouncer::new();
let conn = bouncer.door("192.0.2.50".parse()?)?;
let mut request = conn.request(RequestId(1))?;
let mut reply = Collected::new();
reply.extend_from_slice(b"secret report")?;
bouncer.revoke(RequestId(1), Reason::ADMIN)?;
if request.checkpoint().is_deny() {
    let out = request.deny_and_eject(&mut reply);
    assert!(out.wiped && !out.formatted);          // NoFormat by default
    assert!(reply.is_empty());
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

### `Ticket::tag` and `into_tag`

```rust
pub fn tag(&self) -> TicketTag;
pub fn into_tag(self) -> TicketTag;
```

Tier 3 · P0 · 0.4 · free

`tag` names this ticket as a plain 64-bit value (cell index and generation) without giving it up; a protocol engine passes a request's tag to the transport so the egress check judges exactly that request. `into_tag` gives up the handle and keeps the ticket live under its tag, for transports that store one `u64` per connection; release it later with [`Bouncer::release`](#release). A stale tag never reaches a reused cell: the generation in the tag must match.

### Release on drop

Dropping a ticket releases its cell (the generation advances, so stale handles are denied) and returns its budget slots. Dropping a connection ticket while requests are live marks them revoked with `ConnectionClosed`. A ticket may be dropped on any thread.

### `TicketId`, `TicketKind`, `TicketTag`, `LaneClass`

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)] pub struct TicketId(u64);
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum TicketKind { Connection, Request }
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)] pub struct TicketTag(u64);
impl TicketTag { pub const fn get(self) -> u64; pub const fn from_raw(raw: u64) -> TicketTag; }
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LaneClass { Critical, Admin, Auth, Write, Normal, Bulk }
```

Tier 3 (Tier 1 for `TicketKind`) · P0 (`LaneClass` P2) · 0.3 / 0.4 / 0.5

`TicketId` is for logs. `TicketTag::from_raw` accepts any value: an unknown or stale one is denied by every check that takes it. `LaneClass` mirrors the gateway's lanes.

---

## Verdicts and denials

### `Verdict`

```rust
#[must_use] #[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict { Pass, Deny(Denial) }
impl Verdict {
    pub fn is_pass(&self) -> bool;
    pub fn is_deny(&self) -> bool;
    pub fn denial(&self) -> Option<&Denial>;
}
```

Tier 1 · P0 · 0.3 · 24 bytes or less

The answer of every checkpoint and bind. Ignoring it is the bug this crate exists to prevent, so it is `#[must_use]`. A `Challenge` variant is reserved for after 1.0 (the enum is non-exhaustive).

### `Denial`

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Denial { pub code: DenialCode, pub app_code: u16, pub message: &'static str, pub reference: Reference }
```

Tier 1 · P0 · 0.4

What the protocol adapter formats: a code from a fixed set, the application code and message from the [`DenialTable`](#denialtable) fixed at build, and an opaque reference an administrator can look up. Nothing in it carries the reason.

### `DenialCode`

```rust
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DenialCode { Unavailable, NotFound, TooManyRequests, Unauthorized, Forbidden }
```

Tier 1 · P0 · 0.4

Protocol-neutral; the adapter maps it. Typical mapping:

| Code | HTTP (RFC 9110, RFC 6585) | WebSocket (RFC 6455) | Database wire |
|---|---|---|---|
| `Unavailable` | 503 | 1013 | server busy |
| `NotFound` | 404 | 1008 | not found |
| `TooManyRequests` | 429 | 1008 | throttled |
| `Unauthorized` | 401 | 1008 | authentication required |
| `Forbidden` | 403 | 1008 | permission denied |

Revocations deny with `Forbidden` unless the directive says otherwise; a route that must hide that a resource exists asks for `NotFound` (`Directive::deny_with`). When a ticket is revoked twice the stronger code is kept (`Forbidden` above `Unauthorized` above `TooManyRequests` above `NotFound` above `Unavailable`); bytes already formatted never change.

### `DenialTable`

```rust
#[derive(Clone, Debug)]
pub struct DenialTable { /* one entry per DenialCode */ }
impl DenialTable {
    pub fn new() -> DenialTable;
    pub fn message(self, code: DenialCode, message: &'static str) -> DenialTable;
    pub fn app_code(self, code: DenialCode, app_code: u16) -> DenialTable;
}
impl Default for DenialTable;   // plain messages: "Service unavailable.", "Not found.", "Too many requests.", "Unauthorized.", "Forbidden."
```

Tier 2 · P0 · 0.4

Fixed at build so a denial can never carry text made from the request. Messages longer than 256 bytes are refused at `try_build` (`Config(MessageTooLong)`).

```rust
use bouncer_io::{Bouncer, DenialCode, DenialTable};
let bouncer = Bouncer::builder()
    .denials(DenialTable::new().message(DenialCode::Forbidden, "Request refused.").app_code(DenialCode::Forbidden, 4031))
    .try_build()?;
# Ok::<(), bouncer_io::BouncerError>(())
```

### `Reference`

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Reference(u64);
impl Display for Reference;   // 16 hex digits
```

Tier 1 · P0 · 0.4

64 random bits from a per-bouncer stream. It indexes the event so an administrator can look the denial up; it carries no information.

---

## `Collected`

```rust
pub struct Collected { /* fixed-capacity heap buffer, length, limit */ }
impl Collected {
    pub fn new() -> Collected;
    pub fn with_capacity(capacity: usize, limit: usize) -> Result<Collected, BouncerError>;
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn capacity(&self) -> usize;
    pub fn limit(&self) -> usize;
    pub fn as_slice(&self) -> &[u8];
    pub fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<(), BouncerError>;
    pub fn spare(&mut self, want: usize) -> Result<&mut [u8], BouncerError>;
    pub fn commit(&mut self, written: usize) -> Result<(), BouncerError>;
    pub fn truncate(&mut self, len: usize);
    pub fn clear(&mut self);
    pub fn wipe(&mut self);
}
impl Default for Collected;
impl Drop for Collected;            // wipes the whole capacity
impl std::io::Write for Collected;  // bounded by the limit; a full buffer is an error of kind WriteZero
// Debug prints the length and capacity only, never the contents.
```

Tier 1 (`new`, `extend_from_slice`, `wipe`, accessors) / Tier 3 (`spare`, `commit`) · P0 · 0.4

The buffer a response is collected in, so that "wipe" means overwritten, not dropped. It never reallocates in place: growth (doubling, up to `limit`) allocates a new block, copies, and wipes the old block before freeing it, which closes the gap that a plain `Vec` leaves (`Vec` growth copies and frees the old block without clearing it). Every wipe goes through crypt-io's volatile writes, which the optimizer cannot remove.

| Call | Wipes | Cost |
|---|---|---|
| `clear` | the used part; keeps the capacity, for reuse between requests | 30-60 ns per KiB used [est.] |
| `truncate(len)` | the cut part | per KiB cut |
| `wipe`, `Drop` | the whole capacity, whatever was used, so the time does not depend on the content | per KiB of capacity |

`new` preallocates 16 KiB with a 1 MiB limit.

**Errors:** `CollectedFull { capacity, needed }` past the limit; `InvalidCommit` when `commit` claims more than `spare` gave; `Config(TooLarge)` from `with_capacity` when capacity exceeds limit.

```rust
use bouncer_io::Collected;
use std::io::Write;

let mut reply = Collected::with_capacity(4096, 64 * 1024)?;
write!(reply, "{{\"balance\":{}}}", 1204)?;
assert_eq!(reply.as_slice(), b"{\"balance\":1204}");
reply.wipe();
assert!(reply.is_empty());
# Ok::<(), Box<dyn std::error::Error>>(())
```

```rust
// Encoders can write in place.
let mut reply = bouncer_io::Collected::new();
let room = reply.spare(5)?;
room.copy_from_slice(b"hello");
reply.commit(5)?;
assert_eq!(reply.len(), 5);
# Ok::<(), bouncer_io::BouncerError>(())
```

---

## Formatting and ejection hooks

### `DenialFormat` and `NoFormat`

```rust
pub trait DenialFormat: Send + Sync {
    /// Write the protocol's denial for `denial` into `out`, which is already wiped.
    /// Must not allocate. Must not write anything but the code, app code, message, and reference.
    fn format(&self, denial: &Denial, out: &mut Collected) -> Result<(), FormatError>;
}
pub struct NoFormat;
impl DenialFormat for NoFormat;   // writes nothing: the connection is closed without a reply
```

Tier 3 (`DenialFormat`) / Tier 2 (`NoFormat`) · P0 · 0.4 · about 100 ns per denial [est.]

Implemented by protocol adapters (the HTTP adapter, ws-net, the database wire). Output is bounded by `MAX_DENIAL_BYTES` (1,024). To keep denials identical to ordinary refusals, the adapter uses the same body and headers it uses for its own refusals of that code.

```rust
use bouncer_io::{Collected, Denial, DenialCode, DenialFormat, FormatError};
use std::io::Write;

struct Http;
impl DenialFormat for Http {
    fn format(&self, d: &Denial, out: &mut Collected) -> Result<(), FormatError> {
        let status = match d.code { DenialCode::Forbidden => "403 Forbidden", DenialCode::NotFound => "404 Not Found",
                                    DenialCode::TooManyRequests => "429 Too Many Requests",
                                    DenialCode::Unauthorized => "401 Unauthorized", _ => "503 Service Unavailable" };
        write!(out, "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}", d.message.len(), d.message)
            .map_err(|_| FormatError::TooLarge)
    }
}
```

### `Ejector` and `CloseKind`

```rust
pub trait Ejector: Send + Sync {
    fn eject(&self, conn: ConnId, kind: CloseKind);
}
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseKind { Abort, AfterFlush { deadline: Duration } }
```

Tier 3 · P0 · 0.4

How bouncer closes a connection it is not holding: from `deny_and_eject`, from eject-now sweeps, and from checks on idle tickets. The integration implements it over the transport's kill handle (net-io closes with `SO_LINGER` 0). Fire and forget: failures are the transport's events.

### `Ejected`

```rust
#[non_exhaustive] #[derive(Clone, Copy, Debug)]
pub struct Ejected { pub wiped: bool, pub formatted: bool, pub ejected: bool, pub remembered: bool, pub reference: Reference }
```

Tier 1 · P0 · 0.4

What `deny_and_eject` did. `ejected` is `false` when no `Ejector` is configured: the caller must close the connection itself.

---

## Revocation

### `Target`

```rust
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Target {
    Connection(ConnId), Request(RequestId), Session(SessionKey), Account(AccountKey),
    Tenant(TenantKey), Source(Cidr), Fingerprint(FingerprintKey),
}
impl From<ConnId> for Target; impl From<RequestId> for Target; impl From<SessionKey> for Target;
impl From<AccountKey> for Target; impl From<TenantKey> for Target; impl From<Cidr> for Target;
impl From<IpAddr> for Target; impl From<FingerprintKey> for Target;
```

Tier 1 · P0 · 0.4

What to revoke. `Source` covers every ticket whose source falls inside the prefix; a trusted proxy inside it is not revoked, its real clients are.

### `RevokeMode`

```rust
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum RevokeMode { #[default] AtCheckpoint, EjectNow }
```

Tier 2 · P0 (`EjectNow` P1) · 0.4 · `AtCheckpoint` O(1); `EjectNow` adds a sweep of live tickets, under 1 ms for 65,536 [est.], coalesced

`AtCheckpoint` denies at the next checkpoint. `EjectNow` also queues a sweep that closes matching connections that are not crossing checkpoints (idle keep-alive, parked WebSockets) through the `Ejector`. A full sweep queue still applies the revocation and reports `SweepQueueFull` in the event.

### `Revocation`

```rust
#[non_exhaustive] #[derive(Clone, Copy, Debug)]
pub struct Revocation { pub epoch: u64, pub reference: Reference, pub matched_live: Option<u32> }
```

Tier 1 · P0 · 0.4

The receipt. `epoch` is the epoch value that carries this revocation; `matched_live` is filled by an eject-now sweep run inline (no maintainer thread); with a maintainer thread the sweep runs there and it is `None`. Receipts, like `Applied` and `Lifted`, are not `#[must_use]`: `bouncer.revoke(session, Reason::LOGOUT)?;` reads without noise (decision D-045).

### `RevocationEpoch`

```rust
pub struct RevocationEpoch { /* AtomicU64 alone on its cache line */ }
impl RevocationEpoch { pub fn new() -> RevocationEpoch; pub fn current(&self) -> u64; }
impl Default for RevocationEpoch;
```

Tier 3 · P1 · 0.4 · one load

The word every checkpoint reads. By default each bouncer owns one; a security core that owns its process's shared security state passes its own with [`BouncerBuilder::epoch`](#bouncerbuilder-1), so other modules can read the same word.

```rust
use bouncer_io::{Bouncer, RevocationEpoch};
use std::sync::Arc;

let epoch = Arc::new(RevocationEpoch::new());          // owned by the security core
let bouncer = Bouncer::builder().epoch(epoch.clone()).try_build()?;
let before = epoch.current();
bouncer.revoke(bouncer_io::AccountKey(1), bouncer_io::Reason::ADMIN)?;
assert!(epoch.current() > before);
# Ok::<(), bouncer_io::BouncerError>(())
```

---

## Bans and the allow list

Ban memory has two structures: a dynamic table (one keyed hash table per prefix length in use, plus identity keys) for automatic and directive bans, which change often; and a compiled prefix set for administrator lists, imported feeds, and the allow list, which change rarely and are rebuilt and swapped whole. Expiry is lazy: an expired entry reads as absent and is reclaimed by the next writer or by maintenance. No timer exists per ban.

### `BanSpec`

```rust
#[non_exhaustive] #[derive(Clone, Debug)]
pub struct BanSpec { pub key: BanKey, pub duration: BanDuration, pub actor: Actor, pub reason: Reason, pub evidence: Evidence<'static> }
impl BanSpec {
    pub fn key(key: impl Into<BanKey>) -> BanSpec;
    pub fn address(addr: IpAddr) -> BanSpec;
    pub fn prefix(cidr: Cidr) -> BanSpec;
    pub fn for_duration(self, duration: Duration) -> BanSpec;
    pub fn permanent(self) -> BanSpec;
    pub fn by(self, actor: Actor) -> BanSpec;
    pub fn because(self, reason: Reason) -> BanSpec;
    pub fn evidence(self, evidence: Evidence<'static>) -> BanSpec;
}
impl From<IpAddr> for BanSpec; impl From<Cidr> for BanSpec; impl From<BanKey> for BanSpec;
```

Tier 1 · P0 · 0.3

Describes a ban. The defaults are the duration policy, `Actor::App`, and `Reason::ADMIN`. `permanent` is refused at `ban` time for `Actor::Local`, `Actor::Policy`, and `Actor::Channel` (`PermanentNotAllowed`); administrators, the application, sentinel, and definitive strikes (a decoy touch) may ban permanently.

### `BanDuration`

```rust
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum BanDuration { #[default] Policy, Fixed(Duration), Permanent }
```

Tier 2 · P0 · 0.3 · `Fixed(Duration::ZERO)` is refused (`InvalidDuration`)

### `LiftSpec` and `Lifted`

```rust
#[non_exhaustive] #[derive(Clone, Copy, Debug)]
pub struct LiftSpec { pub key: BanKey, pub actor: Actor, pub reason: Reason }
impl LiftSpec { pub fn key(key: impl Into<BanKey>) -> LiftSpec; pub fn by(self, actor: Actor) -> LiftSpec; pub fn because(self, reason: Reason) -> LiftSpec; }
impl From<IpAddr> for LiftSpec; impl From<Cidr> for LiftSpec; impl From<BanKey> for LiftSpec;

#[non_exhaustive] #[derive(Clone, Copy, Debug)]
pub struct Lifted { pub removed: u32, pub tombstone: BanId }
```

Tier 1 · P0 · 0.3

### `BanId` and `BanRecord`

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)] pub struct BanId(u64);
#[non_exhaustive] #[derive(Clone, Debug)]
pub struct BanRecord {
    pub id: BanId, pub key: BanKey, pub until: Option<SystemTime>, pub issued: SystemTime,
    pub actor: ActorKind, pub reason: Reason, pub offences: u16, pub origin: Option<NodeId>,
}
```

Tier 2 · P0 · 0.3

`until` is `None` for permanent bans. `origin` is the node that issued it, when it came from another node.

### `DurationPolicy`

```rust
#[non_exhaustive] #[derive(Clone, Copy, Debug)]
pub struct DurationPolicy { /* base, factor, step_cap, max, jitter */ }
impl DurationPolicy {
    pub fn base(self, d: Duration) -> Self;     // default 10 minutes
    pub fn factor(self, f: u32) -> Self;        // default 2
    pub fn step_cap(self, n: u8) -> Self;       // default 20
    pub fn max(self, d: Duration) -> Self;      // default 7 days
    pub fn jitter(self, d: Duration) -> Self;   // default 60 seconds
    pub fn half_life(self, d: Duration) -> Self; // default 24 hours: offender memory decay
}
impl Default for DurationPolicy;
```

Tier 2 · P0 · 0.3

`duration = min(base * factor^min(offences, step_cap), max) + random(0..=jitter)`, saturating. Offences come from offender memory, so a returning offender's next ban is longer even after the last one expired. The jitter stops an attacker timing its return to the second. This is fail2ban's `bantime.increment` formula with `bantime.maxtime` and `bantime.rndtime`.

```rust
use bouncer_io::DurationPolicy;
use std::time::Duration;
let policy = DurationPolicy::default().base(Duration::from_secs(300)).factor(3).max(Duration::from_secs(86_400));
```

### `EscalationPolicy`

```rust
#[non_exhaustive] #[derive(Clone, Copy, Debug)]
pub struct EscalationPolicy { /* thresholds, window, factor, widest prefixes, per-parent quota */ }
impl EscalationPolicy {
    pub fn ipv4_threshold(self, children: u16) -> Self;      // default 8 distinct /32 in one /24
    pub fn ipv6_threshold(self, children: u16) -> Self;      // default 4 distinct /64 in one /56, and /56 in one /48
    pub fn window(self, d: Duration) -> Self;                // default 1 hour
    pub fn factor(self, f: u32) -> Self;                     // default 2
    pub fn widest_ipv4(self, len: u8) -> Self;               // default /24
    pub fn widest_ipv6(self, len: u8) -> Self;               // default /48
    pub fn max_children_per_parent(self, n: u16) -> Self;    // default 64
    pub fn off(self) -> Self;
}
impl Default for EscalationPolicy;
```

Tier 2 · P1 · 0.5

When enough distinct children of one parent prefix are banned within the window, the parent is banned (for the longest remaining child duration times `factor`, capped by the duration policy's `max`) and the children are folded into it, which also frees table space. Escalation never crosses an allow-list entry, a trusted proxy, or an address flagged as shared (likely carrier-grade NAT), and never goes wider than the configured widest prefix. Escalations started by local heuristics follow the enforcement mode (observe by default). The per-parent quota means an attacker in one allocation cannot fill the table to push out other bans: past the quota, inserting forces escalation.

### `AllowList` and `AllowKind`

```rust
#[derive(Clone, Debug, Default)]
pub struct AllowList { /* entries; compiled when given to the bouncer */ }
impl AllowList {
    pub fn new() -> AllowList;
    pub fn immune(self, cidr: Cidr, label: &'static str) -> AllowList;
    pub fn exempt_budgets(self, cidr: Cidr, label: &'static str) -> AllowList;
}
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllowKind { Immune, ExemptBudgets }
```

Tier 1 · P0 (`exempt_budgets` P1) · 0.3 / 0.4 · compiled in milliseconds; one trie walk per door check

`immune` entries (own infrastructure, partners) can never be banned, throttled, struck, or revoked by automation; an administrator ban of one is refused with `AllowListed` until the entry is removed. `exempt_budgets` entries (load balancer health checkers) skip rate and concurrency budgets but can still be banned. The allow list is compiled and swapped whole; readers never wait.

---

## Directives

### `Directive`

```rust
#[non_exhaustive] #[derive(Clone, Debug)]
pub struct Directive { pub action: Action, pub target: Target, pub actor: Actor, pub reason: Reason, pub confidence: Option<u8>, /* options */ }
impl Directive {
    pub fn ban(key: impl Into<Target>) -> Directive;
    pub fn revoke(target: impl Into<Target>) -> Directive;
    pub fn revoke_and_ban(target: impl Into<Target>) -> Directive;
    pub fn throttle(key: impl Into<Target>, factor: u8, duration: Duration) -> Directive;
    pub fn lift(key: impl Into<Target>) -> Directive;

    pub fn by(self, actor: Actor) -> Directive;
    pub fn because(self, reason: Reason) -> Directive;
    pub fn confidence(self, value: u8) -> Directive;           // 0-100, STIX scale; absent = not judged
    pub fn for_duration(self, duration: Duration) -> Directive;
    pub fn permanent(self) -> Directive;
    pub fn eject_now(self) -> Directive;
    pub fn keep_connection(self) -> Directive;
    pub fn ban_keys(self, keys: BanKeys) -> Directive;
    pub fn deny_with(self, code: DenialCode) -> Directive;
    pub fn evidence(self, evidence: Evidence<'static>) -> Directive;
}
```

Tier 2 · P0 · 0.4

A decision made elsewhere, carried to [`Bouncer::apply`](#apply). Reads as a sentence: `Directive::revoke(session).by(Actor::Gate).because(Reason::LOGOUT_EVERYWHERE)`.

| Option | Effect | Default |
|---|---|---|
| `eject_now` | revoke with `RevokeMode::EjectNow` | `AtCheckpoint` |
| `keep_connection` | revoking a request leaves its connection open (for an administrator ending one request on a multiplexed connection) | the connection is ejected with the request |
| `ban_keys` | which of the ticket's keys `revoke_and_ban` bans when the target is a connection or request | the source at the automatic prefix; the session instead when the source is flagged shared |
| `deny_with` | the denial code the revoked request gets | `Forbidden` |
| `for_duration`, `permanent` | the ban part's duration | the duration policy |
| `confidence` | below 30 (under the Medium band) a directive cannot ban by itself; it is applied as a throttle and an event records why | absent: treated as Medium for explicit actors |

```rust
use bouncer_io::{Actor, BanKeys, Bouncer, ConnId, DenialCode, Directive, Reason};

let bouncer = Bouncer::new();
bouncer.apply(
    Directive::revoke_and_ban(ConnId(77))
        .by(Actor::Admin(3))
        .because(Reason::ADMIN)
        .ban_keys(BanKeys::SOURCE | BanKeys::ACCOUNT)
        .deny_with(DenialCode::NotFound),
)?;
# Ok::<(), bouncer_io::BouncerError>(())
```

### `Action`

```rust
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Throttle { factor: u8, duration: Duration },
    Ban(BanDuration),
    Revoke(RevokeMode),
    RevokeAndBan(RevokeMode, BanDuration),
    Lift,
}
```

Tier 2 · P0 (`Throttle` P1) · 0.4

`Throttle` divides the key's budgets by `factor` (2 to 16) for the duration (the security policy's "throttle" threshold). A `Challenge` action is reserved for after 1.0.

### `BanKeys`

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BanKeys(u8);
impl BanKeys {
    pub const SOURCE: BanKeys; pub const FINGERPRINT_IN_PREFIX: BanKeys;
    pub const SESSION: BanKeys; pub const ACCOUNT: BanKeys; pub const TENANT: BanKeys;
}
impl BitOr for BanKeys;
```

Tier 2 · P0 · 0.4

### `Actor`

```rust
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Actor { App, Admin(u64), Policy(u32), Sentinel, Gate, Channel(u64), Local }
impl Actor {
    pub const fn is_automated(&self) -> bool;          // every actor except App and Admin
    pub const fn may_ban_permanently(&self) -> bool;   // App, Admin, Sentinel
    pub const fn kind(&self) -> ActorKind;
}
impl Display for Actor;
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ActorKind { App, Admin, Policy, Sentinel, Gate, Channel, Local }   // stored in compact records
```

Tier 1 · P0 · 0.3

Who acted; recorded on every ban and event.

| Actor | Who | Enforcement | May ban permanently | Touches allow-listed keys |
|---|---|---|---|---|
| `App` | the application's own code (the Tier 1 calls) | always | yes | refused with `AllowListed` |
| `Admin(id)` | a named administrator | always | yes | refused with `AllowListed` |
| `Policy(rule)` | the security signals policy | always | no | never |
| `Sentinel` | sentinel-sec | always | yes | never |
| `Gate` | the authentication and authorization gates | always | no | never |
| `Channel(node)` | another node or the back-channel | always, import rate limited | no | never |
| `Local` | bouncer's own strike thresholds | observe by default, enforce per category | no (except a decoy touch) | never |

### `Reason`

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Reason(u16);
impl Reason {
    pub const ADMIN: Reason; pub const LOGOUT: Reason; pub const LOGOUT_EVERYWHERE: Reason;
    pub const PASSWORD_CHANGED: Reason; pub const STANDING_CHANGED: Reason; pub const POLICY: Reason;
    pub const STRIKE_THRESHOLD: Reason; pub const DECOY: Reason; pub const IMPORTED: Reason;
    pub const CONNECTION_CLOSED: Reason; pub const LOCKDOWN: Reason; pub const BUDGET: Reason;
    pub const fn custom(code: u16) -> Reason;   // project codes, 1000 and above (lower values are clamped up)
    pub const fn code(self) -> u16;
}
```

Tier 1 · P0 · 0.3

A catalog code. It goes to events and audit, never to the subject.

### `Evidence`

```rust
#[derive(Clone, Copy, Debug, Default)]
pub struct Evidence<'a> { /* borrowed pairs */ }
impl<'a> Evidence<'a> {
    pub const fn none() -> Evidence<'static>;
    pub const fn new(pairs: &'a [(&'static str, EvidenceValue<'a>)]) -> Evidence<'a>;
}
#[non_exhaustive] #[derive(Clone, Copy, Debug)]
pub enum EvidenceValue<'a> { Number(u64), Text(&'a str), Address(IpAddr), Duration(Duration), Flag(bool) }
```

Tier 2 · P0 · 0.3 · borrowed, no allocation

Bounded key-value evidence (at most `MAX_EVIDENCE_BYTES`, 256 bytes; anything beyond is cut and the event is flagged truncated, the action still happens). There is no variant for session or fingerprint digests, so secrets cannot end up in evidence.

```rust
use bouncer_io::{Evidence, EvidenceValue};
static PAIRS: [(&str, EvidenceValue<'static>); 2] =
    [("failed_logins", EvidenceValue::Number(12)), ("window_s", EvidenceValue::Number(600))];
let evidence = Evidence::new(&PAIRS);
# let _ = evidence;
```

### `Applied`

```rust
#[non_exhaustive] #[derive(Clone, Copy, Debug, Default)]
pub struct Applied { pub ban: Option<BanId>, pub bans: u32, pub revocation: Option<Revocation>, pub lifted: Option<Lifted>, pub throttled: bool, pub downgraded: bool }
```

Tier 2 · P0 · 0.4

`downgraded` is `true` when a low-confidence ban was applied as a throttle.

---

## Strikes and enforcement

### `StrikeKind`

```rust
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StrikeKind {
    HandshakeFailed, ProxyViolation, TlsAlert, Malformed, ContractViolation,
    SlowPeer, LoginFailed, AuthzDenied, TombstoneReuse, DecoyTouched, Custom(u16),
}
```

Tier 1 · P0 · 0.4

What each layer reports: the transport (handshake, PROXY, slow peer), the TLS adapter, protocol engines (malformed traffic), customs-sec (contract violations), the gates (failed logins, authorization denials, reuse of a revoked session token). `DecoyTouched` (a decoy from sentinel-sec) is definitive: it revokes and bans at once, whatever the mode.

### `StrikeOutcome`

```rust
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StrikeOutcome {
    Counted,
    ThresholdObserved { would_ban: BanKey },
    Banned(BanId),
    Throttled,
    Ignored(IgnoredBecause),
}
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IgnoredBecause { TrustedProxy, AllowListed, UnverifiedSource, PendingClient, Released, CounterTableFull }
```

Tier 1 · P0 · 0.4

`Throttled` is what an enforced threshold does to a source flagged as shared (likely NAT): bouncer throttles the address and bans the identity keys instead of punishing everyone behind it.

### `StrikeRules`

```rust
#[derive(Clone, Debug)]
pub struct StrikeRules { /* per kind: weight, window, threshold, ban duration policy */ }
impl StrikeRules {
    pub fn rule(self, kind: StrikeKind, weight: u16, threshold: u16, window: Duration) -> StrikeRules;
    pub fn duration(self, kind: StrikeKind, policy: DurationPolicy) -> StrikeRules;
}
impl Default for StrikeRules;   // weight 1, threshold 5 within 10 minutes for every kind; DecoyTouched definitive
```

Tier 2 · P0 · 0.4

### `Enforcement` and `Mode`

```rust
#[derive(Clone, Debug)]
pub struct Enforcement { /* mode per strike kind, plus the strict-posture set */ }
impl Enforcement {
    pub fn observe_all() -> Enforcement;
    pub fn enforce_all() -> Enforcement;
    pub fn enforce(self, kind: StrikeKind) -> Enforcement;
    pub fn observe(self, kind: StrikeKind) -> Enforcement;
    pub fn strict(self, kinds: &[StrikeKind]) -> Enforcement;
    pub fn mode(&self, kind: StrikeKind, posture: Posture) -> Mode;
}
impl Default for Enforcement;   // observe_all
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode { Observe, Enforce }
```

Tier 2 · P0 · 0.4

Detection on, enforcement off: bouncer's own heuristics observe until a project switches categories to enforce, so the library never blocks what a project did not ask it to block. Explicit commands (administrators, the application, gates, policy, sentinel) always act. `strict` lists the kinds that switch to enforce under `Posture::Strict`.

```rust
use bouncer_io::{Bouncer, Enforcement, StrikeKind};
let bouncer = Bouncer::builder()
    .enforcement(
        Enforcement::observe_all()
            .enforce(StrikeKind::ProxyViolation)
            .strict(&[StrikeKind::Malformed, StrikeKind::LoginFailed]),
    )
    .try_build()?;
# Ok::<(), bouncer_io::BouncerError>(())
```

---

## Budgets

Budgets answer "is this source over its allowance". They are one input to the door and to the identity checkpoint, never the purpose of the crate. The rate math is rate-net's GCRA and better-bucket's token bucket (both without default features, so neither brings a third-party crate); the keyed storage is bouncer's own bounded table.

### `Budgets`

```rust
#[derive(Clone, Debug)]
pub struct Budgets { /* door rate, door concurrency, lane rates, tenant rate and plans, tenant in-flight, capacity */ }
impl Budgets {
    pub fn off() -> Budgets;
    pub fn door_rate(self, per_address: Rate, per_prefix: Rate) -> Budgets;
    pub fn door_concurrency(self, per_address: u32, per_prefix: u32) -> Budgets;
    pub fn lane_rate(self, lane: LaneClass, per_key: Rate) -> Budgets;
    pub fn tenant_rate(self, default: Rate) -> Budgets;
    pub fn tenant_plan(self, tenant: TenantKey, rate: Rate) -> Budgets;
    pub fn tenant_in_flight(self, default: u32) -> Budgets;
    pub fn capacity(self, keys: u32) -> Budgets;
}
impl Default for Budgets;   // door: 20/s burst 40 and 64 concurrent per client; 200/s and 512 concurrent per prefix
// A client is an IPv4 address or an IPv6 /64 (one host controls its /64); its prefix is the IPv4 /24 or IPv6 /48.
```

Tier 2 · P1 (lanes and tenants P2) · 0.4 / 0.5 · door share 20-30 ns [est.]

| Budget | Key | Checked at | Algorithm |
|---|---|---|---|
| accept rate | address, then prefix, then global | door | GCRA (rate-net) |
| concurrency | address, then prefix | door; returned on release | atomic counter |
| lane rate | session or source, per lane | `bind_lane` | GCRA |
| tenant rate | tenant | `bind_tenant` | token bucket (better-bucket) |
| tenant in-flight | tenant | `bind_tenant`; returned on release | atomic counter |
| throttle | any key | where the key's class is checked | divides the key's quota |

**Eviction never resets a limit.** The budget table evicts only keys that have fully recovered. When it is full and nothing has recovered, a new key is charged against its parent prefix, then the global budget: a flood of new addresses cannot lock everyone out, and a key cannot reset itself by flooding.

Door-level budget refusals close abortively like every refusal; identity-level ones deny with `TooManyRequests` and the retry hint goes to the event.

```rust
use bouncer_io::{Bouncer, Budgets, Rate, TenantKey};
let bouncer = Bouncer::builder()
    .budgets(
        Budgets::default()
            .door_rate(Rate::per_second(50).burst(100), Rate::per_second(500))
            .tenant_rate(Rate::per_second(200))
            .tenant_plan(TenantKey(7), Rate::per_second(2_000).burst(4_000))
            .tenant_in_flight(64),
    )
    .try_build()?;
# Ok::<(), bouncer_io::BouncerError>(())
```

### `Rate`

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rate { /* limit per period, burst */ }
impl Rate {
    pub const fn per_second(limit: u32) -> Rate;
    pub const fn per_minute(limit: u32) -> Rate;
    pub fn new(limit: u32, period: Duration) -> Result<Rate, BouncerError>;
    pub const fn burst(self, burst: u32) -> Rate;   // default: equal to the limit
    pub const fn limit(&self) -> u32;
    pub const fn burst_size(&self) -> u32;
}
```

Tier 2 · P1 · 0.4

bouncer's own rate type, converted to rate-net's and better-bucket's internally, so a new major version of either never changes bouncer's API.

---

## Administration

### `Explanation`

```rust
#[non_exhaustive] #[derive(Clone, Debug)]
pub struct Explanation {
    pub key: BanKey, pub admitted: bool, pub allow: Option<AllowKind>,
    pub bans: Vec<BanRecord>, pub offender: Option<OffenderRecord>,
    pub budgets: Vec<BudgetState>, pub strikes: Vec<StrikeState>,
    pub shared_source: bool, pub live_tickets: u32,
}
impl Display for Explanation;
#[non_exhaustive] #[derive(Clone, Copy, Debug)] pub struct OffenderRecord { pub offences: f32, pub last: SystemTime }
#[non_exhaustive] #[derive(Clone, Copy, Debug)] pub struct BudgetState { pub class: &'static str, pub key: BanKey, pub remaining: u32, pub retry_after: Option<Duration> }
#[non_exhaustive] #[derive(Clone, Copy, Debug)] pub struct StrikeState { pub kind: StrikeKind, pub count: u16, pub threshold: u16, pub mode: Mode }
```

Tier 1 · P1 · 0.5

The answer to "why is this refused" (or "why not"), with every cause, its actor, reason, and remaining time.

### `Filter`, `Page`, `Listing`

```rust
#[derive(Clone, Debug, Default)]
pub struct Filter { /* family, key kind, actor, reason, expiring before, within prefix */ }
impl Filter {
    pub fn all() -> Filter;
    pub fn family(self, family: Family) -> Filter;
    pub fn within(self, prefix: Cidr) -> Filter;
    pub fn by(self, actor: Actor) -> Filter;
    pub fn because(self, reason: Reason) -> Filter;
    pub fn expiring_before(self, at: SystemTime) -> Filter;
    pub fn permanent_only(self) -> Filter;
}
#[derive(Clone, Copy, Debug)] pub struct Page { /* after, limit */ }
impl Page { pub fn first(limit: u16) -> Page; pub const fn limit(&self) -> u16; }   // limit 1 to 1,000
#[non_exhaustive] #[derive(Clone, Debug)]
pub struct Listing { pub items: Vec<BanRecord>, pub next: Option<Page>, pub total: u64 }
```

Tier 2 · P1 · 0.5

```rust
use bouncer_io::{Bouncer, Filter, Page};
let bouncer = Bouncer::new();
let mine = bouncer.list(&Filter::all().within("203.0.113.0/24".parse()?), Page::first(50));
println!("{} bans inside 203.0.113.0/24", mine.total);
# Ok::<(), Box<dyn std::error::Error>>(())
```

---

## Events

Every action produces an event: refusal, ban, lift, escalation, expiry, eviction, revocation, denial, ejection, strike, threshold, import, persistence failure. Events are how bouncer joins the security signal bridge: the sink forwards them to the security core, audit, and sentinel-sec, so an attack bouncer sees is known everywhere at once, and other modules' decisions come back through [`apply`](#apply).

### `EventSink` and `NoSink`

```rust
pub trait EventSink: Send + Sync {
    /// Must not block. Copy what you keep; the event borrows its evidence.
    fn event(&self, event: &Event<'_>);
}
pub struct NoSink;
impl EventSink for NoSink;
```

Tier 2 (`NoSink` Tier 3) · P0 · 0.4 · 20-50 ns into a ring buffer [est.]; with no sink, one predictable branch on cold paths only

Refusals under a flood are sampled: the first refusal per ban per 10 seconds is an event, carrying the exact count since the last one. Checkpoints never emit on the fast path.

```rust
use bouncer_io::{Bouncer, Event, EventSink};
use std::sync::Arc;

struct Print;
impl EventSink for Print {
    fn event(&self, e: &Event<'_>) { eprintln!("{} {} x{}", e.signal, e.path, e.count); }
}
let bouncer = Bouncer::builder().event_sink(Arc::new(Print)).try_build()?;
# Ok::<(), bouncer_io::BouncerError>(())
```

### `Event`

```rust
#[non_exhaustive] #[derive(Clone, Copy, Debug)]
pub struct Event<'a> {
    pub signal: SignalId, pub path: &'static str, pub category: Category,
    pub severity: f32, pub confidence: Option<u8>,
    pub at: Now, pub wall: SystemTime,
    pub actor: Actor, pub reason: Reason, pub subject: Subject,
    pub reference: Reference, pub count: u32, pub mode: Mode,
    pub evidence: Evidence<'a>, pub truncated: bool,
}
```

Tier 2 · P0 · 0.4

Fixed size, no allocation. `severity` is the catalog default on the 0-10 scale; `confidence` is the 0-100 scale; `mode` is `Observe` for "would ban" events.

### `SignalId`, `Category`, `Subject`

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SignalId { pub generator: u16, pub id: u32, pub revision: u16 }
impl Display for SignalId;   // "bouncer/11 r1"
pub const GENERATOR: u16 = 2;

#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Category { Unknown, Recon, Access, Auth, Injection, Abuse, Privilege, Exfil, Integrity, Policy, Anomaly, Other }

#[non_exhaustive] #[derive(Clone, Copy, Debug, Default)]
pub struct Subject {
    pub conn: Option<ConnId>, pub request: Option<RequestId>, pub source: Option<IpAddr>, pub prefix: Option<Cidr>,
    pub session: Option<SessionKey>, pub account: Option<AccountKey>, pub tenant: Option<TenantKey>,
    pub fingerprint: Option<FingerprintKey>,
}
```

Tier 2 · P0 · 0.4

Identity, categories, and the axes follow the security signals vocabulary: the id says what was detected; how bad and how sure live in the event. bouncer's generator id is 2 (platform generators are below 1000). Digests in `Subject` print redacted.

### Signal catalog

```rust
pub mod signals { pub const DOOR_REFUSED_BAN: SignalId; /* one constant per row below */ }
```

| Id | Constant | Path | Category | Severity | When |
|---|---|---|---|---|---|
| 1 | `DOOR_REFUSED_BAN` | `bouncer.door.refused.ban` | access | 3.0 | a banned source tried to connect (sampled) |
| 2 | `DOOR_REFUSED_BUDGET` | `bouncer.door.refused.budget` | abuse | 2.0 | over accept rate or concurrency (sampled) |
| 3 | `DOOR_REFUSED_REGISTRY_FULL` | `bouncer.door.refused.registry_full` | abuse | 4.0 | no free ticket (sampled) |
| 4 | `DOOR_PROXY_HOP_UNRESOLVED` | `bouncer.door.proxy_hop_unresolved` | integrity | 5.0 | a proxied request ended without binding its real client |
| 5 | `BUDGET_REFUSED` | `bouncer.budget.refused` | abuse | 2.0 | over a lane, tenant rate, or tenant in-flight budget |
| 10 | `REVOKE_APPLIED` | `bouncer.revoke.applied` | access | from the directive | any revocation |
| 11 | `DENIAL_WIPE_EJECT` | `bouncer.denial.wipe_eject` | access | from the directive | a request was wiped, denied, and ejected |
| 12 | `COMMIT_BLOCKED` | `bouncer.commit.blocked` | integrity | 6.0 | a before-commit checkpoint denied |
| 13 | `EGRESS_BLOCKED` | `bouncer.egress.blocked` | integrity | 6.0 | a transport egress check denied |
| 14 | `CHECKPOINT_MISSING` | `bouncer.checkpoint.missing` | integrity | 5.0 | a revoked ticket went `max_unchecked` without crossing a checkpoint (a pipeline gap) |
| 15 | `POSTURE_CHANGED` | `bouncer.posture.changed` | policy | 4.0 | the posture changed |
| 20 | `BAN_ADDED` | `bouncer.ban.added` | access | from the directive | ban inserted |
| 21 | `BAN_ESCALATED` | `bouncer.ban.escalated` | access | 5.0 | prefix escalation |
| 22 | `BAN_LIFTED` | `bouncer.ban.lifted` | policy | 1.0 | lift |
| 23 | `BAN_EXPIRED` | `bouncer.ban.expired` | policy | 0.5 | expiry noticed (sampled) |
| 24 | `BAN_EVICTED` | `bouncer.ban.evicted` | abuse | 4.0 | eviction from a full table |
| 25 | `BAN_TABLE_FULL` | `bouncer.ban.table_full` | abuse | 7.0 | insert refused |
| 26 | `BAN_REFUSED_ALLOWLISTED` | `bouncer.ban.refused_allowlisted` | policy | 3.0 | automation tried to act on an allow-listed key |
| 30 | `STRIKE` | `bouncer.strike` | per kind | per kind | strike received |
| 31 | `THRESHOLD_REACHED` | `bouncer.threshold.reached` | per kind | per kind | a local threshold fired (observe or enforce) |
| 40 | `SOURCE_SHARED_SUSPECTED` | `bouncer.source.shared_suspected` | anomaly | 1.0 | an address was flagged shared |
| 50 | `PERSIST_FAILED` | `bouncer.persist.failed` | integrity | 6.0 | write or load failure |
| 51 | `IMPORT_REJECTED` | `bouncer.import.rejected` | integrity | 5.0 | a delta or one of its records was refused |
| 52 | `PERSIST_WALL_JUMP` | `bouncer.persist.wall_jump` | integrity | 5.0 | the wall clock moved backwards, or forwards past `max_wall_jump`, between save and load |
| 60 | `TABLE_RESEEDED` | `bouncer.table.reseeded` | abuse | 6.0 | a probe sequence passed its bound; the table was rebuilt with a new seed (arrives at 0.6) |

Ids never change meaning; a changed detection bumps the revision.

---

## Persistence

Bans and offender memory survive a restart: a snapshot plus an append-only journal, loaded before the first door check. The storage is a trait, so it can be a file, a database row, or a replicated store.

### `Persistence`

```rust
pub trait Persistence: Send {
    fn load(&mut self) -> Result<Option<Vec<u8>>, PersistError>;               // snapshot bytes
    fn journal(&mut self) -> Result<Vec<u8>, PersistError>;                    // journal bytes
    fn append(&mut self, records: &[u8]) -> Result<(), PersistError>;
    fn sync(&mut self) -> Result<(), PersistError>;
    fn replace_snapshot(&mut self, snapshot: &[u8]) -> Result<(), PersistError>;   // crash-safe
}
```

Tier 3 · P1 · 0.5 · off the hot path: inserts push a fixed-size record onto a bounded queue (65,536); the maintainer writes and syncs every second or on `flush`

The format (magic `BNCR`, format version, records with CRC32C, a keyed BLAKE3 MAC over snapshot and journal when `mac_key` is set) belongs to bouncer; the trait only stores bytes. When the queue is full a record is dropped from persistence, never from memory, and `persist.failed` is reported. The journal is compacted into a new snapshot past 16 MiB.

Wall time across restarts: entries store wall time; on load, the remaining time is `until - now`, never more than the original duration (a clock stepped backwards cannot lengthen or resurrect a ban, and cannot shorten one either).

### `FilePersistence`

```rust
pub struct FilePersistence { /* directory, name */ }
impl FilePersistence { pub fn open(dir: &Path, name: &str) -> Result<FilePersistence, PersistError>; }
impl Persistence for FilePersistence;
```

Tier 2 · P1 · 0.5

Crash-safe files: the snapshot is written to `name.tmp`, synced, renamed over `name`, and the directory is synced on Unix; Windows rename replaces the target. Tested by killing the process at random points during writes on Linux, macOS, and Windows.

### `LoadFailure`

```rust
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum LoadFailure { #[default] Refuse, LoadEmpty }
```

Tier 2 · P1 · 0.5

`Refuse` (fail closed): a corrupt or tampered snapshot makes `try_build` return `Persist(..)` and the service does not start without its bans. `LoadEmpty` starts with empty memory and reports the failure. A torn journal tail (the last record cut short by a crash) is not a failure: replay stops there and the event says how much was lost.

### `PersistError`

```rust
#[non_exhaustive] #[derive(Debug)]
pub enum PersistError { Io(std::io::ErrorKind), Corrupt { offset: u64 }, Truncated, UnsupportedFormat(u16), TooLarge, Mac }
```

Tier 2 · P1 · 0.5

| Variant | Meaning | What to do |
|---|---|---|
| `Io(kind)` | the store failed | check the disk and permissions |
| `Corrupt { offset }` | a checksum failed at `offset` | restore from a node's snapshot, or start with `LoadEmpty` knowingly |
| `Truncated` | the snapshot ends early | as `Corrupt` |
| `UnsupportedFormat(v)` | written by a newer version | upgrade, or export from the newer node |
| `TooLarge` | bigger than the configured tables | raise `ban_capacity` |
| `Mac` | the MAC does not match: tampered, or the wrong key | treat as an incident; check the key |

---

## Sharing across nodes

Bans and revocations are state, so a cluster shares them: what one node learns, every node enforces. bouncer provides mergeable records; the transport is the caller's (the node link, the back-channel, or a replicated log), authenticated by that transport. Each node always enforces locally, so a node cut off from the others keeps protecting itself, and nodes converge when they reconnect.

### `NodeId`

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub u16);
```

Tier 2 · P2 · 0.5 · set with `BouncerBuilder::node`; 0 is not a valid node id

### `Delta` and `Sequence`

```rust
#[derive(Clone, Debug)]
pub struct Delta { /* encoded records, at most 16 MiB */ }
impl Delta { pub fn as_bytes(&self) -> &[u8]; pub fn from_bytes(bytes: &[u8]) -> Result<Delta, BouncerError>; pub fn last(&self) -> Sequence; }
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sequence(u64);
impl Sequence { pub const START: Sequence; pub const fn next(self) -> Sequence; pub const fn get(self) -> u64; pub const fn from_raw(raw: u64) -> Sequence; }
```

Tier 3 · P2 · 0.5 · the decoder is fuzzed

A delta holds ban, lift, offender, and revocation records (an escalation travels as the parent's ban), each stamped with its origin node, origin sequence, and a hybrid logical clock stamp (Unix milliseconds in the top 48 bits, a counter in the low 16). Pass `delta.last()` as `since` next time; when `since` is older than the outbound log keeps (65,536 records), `export_delta` returns everything instead. Revocations of connection and request ids stay on their node.

### `ImportReport`

```rust
#[must_use] #[non_exhaustive] #[derive(Clone, Copy, Debug, Default)]
pub struct ImportReport { pub applied: u32, pub superseded: u32, pub duplicates: u32, pub revocations: u32, pub rejected: u32 }
```

Tier 3 · P2 · 0.5

### Merge rules

- A record is identified by `(origin node, origin sequence)`; importing it twice changes nothing.
- Each node's ban on a key is kept apart. Of one node's bans on a key, the one with the latest stamp wins; the key is banned while any node's ban on it is in force, and the stored ban is their merge: the latest end, permanent above all.
- A lift is stamped with its node's clock and covers bans stamped at or before it: only its own node's bans, or every node's when an administrator (`Actor::Admin` or `Actor::App`) lifted the key. An automated actor's lift covers only its own node's ban, so the key can stay banned by another node's.
- Over a node channel (`import(.., Actor::Channel(n))`), a lift reaches only node `n`'s own bans, and only lifts node `n` made are taken: a node cannot lift another node's bans (T-17). An administrator's lift reaches every node's bans where an administrator delivers it (`import(.., Actor::Admin(..))`, the administration channel); without that, the other nodes keep their own bans on the key.
- Revocation records are applied to the running requests here, then kept only as long as they can still match a live ticket.
- Stamps more than `max_clock_skew` (default 5 minutes) in the future are refused (`ClockSkew`), so a node with a broken clock cannot pin a ban forever or lift everything.
- Imports from `Actor::Channel` are rate limited (100,000 records per second) and can never touch the allow list.
- A refused record (allow list, clock skew, foreign lift) counts in `ImportReport::rejected` and is reported; a refused delta (corrupt, too large, newer format, rate limited) is an error.

Each rule is commutative, associative, and idempotent, so any order and any repetition of delivery gives the same bans on every node (`tests/cluster.rs`: three nodes, partitions, a clock 30 seconds ahead, reordering, duplication, 5,000 seeds). A node that shares keeps every node's bans in a ledger beside the ban table, 151 bytes per ban held (measured with 100,000 bans; a key banned by several nodes holds one entry per node, and remembered lifts add theirs); [`capacity`](#capacity) counts it in `total_bytes`. Lifts are remembered for the 65,536 most recently lifted keys.

---

## Posture, time, maintenance, health

### `Posture`

```rust
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Posture { #[default] Normal, Strict }
```

Tier 2 · P2 · 0.5 · see [`set_posture`](#set_posture-and-posture)

### `Now`

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Now(u64);   // nanoseconds since the bouncer started
impl Now { pub const fn from_nanos(n: u64) -> Now; pub const fn as_nanos(self) -> u64; }
```

Tier 3 · P0 · 0.3

Monotonic. In-process expiry uses only this, so stepping the wall clock never shortens a ban. A `now` older than one already seen is treated as the later time (nothing expires early).

### `MaintenanceReport`

```rust
#[non_exhaustive] #[derive(Clone, Copy, Debug, Default)]
pub struct MaintenanceReport { pub swept: u32, pub ejected: u32, pub idle_checked: u32, pub reclaimed: u32, pub journal_written: u32, pub next_due: Option<Now> }
```

Tier 3 · P0 · 0.4

### `Health` and `Capacity`

```rust
#[non_exhaustive] #[derive(Clone, Copy, Debug)]
pub struct Health {
    pub tickets_live: u32, pub tickets_capacity: u32, pub tickets_detached: u32,
    pub ban_load: f32, pub revocation_load: f32, pub budget_load: f32,
    pub journal_backlog: u32, pub last_persist_error: Option<std::io::ErrorKind>,
    pub maintainer: MaintainerState, pub posture: Posture,
}
impl Health { pub fn is_ok(&self) -> bool; }
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaintainerState { NotStarted, Parked, Running, Stopped }

#[non_exhaustive] #[derive(Clone, Copy, Debug)]
pub struct Capacity { pub tickets: u32, pub bans: u32, pub revocations: u32, pub budget_keys: u32, pub table_bytes: u64, pub total_bytes: u64 }
```

Tier 2 · P1 · 0.5 (`Capacity` 0.3)

`is_ok` is `false` when any table is above 90% load, the maintainer stopped, or the last persistence write failed. `budget_load` counts the slots holding a key that has not recovered: recovered keys are reclaimed on demand, so a budget table full of them is not full. Near 1, newcomers past a full table are charged together to one global cell at the prefix rate (they are never unlimited).

---

## Metrics

```rust
#[cfg(feature = "metrics")]
#[non_exhaustive] #[derive(Clone, Copy, Debug, Default)]
pub struct MetricsSnapshot {
    pub admitted: u64, pub refused_ban: u64, pub refused_budget: u64, pub refused_registry_full: u64, pub refused_posture: u64,
    pub checkpoints_fast: u64, pub checkpoints_slow: u64, pub revocations: u64, pub denials: u64, pub ejections: u64,
    pub commits_blocked: u64, pub egress_blocked: u64,
    pub bans_active: u64, pub bans_added: u64, pub bans_expired: u64, pub bans_evicted: u64, pub bans_escalated: u64, pub bans_lifted: u64,
    pub strikes: u64, pub thresholds_observed: u64, pub thresholds_enforced: u64,
    pub budget_refused: u64, pub sweeps: u64, pub journal_queue: u64,
}
```

Tier 2 · P1 · 0.5 · counters are per shard, relaxed, on the shard's own cache line; without the feature they do not exist

---

## net-io integration

Feature `net-io`, version 0.8 (needs a published net-io 0.3 or later). net-io defines the `Gate` trait and calls it; bouncer implements it; net-io never depends on bouncer. The shape below is agreed with net-io's 0.2 design lock (decision D-015).

```rust
#[cfg(feature = "net-io")] impl net_io::Gate for Bouncer { type Ticket = ConnectionGate; }
#[cfg(feature = "net-io")] pub struct ConnectionGate { /* the connection Ticket, with its last-seen epoch */ }
#[cfg(feature = "net-io")] impl ConnectionGate { pub fn ticket(&mut self) -> &mut Ticket; }
#[cfg(feature = "net-io")] impl From<net_io::ConnectionId> for ConnId;
#[cfg(feature = "net-io")] impl From<TicketTag> for net_io::GateTag;
#[cfg(feature = "net-io")] impl From<net_io::GateTag> for TicketTag;
#[cfg(feature = "net-io")] impl From<net_io::Cidr> for Cidr;
#[cfg(feature = "net-io")] pub struct NetIoEjector { /* holds a net_io::ServerHandle */ }
#[cfg(feature = "net-io")] impl Ejector for NetIoEjector;
```

Tier 3 · P0 · 0.8

| net-io calls | bouncer does |
|---|---|
| `Gate::admit(info, Accept)` | `door_at` with net-io's id and accept time; `Ok(Admitted { lane: info.lane, ticket, tag })`, where `ticket` is the connection's `ConnectionGate` and `tag` its `TicketTag`; or `Err(Refusal::Reset { .. })`, silent and identical for every reason |
| `Gate::readmit(ticket, info)` after a trusted PROXY header | `bind_client` on the connection ticket with `Provenance::ProxyProtocol` |
| `Gate::check(ticket, write)` before every write | the egress check with the ticket in hand: one atomic load while nothing is revoked (the last-seen epoch lives in the ticket). When the session set a response tag (`write.response`), that request is judged; otherwise the connection and its latest request. `Err(Denial { code })` carries the `DenialCode` as a number (1 `Unavailable`, 2 `NotFound`, 3 `TooManyRequests`, 4 `Unauthorized`, 5 `Forbidden`); net-io wipes its pending output, has the session format the denial only if nothing of the response has left, and closes with `SO_LINGER` 0 |
| `Gate::closed(ticket, info, reason)`, exactly once | releases the connection ticket (its live requests are revoked with `CONNECTION_CLOSED`, its concurrency slot returned); close reasons that mean misbehaviour (`SlowPeer`, `ProxyInvalid`, `ProxyUntrusted`, `TlsFailed`, `HelloRefused`) become strikes |
| `ServerHandle::kill(id, reason)` | used by `NetIoEjector`, so eject-now sweeps and idle checks can close connections bouncer holds only by id |

The protocol engine reads the connection's tag from `ConnectionInfo` and opens request tickets with [`Bouncer::request`](#request); it passes a request's [`tag`](#tickettag-and-into_tag) to `Output::begin_tagged_response` so the egress check judges that request, which matters on multiplexed connections (HTTP/2, or a trusted proxy pooling many clients over one connection).

---

## Errors

### `BouncerError`

```rust
#[non_exhaustive] #[derive(Debug)]
pub enum BouncerError {
    RegistryFull { capacity: u32 },
    BanTableFull { capacity: u32 },
    RevocationTableFull { capacity: u32 },
    InvalidPrefix { len: u8, family: Family, host_bits_set: bool },
    ParseCidr { position: u8 },
    AllowListed { key: BanKey },
    TrustedProxyTarget,
    PermanentNotAllowed,
    InvalidDuration,
    NotFound,
    NotAConnectionTicket,
    InvalidTarget,
    Revoked,
    Stale,
    CollectedFull { capacity: usize, needed: usize },
    InvalidCommit,
    NodeIdUnset,
    Config(ConfigError),
    Persist(PersistError),
    Import(ImportError),
    Spawn(std::io::ErrorKind),
}
impl Display for BouncerError; impl std::error::Error for BouncerError;
```

Tier 1 · P0 · variants arrive with the feature that raises them

Every message says what to do, and none prints key bytes.

| Variant | Raised by | What to do |
|---|---|---|
| `RegistryFull` | `Ticket::request`, `Bouncer::request` | answer `Unavailable`; raise `tickets` or shed load upstream |
| `BanTableFull` | `ban`, `apply` | raise `ban_capacity`; check escalation thresholds |
| `RevocationTableFull` | `revoke`, `apply` | the revocation still reached live tickets; check the maintainer is running; raise `revocation_capacity` |
| `InvalidPrefix` | key constructors, `ban`, `lift`, `revoke` | fix the length or clear the host bits |
| `ParseCidr` | `Cidr::parse` | fix the text at `position` |
| `AllowListed` | `ban`, `revoke`, `apply` | remove the allow entry first |
| `TrustedProxyTarget` | `ban`, `revoke`, `apply` | target the real client |
| `PermanentNotAllowed` | `ban`, `apply` | use a timed ban, or act as an administrator |
| `InvalidDuration` | `ban`, `apply` | use a duration above zero |
| `NotFound` | `lift` | nothing to lift; `explain` shows covering prefix bans |
| `NotAConnectionTicket` | `request` | issue requests from the connection ticket |
| `InvalidTarget` | `apply` | the action does not fit the target (a lift or throttle aimed at a connection or request id); target the key instead |
| `Revoked` | `request` | the connection is revoked: deny and eject |
| `Stale` | `Bouncer::request` | the connection was released; treat as closed |
| `CollectedFull` | `Collected` | raise the limit, or stream the response |
| `InvalidCommit` | `Collected::commit` | commit at most what `spare` gave |
| `NodeIdUnset` | `export_delta`, `export_snapshot` | set `BouncerBuilder::node` |
| `Config` | `try_build`, `Rate::new`, `Collected::with_capacity` | see [`ConfigError`](#configerror) |
| `Persist` | `try_build`, `flush` | see [`PersistError`](#persisterror) |
| `Import` | `import`, `Delta::from_bytes` | see [`ImportError`](#importerror) |
| `Spawn` | `try_build` with `maintainer(true)` | the OS refused a thread; call `maintain` yourself |

### `ConfigError`

```rust
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigError { pub field: &'static str, pub problem: ConfigProblem }
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigProblem { TooSmall { min: u64 }, TooLarge { max: u64 }, InvalidLength, HostBansForbidden,
                         InvalidDuration, InvalidFactor, MessageTooLong, AllowListTooLarge, ZeroNodeId }
```

Tier 2 · P0 · 0.3 · names the field and the accepted range

### `FormatError`

```rust
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormatError { TooLarge, Unsupported }
```

Tier 3 · P0 · 0.4 · on either, the denial bytes are skipped and the eject proceeds

### `ImportError`

```rust
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportError { Corrupt { offset: u64 }, TooLarge, UnsupportedFormat(u16), RateLimited, AllowListTouched, ClockSkew, ForeignLift }
```

Tier 3 · P2 · 0.5 · every rejection is also an `import.rejected` event; `AllowListTouched`, `ClockSkew`, and `ForeignLift` refuse single records (counted in `ImportReport::rejected`), the others the whole delta

---

## Constants

```rust
pub const VERSION: &str;                                 // env!("CARGO_PKG_VERSION")
pub const DEFAULT_TICKETS: u32 = 65_536;
pub const DEFAULT_BAN_CAPACITY: u32 = 1_048_576;
pub const DEFAULT_REVOCATION_CAPACITY: u32 = 65_536;
pub const DEFAULT_IPV4_LENGTHS: &[u8] = &[32, 24];
pub const DEFAULT_IPV6_LENGTHS: &[u8] = &[64, 56, 48];
pub const MAX_DENIAL_BYTES: usize = 1024;
pub const MAX_EVIDENCE_BYTES: usize = 256;
pub const MAX_PROBE: u32 = 32;
pub const SNAPSHOT_MAGIC: [u8; 4] = *b"BNCR";
pub const SNAPSHOT_FORMAT: u16 = 2;
pub const GENERATOR: u16 = 2;
```

Tier 3 (`VERSION` Tier 1) · P0 (snapshot constants P1) · `VERSION` exists; the rest arrive at 0.3 to 0.5

### `VERSION`

```rust
pub const VERSION: &str;
```

The crate version, populated by Cargo at build time.

```rust
println!("bouncer-io {}", bouncer_io::VERSION);
```

---

## The checkpoint contract for pipelines

What a pipeline (serve-net, a private gateway, a service kernel worker) must do, in order:

1. **Door:** call `door` (or let net-io's hook do it) before registering the socket for reading. On refusal, close abortively; read and write nothing.
2. **Real client:** after a trusted PROXY header, `bind_client` on the connection; after a trusted forwarded header, `bind_client` on each request. A request under a proxy hop is denied until this happens.
3. **Fingerprint:** after the ClientHello, `bind_fingerprint`.
4. **Request:** `request(id)` for every request, kept for the request's life. Build the response in a `Collected`.
5. **Identity:** right after authentication, `bind_session`, `bind_account`, `bind_tenant`. A `Deny` here is final.
6. **Between every pair of stages:** `checkpoint`. On `Deny`: `deny_and_eject` and stop.
7. **Before every commit:** `before_commit`. On `Deny`: roll back, `deny_and_eject`, stop.
8. **Before encoding the response:** `checkpoint`.
9. **Every write:** the transport's egress check (net-io does this itself), with the request's tag when the protocol knows it.
10. **Misbehaviour anywhere:** `strike`.

A pipeline that skips steps 6 to 8 still cannot send a byte for a revoked connection (step 9), and bouncer reports `checkpoint.missing` when a revoked ticket goes too long without crossing a checkpoint, so the gap is found.

---

## Cost summary

| Path | Target | Measured at 0.6 (pinned, [`PERFORMANCE.md`](./PERFORMANCE.md)) |
|---|---|---|
| `checkpoint`, nothing revoked | median under 2 ns, p99 under 5 ns | 0.2 ns |
| `checkpoint` slow path, not revoked | under 150 ns with 7 bound keys | p50 64 ns, p99 96 ns |
| `before_commit` | under 5 ns | 0.2 ns |
| `egress`, nothing revoked | under 3 ns | 1.3 ns |
| `door` with 1,000,000 bans and 10,000 administrator prefixes | under 100 ns p99, budgets included | 113 ns per call (`door_at`, admitted); not met |
| ticket issue and release | under 40 ns median with 32 threads | 40 ns, one thread |
| `bind_session` / `bind_account` / `bind_tenant` | under 30 ns each | about 24 ns |
| `revoke` | under 1 µs | 119 ns |
| `ban` | under 500 ns | median 457 ns while the table fills |
| eject-now sweep over 65,536 tickets | under 1 ms | 317 µs |
| wipe | 30-60 ns per KiB of capacity | not measured at 0.6 |
| memory per ban | 45-48 bytes, hard limit 64 | 56 bytes |
| idle CPU | zero wake-ups with nothing pending | none |

No allocation on the door, checkpoint, before-commit, egress, bind, or strike paths, proven with a counting allocator. Readers (door, checkpoints, egress) never wait on writers (ban, revoke, lift, import).

<br>

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>James Gober.</strong></sup>
</div>
