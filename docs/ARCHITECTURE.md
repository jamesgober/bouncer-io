<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br><b>bouncer-io</b><br>
    <sub><sup>ARCHITECTURE</sup></sub>
</h1>
<div align="center">
    <sup>
        <a href="../README.md" title="Project Home"><b>HOME</b></a>
        <span>&nbsp;│&nbsp;</span>
        <a href="./API.md" title="API reference"><b>API</b></a>
        <span>&nbsp;│&nbsp;</span>
        <a href="./INTEGRATION.md" title="Integration"><b>INTEGRATION</b></a>
        <span>&nbsp;│&nbsp;</span>
        <span>ARCHITECTURE</span>
    </sup>
</div>
<br>

How bouncer-io is built: what each part holds, how the hot paths stay cheap, and why the concurrent parts are correct. The design record with every decision is [`../dev/PLAN.md`](../dev/PLAN.md); this page is the map.

- [The shape](#the-shape)
- [Hot paths](#hot-paths)
- [Tickets and the registry](#tickets-and-the-registry)
- [Revocation](#revocation)
- [Ban memory](#ban-memory)
- [Budgets, strikes, and shared addresses](#budgets-strikes-and-shared-addresses)
- [Persistence](#persistence)
- [Sharing across nodes](#sharing-across-nodes)
- [Maintenance](#maintenance)
- [Memory](#memory)
- [Concurrency proofs](#concurrency-proofs)

## The shape

bouncer is consulted, never flowed through. A transport, a pipeline, and the gates call it at fixed points and act on the answer:

```text
            accept                 every request                    every write
   peer ─────────► door ──► connection ticket ──► request ticket ──► egress
                     │            │   │ bind_* (client, fingerprint,      │
                     │            │   │ session, account, tenant, lane)   │
                     │            │   └─ checkpoint, before_commit ───────┤
                     ▼            ▼                                       ▼
                ban memory    revocation epoch ◄── revoke / apply   deny_and_eject:
                budgets       revocation tables                     wipe, replace,
                allow list    registry cells                        eject, remember
```

Everything one bouncer knows lives in one `Shared` value behind an `Arc`: ban memory, the allow list and trusted proxies, the registry, the revocation epoch and tables, budgets, strike counters, offender memory, the shared-address detector, the event sink, persistence, and the sharing log. Every table is sized at build and never grows.

| Module | Holds |
|---|---|
| `door` | the accept-time judgement: trusted proxy, allow list, ban memory, budgets |
| `registry`, `ticket` | ticket cells, the free lists, checkpoints, binds, egress, release |
| `revoke` | the epoch word, revocation records and tables |
| `bans` | the dynamic ban table, the compiled administrator set, escalation, offender memory, views |
| `budgets`, `claims` | door, lane, and tenant budgets on lock-free keyed slots |
| `strikes`, `sources` | windowed strike counters; shared-address detection |
| `collected`, `format` | the zeroizing response buffer; the denial formatter hook |
| `events`, `metrics` | the event sink and catalog; per-shard counters |
| `persist`, `codec`, `share`, `state` | the snapshot and journal, the record format, deltas and merge, the glue between them |
| `maintain` | the bounded maintenance step and the parked thread |

## Hot paths

| Path | Work | Cost |
|---|---|---|
| checkpoint, nothing revoked | one Acquire load of the epoch, compared with the ticket's own copy | about 1 ns (measured at 0.3) |
| before-commit, nothing revoked | one SeqCst load | a few ns [est.] |
| egress by tag, nothing revoked | two loads and the cell's flags | under 3 ns [est.] |
| door | allow-list lookup through a per-thread copy, ban probes for each length in use (batched), door budgets | 230 to 360 ns with 1,000,000 bans on a noisy machine (measured at 0.3); target under 100 ns at 0.6 |
| identity bind | key write, one fence, ban probe, revocation probe, shared-address bitmap OR | tens of ns [est.] |

Nothing on these paths allocates (checked by `tests/alloc.rs` with a counting allocator) or takes a lock. Bans, lifts, revocations, imports, listings, and persistence are cold paths: they take a writer lock and may allocate.

## Tickets and the registry

Every connection and every request in flight holds a ticket: a 128-byte cell in one array shared by all shards. A cell's state word packs a 32-bit generation, flags (live, revoked, cancelled, pending client, proxy hop, immune, client bound, detached, charged, keep connection, tenant charged), the provenance, and the denial code. Its key words hold the source, the request id, and the bound session, account, tenant, and fingerprint, with a bitmap saying which are present.

Shards are ranges of the array, each with a Treiber free list whose head is tagged on every change (no ABA; loom model L-2). A ticket handle knows its cell index and generation; a stale handle or tag fails closed.

A transport that stores one number per connection holds a `TicketTag` (index and generation) instead of the handle and checks it before every write.

## Revocation

Revoking writes a record into a revocation table and moves the epoch, both under the table's writer lock, so every record has a unique birth epoch. A checkpoint compares the epoch with its own copy; when they differ it checks the cell against the tables (by connection, request, session, account, tenant, fingerprint, and source prefix), then remembers the new epoch. The paired fences in `revoke` and in the binds mean a key bound at the same moment as it is revoked is never missed by both sides (loom model L-4); `before_commit` uses a SeqCst load so a commit that starts after `revoke` returned cannot pass.

A record is removed once every live ticket has checked at or after its birth (quiescence), so the tables hold only what can still match.

## Ban memory

Two structures:

- **The dynamic table** holds automatic and directive bans at the configured lengths (IPv4 /32 and /24; IPv6 /64, /56, /48 by default) and identity bans. It is a tagged open-addressing table: groups of eight slots with one-byte tags, triangular probing bounded to 32 groups, each slot a small sequence lock. Readers never take a lock; writers are serialized. Keys are hashed with SipHash-1-3 under a random key.
- **The compiled set** holds administrator prefixes of any other length: a six-bit-stride trie with popcount-indexed children, rebuilt on change and swapped whole, read through a per-thread copy.

Eviction, when the table is full: expired entries, then the automatic ban that ends first within a bounded scan. Administrator, permanent, and directive bans are never evicted.

**Escalation.** When enough distinct children of one parent are banned within the window (IPv4 8 /32 in a /24; IPv6 4 /64 in a /56 and 4 /56 in a /48), the parent is banned for the longest remaining child time times the factor and the children are folded into it. The tracker lives under the writer lock. It never crosses an allow-list entry, a trusted proxy, or a shared address (sorted span lists beside the compiled sets answer "is anything inside this prefix"), and never goes wider than the configured widest prefix. Past `max_children_per_parent`, inserting forces escalation, so one allocation cannot fill the table.

**Offender memory** keeps past offences per ban key, decayed with a half-life (24 hours by default), and sets the next ban's length after the last one expired: `min(base × factor^offences, max) + jitter`.

## Budgets, strikes, and shared addresses

Budgets are keyed slots in a lock-free claims table: a slot is claimed by a compare-and-swap of its key word, and taken over only when its payload has recovered, so eviction never resets a limit. Door budgets (rate per client and prefix through rate-net's GCRA, concurrency counters) run at the door; lane budgets (GCRA per session or client) at `bind_lane`; tenant budgets (better-bucket token buckets, per-tenant plans in a sorted table) at `bind_tenant`. Throttles multiply the cost of a charge.

Strikes are windowed counters in the same kind of table. A local threshold observes by default and enforces only for the kinds a project switched on, or under the strict posture.

Shared-address detection ORs a hashed identity into a 64-bit bitmap per client at every session and account bind. More than 16 distinct identities within an hour flags the address as shared for a day: automation then bans identities and throttles the address instead of banning everyone behind it.

## Persistence

```text
snapshot := "BNCR" | format:u16 | flags:u16 | created:u64 | epoch:u64 | node:u16 | hlc:u64
            | count:u64 | record* | length:u64 | crc32c:u32 | [mac:32]
batch    := "BNCJ" | epoch:u64 | wall:u64 | length:u32 | record* | crc32c:u32 | [mac:32]
record   := length:u32 | type:u8 | origin:u16 | sequence:u64 | payload | crc32c:u32
```

Every ban, lift, removal, and offender change becomes a record in a bounded queue (65,536); the maintainer writes queued records as one journal batch and syncs about every second. The snapshot's keyed BLAKE3 MAC covers all of it; each batch's MAC covers the previous MAC and the batch, so batches cannot be dropped, reordered, or spliced in without the key. A batch carries the snapshot's epoch: batches left by a crash during compaction belong to an older epoch and are skipped. Past 16 MiB of journal, the full state becomes a new snapshot of the next epoch.

Loading happens in `try_build`, before the first door check: the snapshot (refused whole on any checksum or MAC failure, unless `LoadFailure::LoadEmpty`), then the journal batches up to the first damaged one. Bans store wall times and their original length, so a clock step between save and load can neither lengthen nor resurrect a ban.

## Sharing across nodes

Every local change also goes to a bounded outbound log (65,536 records). `export_delta(since)` encodes what came after `since`; `import` merges:

- a record is identified by (origin node, origin sequence), and a record seen before is skipped;
- each node's ban on a key is kept apart (the ledger, beside the ban table); of one node's bans the latest stamp wins, and the ban table holds the merge of every node's ban in force: the latest end, permanent above all;
- a lift is stamped with a hybrid logical clock and covers bans stamped at or before it: its own node's, or every node's for an administrator's lift delivered by an administrator;
- stamps further in the future than `max_clock_skew` are refused;
- a channel cannot touch the allow list and carries only lifts its own node made, which reach only that node's bans.

Each rule is a per-origin last-writer-wins register, so any order and any repetition of delivery converge. Revocations travel too and reach the requests running on every node. Each node always enforces locally; a node cut off keeps protecting itself.

## Maintenance

One bounded step does every pending job: eject-now sweeps, checks of tickets that went `max_unchecked` without a checkpoint (run on their behalf; a revoked one is ejected and reported), revocation cleanup by quiescence, and the persistence flush. It returns when more work is next due, or nothing. The optional maintainer thread parks until then, is woken by revocations and the first queued record, and never wakes when nothing is pending.

## Memory

| Structure | Default size |
|---|---|
| registry | 65,536 cells × 128 B = 8 MiB |
| dynamic ban table | 1,048,576 entries, about 45 MiB [est.] |
| revocation table | 65,536 entries |
| door budgets | 65,536 keys per tier |
| offender memory | a quarter of the ban capacity, about 10 MiB [est.] |
| shared-address detector | 65,536 clients × 16 B plus claim words |
| persistence queue | 65,536 records |
| outbound log | 65,536 records |

`Bouncer::capacity` reports what was reserved; nothing grows past it.

## Concurrency proofs

The loom models in `src/loom_models.rs` and next to the free list and ban slots check, over every interleaving: a revocation published by the epoch is seen by a checkpoint that observes the epoch (L-1); the free list never hands one cell out twice (L-2); a ban slot reader never sees a torn entry (L-3); a bind racing a revocation is never missed by both (L-4); a revocation never lands on the next generation of a cell (L-5); a concurrency counter never underflows (L-6). A 10^8-checkpoint stress run with concurrent revocations misses none.

<br>

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>James Gober.</strong></sup>
</div>
