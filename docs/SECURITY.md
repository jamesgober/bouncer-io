<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br><b>bouncer-io</b><br>
    <sub><sup>SECURITY</sup></sub>
</h1>
<div align="center">
    <sup>
        <a href="../README.md" title="Project Home"><b>HOME</b></a>
        <span>&nbsp;│&nbsp;</span>
        <a href="./API.md" title="API reference"><b>API</b></a>
        <span>&nbsp;│&nbsp;</span>
        <a href="./ARCHITECTURE.md" title="Architecture"><b>ARCHITECTURE</b></a>
        <span>&nbsp;│&nbsp;</span>
        <a href="./PERFORMANCE.md" title="Performance"><b>PERFORMANCE</b></a>
        <span>&nbsp;│&nbsp;</span>
        <span>SECURITY</span>
        <span>&nbsp;│&nbsp;</span>
        <a href="./PLATFORM-NOTES.md" title="Platform notes"><b>PLATFORM NOTES</b></a>
    </sup>
</div>
<br>

What bouncer-io defends against, how, what each defence costs, and the test that shows it holds; where its trust boundaries are; and what it leaves to other parts of a deployment. The threat numbers T-1 to T-27 are those of [`dev/PLAN.md`](../dev/PLAN.md) section 8.

- [Reporting a vulnerability](#reporting-a-vulnerability)
- [Trust boundaries](#trust-boundaries)
- [Threats, defences, tests, costs](#threats-defences-tests-costs)
- [Sharing between nodes](#sharing-between-nodes)
- [What bouncer-io does not cover](#what-bouncer-io-does-not-cover)
- [How it is checked](#how-it-is-checked)

## Reporting a vulnerability

Open a private security advisory on the [repository](https://github.com/jamesgober/bouncer-io/security/advisories/new) with a description, a proof of concept if you have one, and the affected versions. Please do not open a public issue for a security report.

## Trust boundaries

| Input | Trusted as | Checked by |
|---|---|---|
| The socket peer address | the client, unless it is a trusted proxy | the door: allow list, ban memory, budgets |
| A client address named by a proxy (PROXY protocol, forwarded header, FastCGI) | the client, only when the peer is a configured trusted proxy and the provenance says so | `bind_client` refuses every other case (T-1) |
| Identity keys (session, account, tenant, fingerprint) | what the application says; digests, compared in constant time | the binds, checked against revocations and bans |
| Strikes and directives | the actor named (`Actor`), with its limits: automation cannot ban permanently, ban a bare fingerprint, or touch allow-listed or proxy addresses | the strike rules and the directive checks |
| Persisted state | this node's, when its MAC verifies (with a key), or its CRC (without) | the snapshot and journal decoders (T-15, T-16) |
| A delta from another node | that node's records, as far as its channel allows | the import rules (T-17, T-27; [below](#sharing-between-nodes)) |
| Unverified datagram sources | nobody: never struck or banned, charged under a key of their own | the datagram door (T-20) |

Denials never say why: every refusal is the same abortive close, every denial carries the same fixed message for its code, and the reason is only in events (T-21).

## Threats, defences, tests, costs

| Id | Threat | Defence | Test (must fail to get through) | Cost |
|---|---|---|---|---|
| T-1 | Address spoofing behind proxies to evade a ban or frame someone | PROXY only from trusted proxies; forwarded headers bound only with a trusted provenance; automation bans only trusted-provenance addresses; the proxy is never a target | `test_door_forwarded_header_from_untrusted_peer_not_bound`, `test_strike_on_proxy_hop_ignored_and_real_client_struck`, `test_ban_trusted_proxy_refused`, `test_proxied_request_without_client_denies_every_checkpoint` | about 1 ns |
| T-2 | Ban evasion by IPv6 /64 rotation (RFC 8981 temporary addresses) | automatic keys at /64; escalation /64 to /56 to /48; budgets per /64 and parent | `test_ban_ipv6_rotation_within_64_refused`, proptest over banned /64s, `test_escalation_four_64s_bans_56_then_48` | none extra |
| T-3 | Rotation inside an IPv4 provider block | /24 escalation after 8 distinct /32 | `test_escalation_ipv4_eight_hosts_bans_24` | one probe |
| T-4 | Ban table exhaustion | fixed capacity; per-parent quota forces escalation (folding); evict shortest automatic bans only; refuse with event when full | flood: 10x capacity unique /64s from 64 /48s; table stays at capacity, every flooding /48 banned, admin bans intact | scan bounded to 32 slots |
| T-5 | Banning shared NAT addresses (RFC 6598 carrier-grade NAT, offices, mobile) | shared-address detection; identity keys preferred; throttle instead of ban; no escalation from a shared address; low confidence cannot ban; observe by default | `test_shared_source_strikes_throttle_not_ban`, `test_shared_source_blocks_escalation`, 500 sessions behind one address with one attacker: only the attacker's keys banned | 8 B per tracked address |
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

## Sharing between nodes

bouncer-io provides the records; the transport authenticates them (mutual TLS on node links, or the back-channel). Inside that boundary:

- Each node's ban on a key is kept apart, with its stamp, so the outcome of any order and any repetition of delivery is the same on every node.
- A node channel (`Actor::Channel(n)`) carries only lifts node `n` made, and they reach only node `n`'s bans: a node cannot lift another node's bans. An administrator's lift reaches every node's bans only when an administrator delivers it (`Actor::Admin` or `Actor::App`, the administration channel).
- Records stamped more than `max_clock_skew` (5 minutes) ahead are refused, so a node with a broken clock cannot pin a ban or a lift in the future.
- Channels are rate limited (100,000 records a second) and can never touch the allow list.
- A node that is cut off keeps enforcing what it has.

## What bouncer-io does not cover

- Bytes already flushed to a client cannot be recalled; a revocation stops what has not been written yet (at most one chunk in flight).
- A flood larger than the network link needs help upstream (the provider, a CDN). bouncer-io protects the server's resources, not the pipe.
- Detection is as good as the signals fed into it; long-term correlation belongs to a detection system.
- A compromised process can turn off its own bouncer; containment belongs to the host.
- A node that is itself compromised can ban arbitrary keys and lift its own bans across the cluster; it cannot lift other nodes' bans or touch their allow lists.
- A formatter (`DenialFormat`) that panics leaves the ticket revoked and the buffer wiped (both happen before it runs); build with `panic = "abort"` in release so a panic cannot leave a connection half-handled.

## How it is checked

- Every threat above has its named test; the test suite runs on Linux, macOS, and Windows, on stable and Rust 1.85.
- Loom models check the revocation, bind, and release orderings; property tests check ban memory and the merge of shared records.
- Five fuzz targets (address parsing, directive sequences, snapshots, journals, deltas) ran 24 hours each for 0.7; the decoder targets frame part of their inputs with valid checksums so mutations reach the record decoders.
- A three-node simulation checks sharing under partitions, clock skew, reordering, and duplication.
- The timing tests (`tests/timing.rs`, T-8) check that admitted latency does not depend on neighbours' bans and bind latency does not reveal digests near a banned one.
- `cargo audit` and `cargo deny` run in CI.

<br>

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>James Gober.</strong></sup>
</div>
