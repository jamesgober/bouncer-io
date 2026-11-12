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
| T-2 | Ban evasion by IPv6 /64 rotation (RFC 8981 temporary addresses) | automatic keys at /64; escalation /64 to /56 to /48; strikes also counted at the widest escalation prefix, so rotating before any /64 reaches its threshold is caught there (D-108); budgets per /64 and parent | `test_ban_ipv6_rotation_within_64_refused`, proptest over banned /64s, `test_escalation_four_64s_bans_56_then_48`, `test_replay_credential_stuffing_from_a_48_bans_the_48` | one more strike counter per prefix and kind |
| T-3 | Rotation inside an IPv4 provider block | /24 escalation after 8 distinct /32 | `test_escalation_ipv4_eight_hosts_bans_24` | one probe |
| T-4 | Ban table exhaustion | fixed capacity; per-parent quota forces escalation (folding); evict only timed bans set by local heuristics, the earliest to end first (never administrator, application, policy, or permanent bans); refuse with event when full | flood: 10x capacity unique /64s from 64 /48s; table stays at capacity, every flooding /48 banned, admin bans intact | scan bounded to 32 slots |
| T-5 | Banning shared NAT addresses (RFC 6598 carrier-grade NAT, offices, mobile) | an address is shared when the deployment names its range (`SharedAddresses::known`) or when about 32 distinct accounts bind from it within an hour; sessions never count, since a client mints them at will (D-137); detection can be turned off; identity keys preferred; a threshold throttles a shared address instead of banning it, and the throttle slows it at the door (its factor goes to the prefix tier that holds it); a second threshold while it is throttled bans it; a shared address held to its prefix's door budget, never more (D-109); its strikes do not count at its prefix; escalation and prefix strike bans stop at known shared ranges only; low confidence cannot ban; no weak word bans a shared address by any route: a directive aimed at one of its connections, a decoy touch, or another node's automated ban (D-123); observe by default | `test_minted_sessions_do_not_make_an_address_shared`, `test_a_shared_address_is_banned_at_its_second_threshold`, `test_a_throttled_shared_address_is_admitted_at_a_quarter_of_its_rate`, `test_shared_source_strikes_throttle_not_ban`, `test_known_shared_ranges_block_escalation_and_detected_addresses_do_not`, `test_prefix_strikes_never_ban_over_a_known_shared_range`, `test_connection_ban_never_takes_a_shared_address_on_a_weak_word`, `test_decoy_touch_behind_a_shared_address_bans_the_identities_only`, `test_an_imported_local_ban_never_takes_an_address_shared_here`, `test_replay_cgnat_population_keeps_its_users_and_loses_its_attacker`: 2,000 logged-in users behind one address with one attacker: only the attacker's keys banned, the address throttled for one base ban length and never banned, no bind denied | 8 B per tracked address; a throttled NAT admits a quarter of its prefix budget until the throttle ends |
| T-6 | Revocation races (checkpoint, bind, release) | Release/Acquire epoch; SeqCst fence pairing; generations; idempotent revoked state | loom L-1, L-4, L-5, L-7, L-8, L-9 (a revocation against epoch moves from elsewhere, D-116); 32 threads, 10^8 checkpoints, random revokes, no checkpoint started after `revoke` returned passes | zero on the fast path; a second slot write per revocation (D-116) |
| T-7 | Bytes leaving a revoked connection | mandatory transport egress check per write and per chunk; request revocation flags the connection; eject-now; buffered mode for all-or-nothing | `test_egress_after_revoke_writes_only_denial`; loopback: revoke during a 10 MiB stream, at most one chunk leaves | two loads per write |
| T-8 | Timing side channels on ban, allow, or revocation state | every refusal is the same abortive close with no work after the decision; denials byte-identical to ordinary refusals; wipe over the whole constant capacity; keyed hashing; constant-time digests | `test_timing_admitted_does_not_reveal_neighbour_bans`, `test_timing_bind_does_not_reveal_near_banned_digests` (KS at p < 0.01, D-093; `--ignored`, release, quiet machine); byte equality of denials; the abortive close at the transport with net-io (0.8) | wipe 0.5-1 µs per 16 KiB [est.] |
| T-9 | Hash flooding | keyed hash with a random per-process seed; probe bound; reseed and rebuild with event | 10^6 keys colliding under a known seed, run with a random seed: probes stay bounded; forced seed triggers reseed | 3-10 ns per key [est.] (O-8) |
| T-10 | Stale ticket handles | generations; tagged free list; stale denies | `test_ticket_stale_generation_denied`, loom L-2 | one compare on the slow path |
| T-11 | Collateral fingerprint bans | automation bans only fingerprint-within-prefix; bare fingerprint bans need an administrator | `test_bind_fingerprint_compound_ban` | none |
| T-12 | Revocation storm pushing every checkpoint onto the slow path | bounded slow path; coalesced sweeps; a rate watch on automated revocations (one for all automated actors, default 10,000/s) that reports the excess in an Observe event and never drops a revocation (a dropped revocation would leave a revoked request running) | 100,000 revocations/s while serving: p99 checkpoint under 300 ns (`benches/storm.rs`); a storm above the rate applies every revocation and reports the excess (`test_revocation_storm_applies_every_revocation_and_reports_the_excess`) | bounded |
| T-13 | Revocation table exhaustion | capacity bound; quiescence cleanup; idle checks; a full table first reclaims, inline, every entry no live ticket needs (one pass over the registry), so a bouncer with no maintainer thread does not stay full; when it is still full, a direct sweep flags matching live tickets and the error returns | fill with no maintainer: 98,304 revocations with no error (`test_revocations_without_a_maintainer_never_fill_the_table`); a table held full by a ticket that needs its entries still denies matching live tickets | sweep cost |
| T-14 | Registry exhaustion by connection flood | fixed capacity; per-address and per-prefix concurrency at the door; transport global cap below registry capacity (a flood spread over many prefixes is the transport's to cap) | a flood from one address, and one from 1,000 addresses of one /48: each holds at most its limit and a legitimate address is still admitted | none |
| T-15 | Forged ban persistence | keyed MAC; refuse on MAC failure | `test_snapshot_tampered_byte_refused` | MAC about 1 GB/s at load [est.] |
| T-15b | Persistence rollback: an older backup put back, or the journal cut after a whole batch | a store version (snapshot epoch, batches since) recorded in a `VersionAnchor` outside the store after every durable write, checked at load; refused under `LoadFailure::Refuse` | `test_a_store_restored_from_an_older_backup_is_refused`, `test_a_journal_cut_after_a_whole_batch_is_refused_with_an_anchor`, `test_kill_during_writes_always_loads_cleanly` (with an anchor) | one 24-byte write and sync per journal flush (at most one a second) and per snapshot, off the hot path |
| T-16 | Torn writes and crashes | temp, sync, rename, directory sync; CRC32C records; tolerant tail | kill at 1,000 random points during writes; reload succeeds or refuses cleanly, never loads a corrupt entry | off the hot path |
| T-17 | Malicious import delta | per-channel rate limit; allow list untouchable; bounded deltas; fuzzed decoder; channels lift only their own node's bans; skew bound | fuzz `delta_decode`; `test_import_cannot_touch_allowlist_and_foreign_lifts_refused`; `test_node_a_day_ahead_cannot_poison_the_cluster` | cold |
| T-18 | Secrets in logs or events | digests only; redacted `Debug`; no evidence variant for digests | `test_debug_never_prints_key_bytes` | none |
| T-19 | Clock manipulation | monotonic in-process expiry; wall rules across restarts; HLC across nodes | `ManualClock` steps back and forward a day, across a reload and an import | none |
| T-20 | Unverified UDP sources framing victims, or forged from a trusted range | never strike or ban unverified datagram sources; charge them at the prefix under a key of their own, so they never spend a real source's budget (D-092); an unverified source earns no exemption from the allow list, and a source inside the trusted proxies is an ordinary source, since a datagram carries no PROXY header | `test_datagram_unverified_never_banned`, `test_datagram_forged_flood_does_not_starve_verified_sources`, `test_unverified_datagrams_get_no_exemption_from_their_source` | one rotate and xor per unverified datagram |
| T-21 | Denial reveals detection | generic codes, fixed messages, reason only in events | byte-equality tests (T-8) | none |
| T-22 | Wipe removed by the optimizer | volatile writes through crypt-io; never `fill(0)` alone | inspecting global allocator: every freed `Collected` block is all zero, in debug and release builds (CI runs `tests/wipe.rs` in release) | as 7.6 |
| T-23 | Stale reallocation copies, or uncommitted bytes left behind | `Collected` never reallocates in place; `clear` and `truncate` wipe up to the furthest byte ever handed out by `spare`, committed or not | allocator inspection on growth; `test_clear_wipes_bytes_written_through_spare` | one copy on growth; a wipe proportional to what was used |
| T-24 | A request reaches content before identity is bound | `present` bitmap (a checkpoint judges only the keys bound so far); the gateway's stage types guarantee the identity checkpoint runs before content | the gateway's integration tests (this crate does not order a protocol's stages) | none |
| T-25 | Escalation weaponized against neighbours | widest-prefix limit; refused over known shared ranges and allow-listed addresses; observe by default for local heuristics | `test_escalation_blocked_by_allow_list_and_proxy_and_shared`, `test_known_shared_ranges_block_escalation_and_detected_addresses_do_not` | none |
| T-26 | A pipeline that forgets checkpoints | transport egress (B6b) is mandatory; idle revoked tickets are found by the maintainer and reported as `checkpoint.missing` | `test_idle_ticket_checked_on_its_behalf_and_reported` | rides on the quiescence scan |
| T-27 | A node with a broken or hostile clock poisons the cluster | HLC stamps; future stamps past the skew bound refused; tombstones ordered by stamp, not by arrival | a node a day ahead lifts another node's ban and bans: both records are refused through the administration channel, and both apply with a sound clock (`test_node_a_day_ahead_cannot_poison_the_cluster`); a cluster simulation with one node 30 s ahead | none |
| T-28 | Clients behind an HTTP proxy escaping the door budgets | a client named by a forwarded header is charged the door rate and concurrency budgets at `bind_client`, once per request, and its concurrency slot returns when the request ends | `test_forwarded_header_clients_are_charged_door_budgets` | the door budget step per proxied request |
| T-29 | Strike counter exhaustion switching strikes off | sized by `strike_capacity` (262,144 by default); a full probe path never drops a strike: the counter with the fewest strikes gives up its slot, so one-strike keys cannot push out a key near its threshold; a sampled `strike.table_full` event; each counter judged idle by its own kind's window | `test_a_full_strike_table_still_counts_and_bans`, `test_a_strike_flood_does_not_flush_an_offender_near_its_threshold`, `test_a_full_counter_path_is_judged_by_each_occupant_window` | 16 B per counter; one more score read per slot on a full path |
| T-30 | Racing allow-list reloads hiding the list from the door | replacements serialized; the length the door reads is published in the order that never hides a non-empty list | `test_concurrent_allow_list_replacements_leave_the_door_consistent` | a mutex on `replace_allow` only |

## Sharing between nodes

bouncer-io provides the records; the transport authenticates them (mutual TLS on node links, or the back-channel). Inside that boundary:

- Each node's ban on a key is kept apart, with its stamp, so the outcome of any order and any repetition of delivery is the same on every node.
- A node channel (`Actor::Channel(n)`) carries only node `n`'s own records; a record of another node on it is refused before it is remembered as seen. A node cannot shorten, erase, lift, or shadow another node's bans. An administrator's lift reaches every node's bans only when an administrator delivers it (`Actor::Admin` or `Actor::App`, the administration channel).
- A channel's bans are held to what their actor could set locally, never cover a whole address family, and one key holds the bans of at most 64 nodes.
- Records stamped more than `max_clock_skew` (5 minutes) ahead are refused, so a node with a broken clock cannot pin a ban or a lift in the future.
- Channels are rate limited (100,000 records a second) and can never touch the allow list.
- A node that is cut off keeps enforcing what it has.

## What bouncer-io does not cover

- Bytes already flushed to a client cannot be recalled; a revocation stops what has not been written yet (at most one chunk in flight).
- A flood larger than the network link needs help upstream (the provider, a CDN). bouncer-io protects the server's resources, not the pipe.
- Detection is as good as the signals fed into it; long-term correlation belongs to a detection system.
- A compromised process can turn off its own bouncer; containment belongs to the host.
- A node that is itself compromised can ban keys within the limits above and lift its own bans across the cluster; it cannot lift or change other nodes' bans or touch their allow lists. Allow-list the addresses the deployment cannot lose (its own infrastructure, monitoring).
- Someone who can write the state files, even without the MAC key, can cut the journal after a whole batch or put back an older snapshot and journal, which brings back lifted bans and loses the bans recorded since. With a `VersionAnchor` kept where they cannot write (another volume or machine, a database row, a hardware counter), that store is refused at load and `persist.rolled_back` is reported (T-15b). Without one it loads silently. The MAC detects any change, reordering, or removal from the middle either way. Protect the state directory like the server's own configuration.
- A formatter (`DenialFormat`) that panics leaves the ticket revoked and the buffer wiped (both happen before it runs); build with `panic = "abort"` in release so a panic cannot leave a connection half-handled.

## How it is checked

- Every threat above has its named test (T-24's are the gateway's: its defence is the gateway's stage order); the test suite runs on Linux, macOS, and Windows, on stable and Rust 1.85.
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
