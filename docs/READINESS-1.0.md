<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br><b>bouncer-io</b><br>
    <sub><sup>READINESS FOR 1.0</sup></sub>
</h1>
<div align="center">
    <sup>
        <a href="../README.md" title="Project Home"><b>HOME</b></a>
        <span>&nbsp;│&nbsp;</span>
        <a href="./API.md" title="API reference"><b>API</b></a>
        <span>&nbsp;│&nbsp;</span>
        <a href="./PERFORMANCE.md" title="Performance"><b>PERFORMANCE</b></a>
        <span>&nbsp;│&nbsp;</span>
        <a href="./SECURITY.md" title="Security"><b>SECURITY</b></a>
        <span>&nbsp;│&nbsp;</span>
        <span>READINESS</span>
    </sup>
</div>

<br>

Where bouncer-io stands after the pre-1.0 polish (0.9.0 to 0.9.2): what is done, what is still open and why, what each open item costs, and a recommendation. Written for the go/no-go on 1.0. Decision numbers refer to the decision log in [`dev/PLAN.md`](../dev/PLAN.md).

## Recommendation

Go to the release candidates now: the three performance targets are decided (D-125) and met as far as a busy machine can show. Do not tag 1.0 until the per-call latency and the ticket cycle have been measured on an idle machine and the audit in `dev/DIRECTIVES.md` section 3 has passed.

## The targets you decided (D-125)

On 2026-11-06 you accepted the recommended targets and asked for the door to be improved where needed. 0.9.2 is that pass. Every figure below was taken with every core of the machine busy with other work, so the absolute numbers are upper bounds; the ratios compare like with like within one run.

| Target | Measured at 0.9.2 | Status |
|---|---|---|
| NFR-10: at least 20% faster than the same-rate-work composition for admitted, random, and near-the-bans peers; at least twice its throughput at 32 threads | 35.7%, 56.7%, and 59.8% faster by within-run ratio; 35.7%, 31.5%, and 54.5% faster by the estimate from 0.9's idle ratios; 4.3 times the throughput at 32 threads. Against D-081's composition (one rate check): 23.9%, 34.5%, and 40.2% faster by within-run ratio; 26.0%, 18.7%, and 42.9% by the estimate | Met. The 15% floor for random peers is not needed |
| NFR-2: at most 150 ns median and 500 ns p99 per call, cold random peer, idle machine | Not measurable during this pass: the Linux machine's load average was near 500 on 32 cores and the per-call figures (p50 283 to 304 ns, p99 1.6 to 1.8 microseconds) measure queueing. At 0.9, with every core busy but far less load, the best run gave p50 111 ns and p99 462 ns, and 0.9.2's door is 12 to 21% faster than 0.9.1's | Open: one quiet hour |
| NFR-3: ticket cycle under 60 ns median at 32 threads, within 1.5 times its one-thread cost | 62.8 ns at 32 threads and 60.0 at one (1.05 times), under full load; 57.9 and 42.4 ns on an idle core at 0.9, and the ticket's code is unchanged since | Ratio met. The 60 ns figure was met at 0.9 on an idle core; confirm it on the idle machine |

## Done

- **Features**: everything in the plan's scope, built and tested:
  - the door;
  - ban memory with escalation and offender memory;
  - tickets with in-flight revocation;
  - wipe, replace, and eject;
  - strikes and enforcement modes;
  - budgets;
  - events and metrics;
  - maintenance without idle CPU;
  - persistence;
  - sharing across nodes;
  - the net-io gate, tested behind serve-net and through a real PROXY listener.
- **Defects found and fixed in 0.9**, each with a test that failed first:
  - **A revocation could miss a running ticket** when another thread moved the revocation epoch at the same moment (D-116). Loom model L-9 fails with the old order.
  - **Concurrency budgets lost counts** (D-117). Under more keys than slots, every slot of the table ended up holding a count no release returned, and from then on newcomers went uncounted. Loom model L-10 covers the new protocol.
  - **The grouped ban lookup of D-104 had never been switched on** (D-118). It is now on, bounded so that one crowded prefix cannot slow lookups of addresses inside it or of other prefixes. Random-peer door checks are about 7% faster for it.
  - **Shards shared cache lines** (D-113). A ticket at 32 threads went from 162 ns to 58 ns.
  - **Five smaller fixes** (D-119): a cleanup race with proxied requests; a client behind a PROXY listener could tell a ban from a spent budget; Unix-socket peers were refused when loopback was trusted; a custom clock under net-io; a reseed counter race.
- **Review**: every threat (27) and edge case (71) was checked against the tests by a reviewer reading without the design's reasoning. The 11 found weak or missing are covered now (D-122).
- **API review** (0.9.1, D-124): every Tier 1 call takes one or two arguments, every public method has its own example, and `cargo-semver-checks` runs in CI. Checking each documented default against the code found three routes by which a weak word could still ban a shared (NAT) address: a directive aimed at one of its connections, a decoy touch, and another node's automated ban. All three are fixed test-first (D-123).
- **The 0.9.2 pass** (D-126 to D-131):
  - **The door's filter** (D-126): a blocked Bloom filter in front of the ban table, so most peers with no ban never read it. `door_at` 12 to 21% faster than 0.9.1, judgement against 1,000,000 bans 18 to 32% faster; banned peers about 8% slower, which is the trade.
  - **Administrator-covered peers** (D-127): refused without a hash or an automatic-length probe, so which ban answers is unchanged.
  - **Persistence rollback detected** (D-128): with a `VersionAnchor` kept outside the store, an older backup put back or a journal cut is refused at load. The tests fail with the check removed, and 200 kills during writes gave no false refusal.
  - **The loom models had gaps** (D-129): in six models and two of the crate's own, the main thread acted right after spawning, and loom never ran the other side first. All are rewritten with every side spawned and pass.
  - **The 64-bit slot version** (D-130): measured. The door is unchanged, but memory per ban rises to 48.8 B, past NFR-6's 48 B target. Kept as D-105 left it.
- **Concurrency**: loom models L-1 to L-11, each participant spawned. Every protocol change of 0.8 and 0.9 has a model that fails when the change is undone.
- **Fuzzing and soak**: 24 hours each at 0.7 with no findings. Two hours of fuzzing on the 0.8 code with no findings. 24 hours each on the final 0.9 code (2026-11-04 to 2026-11-05) with no findings: the five fuzz targets ran 9.5 billion inputs between them with no crash and no artifact; the soak made 8.1 billion connections (540 million refused as banned, 50.8 million revocations, none missed) with live heap between 31.914 and 31.923 MB from the first hour to the last.

## Open, with reason and cost

| Item | Why it stays | Cost of leaving it | Cost of closing it |
|---|---|---|---|
| Per-call latency and the ticket cycle on an idle machine | Every core of the measurement machine was busy with other work through 0.9 and 0.9.2 (other sessions' soak and fuzz runs) | NFR-2 is not yet shown on an idle machine; the other figures are upper bounds | One quiet hour on the reference machine |
| net-io on Windows can drop the denial after a revocation | net-io closes abortively after a denial (to cut the connection at once); on Windows a pending send is discarded (4 in 50 loopback runs; never on Linux) | A Windows client sees a reset instead of the 403 now and then; nothing of the response leaks either way | net-io 0.8 (its D-182, built, not yet published): a bounded soft close after a denial, capped in number so a denial storm cannot hold slots. bouncer adopts it when it publishes |
| `NetIoEjector` aborts instead of flushing | net-io can close a connection by id only abortively | A denial on an ejected connection is not delivered; the connection is cut | net-io 0.8's `close_after_flush` (the same release) |
| serve-net's envelope has no gate tag | serve-net's change | Each integration keeps a small map from connection id to tag (the example shows it) | An accessor in serve-net (a small additive release) |
| 19-bit slot version in the ban table (D-105) | Halved the slot size; closing it was measured at 0.9.2 (D-130) | A reader stalled for tens of milliseconds while one slot is rewritten 2^18 times could keep a torn read | 9.2 more bytes per ban (39.6 to 48.8 B, past NFR-6's 48 B target); the door unchanged |
| Long keys stored as 64-bit fingerprints (D-105) | Halved the slot size | About 2^-64 per stored long key per lookup of a false match (choosing one needs the table key) | 8 more bytes per long key |
| Prefix strike bans count many people's strikes (D-108) | The defence against attackers rotating through a /48 | A /24 or /48 with many independent bad actors can be banned as a whole (never over an address flagged as shared) | Turning escalation off, which reopens the rotation attack |
| A shared address gets its prefix's door budget (D-109) | Keeps one person behind a NAT from getting everyone behind it refused | A shared address can admit more than one client's budget, up to its prefix's | None that keeps the NAT case working |
| Revocation costs 134 ns instead of 101 (D-116) | The second slot write is what makes births sound | About 33 ns per revocation (a cold path; 100,000 a second costs 3 ms of CPU) | An epoch protocol change at every one of six bump sites |
| Concurrency keys share a count when 44 bits match (D-117) | Key and count in one word is what makes takeovers sound | Two clients could share a concurrency budget: stricter, never looser; choosing such keys needs the budget key | A second word and a two-word protocol, the design that leaked |
| Old ban tables kept by threads after a reseed (D-119) | Freeing them would cost an atomic on every lookup | A thread that read a table later reseeded keeps it until its next lookup in a reseeded table or its exit (tens of MB at a million bans) | An atomic per lookup |
| Persistence rollback without an anchor | `version_anchor` is optional: only the deployment knows a place a restore does not reach (D-128) | Without one, an older store loads silently, as before | Configure a `VersionAnchor` on another volume or machine, or in a database row |

## What 1.0 needs, in order

1. The per-call latency (NFR-2) and the ticket cycle (NFR-3) measured on an idle machine. Tighten NFR-2 to the measured value plus a stated margin if it comes in well under (D-125).
2. The beta: the release candidates used end to end by the web stack and one non-HTTP service, with no API change needed for two of them (ROADMAP).
3. The full audit of `dev/DIRECTIVES.md` section 3.
4. Your go.
