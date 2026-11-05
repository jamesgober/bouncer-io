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

Where bouncer-io stands after the pre-1.0 polish (0.9.0): what is done, what is still open and why, what each open item costs, and a recommendation. Written for the go/no-go on the beta and on 1.0. Decision numbers refer to the decision log in [`dev/PLAN.md`](../dev/PLAN.md).

## Recommendation

Go to the beta (0.9.x release candidates) once you have decided the three performance targets below. Do not tag 1.0 until the per-call latency has been measured on an idle machine and the audit in `dev/DIRECTIVES.md` section 3 has passed.

The library does what the plan says it does, and the 0.9 review found and fixed real defects in it (below). What is not met is three performance targets that were estimates written before anything could be measured. Each has been measured now, and each has a proposed replacement grounded in those measurements. Accepting them is your call: they are the product's promises.

## Decisions for you

| # | Target as written | Measured at 0.9 | Proposed (decision) |
|---|---|---|---|
| 1 | NFR-10: the door 20% faster than the same-job composition, admitted and random peers (D-081) | Against that composition: admitted 16.3% faster, random peers at parity, peers near the bans 27.6% faster. Against a composition doing the same rate work (it checks one rate; the door checks two): 27.2%, 15.4%, and 42.2% faster. At 32 threads the door does 2.9 times the composition's work | With the same rate work, at least 20% faster for admitted peers and peers near the bans and at least 15% for random peers; against D-081's composition, at least 15% faster for admitted peers and within 2% for random peers; at 32 threads, at least twice the throughput (D-120) |
| 2 | NFR-2: the door at most 100 ns p99 per call | 111 ns median, 462 ns p99 per call for a cold random peer at best, on a machine busy with other work; warm, 95.5 ns | At most 150 ns median and 500 ns p99 per call for a cold random peer, measured on an idle machine (D-121) |
| 3 | NFR-3: a ticket at most 40 ns median with 32 threads | 42.4 ns at one thread, flat to 8, 57.9 ns at 32 (two threads per core) | Within 1.5 times the one-thread cost at 32 threads and under 60 ns median (D-121) |

My recommendation is to accept all three. Why 20% against D-081's composition is not reachable without giving something up:

- **Two rate checks against one.** The door always checks a rate per address and per prefix. The prefix check is what stops IPv6 rotation inside a /48, and it is about a quarter of the door's work.
- **The ticket's floor.** A ticket costs six locked operations, about 23 ns on this machine. Removing more of them means one of three things:
  - unsafe code;
  - a lifetime on `Ticket`, which breaks moving tickets into async tasks;
  - a per-thread cache of free cells, which makes the registry refuse while it still has room.
- **The benchmark's random set.** A quarter of its peers are IPv4 addresses covered by the fixture's administrator /8 bans, so they take the refusal path. That path costs more in the door because it computes a lookup reference for the administrator and checks every automatic length first.

Keeping 20% against D-081's composition would mean accepting one of those three costs. I do not recommend it.

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
- **Concurrency**: loom models L-1 to L-10. Every protocol change of 0.8 and 0.9 has a model that fails when the change is undone.
- **Fuzzing and soak**: 24 hours each at 0.7 with no findings. Two hours of fuzzing on the 0.8 code with no findings. 24 hours each on the final 0.9 code (2026-11-04 to 2026-11-05) with no findings: the five fuzz targets ran 9.5 billion inputs between them with no crash and no artifact; the soak made 8.1 billion connections (540 million refused as banned, 50.8 million revocations, none missed) with live heap between 31.914 and 31.923 MB from the first hour to the last.

## Open, with reason and cost

| Item | Why it stays | Cost of leaving it | Cost of closing it |
|---|---|---|---|
| Per-call latency on an idle machine | Every core of the measurement machine was busy with other work during 0.9 | The p99 figures above are upper bounds, not the real numbers | One quiet hour on the reference machine |
| net-io on Windows can drop the denial after a revocation | net-io closes abortively after a denial (to cut the connection at once); on Windows a pending send is discarded (4 in 50 loopback runs; never on Linux) | A Windows client sees a reset instead of the 403 now and then; nothing of the response leaks either way | A graceful close after a denial in net-io (its change, not bouncer's) |
| `NetIoEjector` aborts instead of flushing | net-io can close a connection by id only abortively | A denial on an ejected connection is not delivered; the connection is cut | A flush-then-close by id in net-io |
| serve-net's envelope has no gate tag | serve-net's change | Each integration keeps a small map from connection id to tag (the example shows it) | An accessor in serve-net (a small additive release) |
| 19-bit slot version in the ban table (D-105) | Halved the slot size | A reader stalled for tens of milliseconds while one slot is rewritten 2^18 times could keep a torn read | 8 more bytes per ban |
| Long keys stored as 64-bit fingerprints (D-105) | Halved the slot size | About 2^-64 per stored long key per lookup of a false match (choosing one needs the table key) | 8 more bytes per long key |
| Prefix strike bans count many people's strikes (D-108) | The defence against attackers rotating through a /48 | A /24 or /48 with many independent bad actors can be banned as a whole (never over an address flagged as shared) | Turning escalation off, which reopens the rotation attack |
| A shared address gets its prefix's door budget (D-109) | Keeps one person behind a NAT from getting everyone behind it refused | A shared address can admit more than one client's budget, up to its prefix's | None that keeps the NAT case working |
| Revocation costs 134 ns instead of 101 (D-116) | The second slot write is what makes births sound | About 33 ns per revocation (a cold path; 100,000 a second costs 3 ms of CPU) | An epoch protocol change at every one of six bump sites |
| Concurrency keys share a count when 44 bits match (D-117) | Key and count in one word is what makes takeovers sound | Two clients could share a concurrency budget: stricter, never looser; choosing such keys needs the budget key | A second word and a two-word protocol, the design that leaked |
| Old ban tables kept by threads after a reseed (D-119) | Freeing them would cost an atomic on every lookup | A thread that read a table later reseeded keeps it until its next lookup in a reseeded table or its exit (tens of MB at a million bans) | An atomic per lookup |
| Persistence rollback | Not covered by the design (`docs/SECURITY.md`) | A store restored from an older backup brings back lifted bans and forgets newer ones | A monotonic store version, checked at load |

## What 1.0 needs, in order

1. Your decision on the three targets.
2. The per-call latency measured on an idle machine against the decided targets.
3. The beta: the release candidates used end to end by the web stack and one non-HTTP service, with no API change needed for two of them (ROADMAP).
4. The full audit of `dev/DIRECTIVES.md` section 3.
