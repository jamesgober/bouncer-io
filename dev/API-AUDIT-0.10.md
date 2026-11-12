# API simplicity audit for 0.10

Date: 2026-11-11. Scope: every public item of 0.9.3 (117 items, 227 inherent methods, listed from rustdoc's JSON output) against four rules:

1. Tier 1 one-liners with no builder cover about 80% of uses and work with plain `?`.
2. Names a newcomer can read without the docs.
3. One way to do each thing.
4. `docs/API.md` lists every public item, in the reference format: nested contents, description, parameters, errors, examples.

The 0.9 freeze does not protect an API that is hard to use, so breaks are allowed. They ship as 0.10.0 with a migration note. The one dependent in the stack is a private gateway (on bouncer-io 0.9.2). Nothing on crates.io depends on bouncer-io.

## The common path, as a newcomer writes it

```rust
let bouncer = Bouncer::new();
let conn = bouncer.door(peer)?;                 // at accept
let mut request = conn.request(RequestId(n))?;  // per request
if request.bind_session(key).is_deny() { /* deny_and_eject */ }
if request.checkpoint().is_deny() { /* deny_and_eject */ }
bouncer.ban(addr)?;
bouncer.lift(addr)?;
bouncer.revoke(session, Reason::LOGOUT)?;
```

Every call is one line and takes one or two arguments. Tier 1 passes on length. Five findings below sit on or next to this path.

## Findings, each with what 0.10 does

| # | Rule | Finding | 0.10 |
|---|---|---|---|
| 1 | `?` | `door` returns `Refusal`, and there is no `From<Refusal>` for `BouncerError`, so `bouncer.door(peer)?` does not compile in a function that returns `Result<_, BouncerError>`. That is the first call every user writes. | Fixed: `BouncerError::Refused(Refusal)` and `From<Refusal>`. `door` still returns the small `Refusal`, so the door's hot path is unchanged. |
| 2 | names | `ConnId` and `Ticket::conn()` (and `Subject::conn`) are abbreviations. net-io, the stack's transport, names the same thing `ConnectionId`. | Renamed: `ConnectionId`, `Ticket::connection()`, `Subject::connection`. |
| 3 | names | `BouncerBuilder::try_build` suggests that a panicking `build` exists, and it does not. Every other builder in the stack ends in `build()`. | Renamed: `build()`, which returns `Result`. |
| 4 | one way | Two option builders do the same job. `ban(BanSpec::address(a).for_duration(d).by(x).because(r))` and `apply(Directive::ban(a).for_duration(d).by(x).because(r))` set the same fields, and so do `LiftSpec` and `Directive::lift`. `Directive` is the one every other layer of the stack sends, and it also carries confidence, eject mode, ban keys and denial code. | `BanSpec` and `LiftSpec` leave the public API. `ban(key)` and `lift(key)` stay as the Tier 1 one-liners, taking the key with the defaults. Anything more goes through `apply(Directive::...)`. `Target` gains `FingerprintIn`, so a fingerprint-within-prefix ban keeps its actor, reason and duration. |
| 5 | one way | `Ticket::is_cancelled()` is `checkpoint().is_deny()` under another name. | Removed. Loops call `request.checkpoint().is_deny()`. |
| 6 | Tier 2 | The builder's plug-ins mix `Arc<dyn _>` (event sink, ejector, denial format, clock) with `Box<dyn _>` (persistence, version anchor). The caller has to know which to wrap in. | Each takes `impl Trait + 'static`, and bouncer wraps it. Blanket impls for `Arc<T>` (and `Box<T>` for the stores) keep a shared handle working, such as a gateway's `Arc<NetIoEjector>`. The revocation epoch stays `Arc<RevocationEpoch>`, since sharing it between bouncers is its purpose. |
| 7 | names | `Delta::last()` reads as "the last entry". It returns the delta's last sequence number. | Renamed: `last_sequence()`. |
| 8 | docs | The crate-level rustdoc still says that revocation, strikes and budgets arrive in 0.4, and persistence and sharing in 0.5. | Rewritten for what the crate is now, Tier 1 first. |
| 9 | docs | `docs/API.md` against every public item. | Checked by a script against rustdoc's JSON. Missing items were added, and the renamed and removed items were updated. |

## Kept, with the reason

| Item | Why it stays |
|---|---|
| `checkpoint`, `bind_*`, `before_commit` and `egress` return `Verdict`, not `Result` | A denial is an outcome to handle where it happens: the response collected so far must be wiped and replaced (`deny_and_eject`). A `?` would carry it away from the buffer it has to wipe. `Verdict::is_deny()` keeps the check on one line. |
| `revoke(target, reason)` keeps its reason | Every revocation is an event and an audit record, and the reason is what an application knows at the call (`Reason::LOGOUT`, `Reason::PASSWORD_CHANGED`). It is still two arguments. |
| `door` | The crate's one verb for the accept-time check; the README and the docs are built around it. `admit` would clash with net-io's `Gate::admit`, which `Bouncer` implements with other arguments. |
| `egress(tag)` | The networking word for traffic leaving. It is the transport's call, not an application's. |
| `prefix_of(addr, len)` beside `Cidr::new(addr, len)` | They differ. `prefix_of` normalizes first and reads `len` in the normalized family (an IPv4-mapped address and 24 give an IPv4 /24). `Cidr::new` reads `len` in the literal family. The docs of each now say so. |
| `Cidr::parse` beside `str::parse::<Cidr>()` | `FromStr` is the standard trait; the inherent call is the one-liner a reader finds first, as with `Url::parse`. |
| `Budgets::off()` as the start of a budget set | Matches `EscalationPolicy::off()`; the default `Bouncer` has budgets on, so building from nothing is the explicit choice. |
| `Bouncer::request(tag, id)` beside `Ticket::request(id)` | One is for a transport that holds only the tag (serve-net, the gateway), the other for code that holds the ticket. Neither can do the other's job. |

## Cost

None at run time. The door, the ticket and the checkpoint compile to the same code, and the instruction-count gate in CI checks that. The breaks are confined to option builders, names and builder arguments. The migration for the one dependent is about ten lines and is listed in `docs/release/v0.10.0.md`.
