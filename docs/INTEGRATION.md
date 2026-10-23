<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br><b>bouncer-io</b><br>
    <sub><sup>INTEGRATION</sup></sub>
</h1>
<div align="center">
    <sup>
        <a href="../README.md" title="Project Home"><b>HOME</b></a>
        <span>&nbsp;│&nbsp;</span>
        <a href="./API.md" title="API reference"><b>API</b></a>
        <span>&nbsp;│&nbsp;</span>
        <span>INTEGRATION</span>
    </sup>
</div>
<br>

How a transport, a pipeline, a protocol adapter, an authentication gate, and the security signal bridge wire into bouncer-io. bouncer is consulted, never flowed through: each part calls it at a fixed point and acts on the answer.

- [The checkpoint contract](#the-checkpoint-contract)
- [Transport (net-io)](#transport-net-io)
- [Pipeline (serve-net, a gateway, a worker)](#pipeline-serve-net-a-gateway-a-worker)
- [Protocol adapter](#protocol-adapter)
- [Authentication and authorization gates](#authentication-and-authorization-gates)
- [The security signal bridge](#the-security-signal-bridge)
- [Maintenance](#maintenance)
- [Choosing defaults](#choosing-defaults)

## The checkpoint contract

What a pipeline must do, in order:

| Step | Where | Call | On a refusal or `Deny` |
|---|---|---|---|
| 1 door | right after accept, before the socket is read | `bouncer.door(peer)` (or `door_at`) | close abortively; read and write nothing |
| 2 real client | after a trusted PROXY header (connection) or forwarded header (each request) | `ticket.bind_client(addr, provenance)` | deny and eject; until bound, a proxied request is denied |
| 3 fingerprint | after the TLS ClientHello | `conn.bind_fingerprint(digest)` | deny and eject |
| 4 request | every request | `conn.request(id)`; build the response in a `Collected` | `RegistryFull`: answer unavailable |
| 5 identity | right after authentication | `bind_session`, `bind_account`, `bind_tenant` | deny and eject; final |
| 6 stages | between every pair of pipeline stages | `request.checkpoint()` | `request.deny_and_eject(&mut reply)` and stop |
| 7 commit | before every commit or irreversible side effect | `request.before_commit()` | roll back, deny and eject, stop |
| 8 encode | before encoding the response | `request.checkpoint()` | deny and eject |
| 9 write | before every socket write | the transport's egress check | the transport wipes, sends the denial if nothing has left, closes |
| 10 misbehaviour | anywhere | `ticket.strike(kind)` | the outcome says what happened |

A pipeline that skips steps 6 to 8 still cannot send a byte for a revoked connection (step 9 is the transport's), and a revoked ticket that goes `max_unchecked` without a checkpoint is found by maintenance, ejected, and reported as `bouncer.checkpoint.missing`, so the gap is visible.

Long handlers poll `request.is_cancelled()` inside their loops, so a revoked request stops working, not only stops being answered.

## Transport (net-io)

net-io calls bouncer through its `Gate` trait (bouncer's feature `net-io`, from 0.8). The agreed shape:

| net-io calls | bouncer does |
|---|---|
| `Gate::admit(info, Accept)` | the door with net-io's id and accept time; returns the connection's ticket and its `TicketTag` as the `GateTag`; refusals are a silent `Refusal::Reset` |
| `Gate::readmit(ticket, info)` after a trusted PROXY header | `bind_client` with `Provenance::ProxyProtocol` |
| `Gate::check(ticket, write)` before every write | the egress check: one atomic load while nothing is revoked; the response's tag (`write.response`, set through `Output::begin_tagged_response`) is judged when present, otherwise the connection and its latest request |
| `Gate::closed(ticket, info, reason)` | releases the ticket; misbehaviour reasons become strikes |
| `ServerHandle::kill(id, reason)` | used by bouncer's `Ejector` for eject-now sweeps and idle checks |

On `Err(Denial { code })` net-io wipes its pending output, asks the session to format the denial for `code` (1 `Unavailable`, 2 `NotFound`, 3 `TooManyRequests`, 4 `Unauthorized`, 5 `Forbidden`) only if nothing of the response has left, and closes with `SO_LINGER` 0.

A transport other than net-io uses the same calls directly: `door_at`, `into_tag`, `Bouncer::request(tag, id)`, `Bouncer::egress(tag)`, `Bouncer::release(tag)`.

## Pipeline (serve-net, a gateway, a worker)

```rust
use bouncer_io::{Collected, RequestId, SessionKey, Verdict};

fn handle(conn: &bouncer_io::Ticket, id: RequestId, session: SessionKey) {
    let Ok(mut request) = conn.request(id) else { return /* answer unavailable */ };
    let mut reply = Collected::new();
    if request.bind_session(session).is_deny() {
        let _ = request.deny_and_eject(&mut reply);
        return;
    }
    for _stage in ["route", "authorize", "load", "render"] {
        if let Verdict::Deny(_) = request.checkpoint() {
            let _ = request.deny_and_eject(&mut reply);
            return;
        }
        // run the stage, writing the response into `reply`
    }
    if request.before_commit().is_deny() {
        // roll back
        let _ = request.deny_and_eject(&mut reply);
        return;
    }
    // commit, then send `reply`
}
```

Build every response in a `Collected`, so a denial overwrites it: growth copies and wipes, and the whole capacity is wiped on deny and on drop. For responses that must be all-or-nothing, buffer the whole response before the first write, so the egress check sees all of it; a streamed response can leak at most one transport chunk after a revocation.

## Protocol adapter

The adapter implements `DenialFormat` (set with `BouncerBuilder::denial_format`) and, with net-io, the session's denial hook. Use the same body and headers as the adapter's own refusal of each code, so a revoked request's denial is byte-identical to an ordinary refusal. Nothing in a `Denial` says why; the reason goes only to events.

Forwarded headers (`Forwarded`, `X-Forwarded-For`) are believed only from the trusted proxies the bouncer was built with; the adapter picks the right-most address that is not a trusted proxy and calls `bind_client` with `Provenance::ForwardedHeader` on the request.

## Authentication and authorization gates

The gates bind identity after authentication (step 5) and issue revocations through directives:

```rust
use bouncer_io::{Actor, Bouncer, Directive, Reason, SessionKey, AccountKey};

fn logout(bouncer: &Bouncer, session: SessionKey) {
    let _ = bouncer.apply(Directive::revoke(session).by(Actor::Gate).because(Reason::LOGOUT));
}

fn password_changed(bouncer: &Bouncer, account: AccountKey) {
    let _ = bouncer.apply(Directive::revoke(account).by(Actor::Gate).because(Reason::PASSWORD_CHANGED).eject_now());
}
```

A revocation stops running work. Keeping a logged-out token out of future requests is the session store's job (or a ban on the session key).

Failed logins and authorization denials are strikes (`StrikeKind::LoginFailed`, `AuthzDenied`); reuse of a revoked token is `TombstoneReuse`; a decoy token is `DecoyTouched` (definitive).

## The security signal bridge

Every action is an event through the `EventSink` (`BouncerBuilder::event_sink`), with a stable signal id (generator `GENERATOR`, the catalog in `docs/API.md`), category, severity, actor, reason, subject, reference, and bounded evidence. The sink is called on the acting thread and must not block: copy and hand off.

Decisions come back through `Bouncer::apply` from any thread. The security core can own the revocation epoch word (`BouncerBuilder::epoch`), so other modules read the same word at their own checkpoints. bouncer's own strike thresholds observe by default; switch categories to enforce with `Enforcement`.

## Maintenance

Either call `bouncer.maintain(bouncer.now())` from your own worker when it returns `next_due`, or set `BouncerBuilder::maintainer(true)` for one thread that parks until work is due and is woken by revocations. With nothing revoked it never wakes. Give the bouncer an `Ejector` over your transport's kill handle, or eject-now sweeps and idle checks can flag tickets but not close their connections.

## Choosing defaults

| Setting | Default | Change it when |
|---|---|---|
| `tickets` | 65,536 | more concurrent connections plus requests than that; keep the transport's connection cap below it |
| `ban_capacity` | 1,048,576 | memory is tight, or more bans are expected |
| `revocation_capacity` | 65,536 | many revocations within the cleanup window |
| door budgets | 20/s burst 40 and 64 concurrent per client (an IPv4 address or an IPv6 /64); 200/s and 512 concurrent per /24 or /48 | real users behind one address (offices, carrier NAT) hit them; health checkers go in the allow list as budget-exempt |
| enforcement | observe every strike kind | you have watched the `threshold.reached` events and trust a category |
| `max_unchecked` | 60 s | long-lived connections should be checked sooner |

<br>

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>James Gober.</strong></sup>
</div>
