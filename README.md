<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br>
    <b>bouncer-io</b>
    <br>
    <sub><sup>THE CONNECTION GATE</sup></sub>
</h1>

<div align="center">
    <a href="https://crates.io/crates/bouncer-io"><img alt="Crates.io" src="https://img.shields.io/crates/v/bouncer-io"></a>
    <a href="https://crates.io/crates/bouncer-io"><img alt="Downloads" src="https://img.shields.io/crates/d/bouncer-io?color=%230099ff"></a>
    <a href="https://docs.rs/bouncer-io"><img alt="docs.rs" src="https://img.shields.io/docsrs/bouncer-io"></a>
    <a href="https://github.com/jamesgober/bouncer-io/actions"><img alt="CI" src="https://github.com/jamesgober/bouncer-io/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md"><img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.85%2B-blue"></a>
</div>

<br>

<div align="left">
    <p>
        <strong>bouncer-io</strong> is the door guy. Every connection that comes in goes past it, and everything that goes back out goes past it again. At the door it knows who is banned (by address, prefix, client fingerprint, session, or account) and refuses them before a byte of their traffic is read.
    </p>
    <p>
        Inside, it does not care where a request has got to. If the request, its session, its account, or its source is flagged while it is still being handled, the next checkpoint it crosses wipes everything it collected, replaces the response with a denial, throws the connection out, and remembers the offender so the next attempt dies at the door. A checkpoint costs one atomic load until something is actually revoked.
    </p>
    <br>
    <hr>
    <p>
        <strong>MSRV is 1.85+</strong> (Rust 2024 edition). <code>#![forbid(unsafe_code)]</code>.
    </p>
    <blockquote>
        <strong>Status: <code>0.7.0</code> (hardening).</strong> Feature complete since <code>0.5.0</code>; 0.6 made the door 24% faster, tickets 47% faster, and binds 70% faster (measurements in <a href="./docs/PERFORMANCE.md"><code>docs/PERFORMANCE.md</code></a>). 0.7 tested every threat and edge case of the plan, fuzzed and soaked for 24 hours with no findings, and made sharing across nodes converge; threats and defences are in <a href="./docs/SECURITY.md"><code>docs/SECURITY.md</code></a>. The net-io integration comes next. See <a href="./docs/API.md"><code>docs/API.md</code></a>, <a href="./docs/INTEGRATION.md"><code>docs/INTEGRATION.md</code></a>, <a href="./docs/ARCHITECTURE.md"><code>docs/ARCHITECTURE.md</code></a>, and <a href="./dev/ROADMAP.md"><code>dev/ROADMAP.md</code></a>.
    </blockquote>
</div>

<hr>
<br>

## Installation

```toml
[dependencies]
bouncer-io = "0.7"
```

<hr>
<br>

## Quick start

The Tier 1 API (see [`docs/API.md`](./docs/API.md)): the door, a request, a revocation from another thread, and the checkpoint that throws the request out.

```rust
use bouncer_io::{Bouncer, Collected, Reason, RequestId, Verdict};

let bouncer = Bouncer::new();

// The door: before reading a byte. A refusal means close abortively.
let conn = bouncer.door("203.0.113.7".parse()?)?;

// A request on that connection, and the buffer its response is built in.
let mut request = conn.request(RequestId(1))?;
let mut reply = Collected::new();

// Anywhere, any thread: an administrator throws this connection out.
bouncer.revoke(conn.conn(), Reason::ADMIN)?;

// Between pipeline stages: one atomic load until something is revoked.
if let Verdict::Deny(_) = request.checkpoint() {
    request.deny_and_eject(&mut reply);   // wipe, replace, eject, remember
}
```

Banning is one line, and a logout stops the session's running requests:

```rust
bouncer.ban("2001:db8:7::/48".parse::<bouncer_io::Cidr>()?)?;
bouncer.revoke(session_key, Reason::LOGOUT)?;
```

<hr>
<br>

## Scope

Admission at the door (ban memory by address, prefix, fingerprint, session, and account; prefix escalation; per-prefix budgets), in-flight revocation through epoch-gated checkpoints (between stages, before commit, and at egress through net-io), wipe-replace-eject with a zeroizing response buffer, strikes from every layer, persistence and sharing of bans. Rate and concurrency budgets are one tool at the door, not the purpose. It is not a rate limiter, a parser, or the detection layer (that is sentinel-sec). Bans and revocations are shared across nodes as mergeable deltas, and every action is reported as a security event.

See [`dev/PLAN.md`](./dev/PLAN.md) for the full scope, what is deliberately left to other crates, and the decision log.

<hr>
<br>

## Contributing

See <a href="./dev/DIRECTIVES.md"><code>dev/DIRECTIVES.md</code></a> for engineering standards and the definition of done. Before a PR: `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-features` must be clean.

<br>

<div id="license">
    <h2>License</h2>
    <p>Licensed under either of</p>
    <ul>
        <li><b>Apache License, Version 2.0</b> (<a href="./LICENSE-APACHE">LICENSE-APACHE</a>)</li>
        <li><b>MIT License</b> (<a href="./LICENSE-MIT">LICENSE-MIT</a>)</li>
    </ul>
    <p>at your option.</p>
</div>

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>James Gober.</strong></sup>
</div>
