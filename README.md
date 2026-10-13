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
        <strong>Status: scaffold (<code>0.1.0</code>).</strong> No functional code yet. The design is written down in <a href="./dev/PLAN.md"><code>dev/PLAN.md</code></a> and the schedule in <a href="./dev/ROADMAP.md"><code>dev/ROADMAP.md</code></a>; the public API is locked in <code>0.2.0</code>.
    </blockquote>
</div>

<hr>
<br>

## Scope

Admission at the door (ban memory by address, prefix, fingerprint, session, and account; prefix escalation; per-prefix budgets), in-flight revocation through epoch-gated checkpoints (between stages, before commit, and at egress through net-io), wipe-replace-eject with a zeroizing response buffer, strikes from every layer, persistence and sharing of bans. It is not a rate limiter, a parser, or the detection layer (that is sentinel-sec).

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
        <li><b>Apache License, Version 2.0</b> &mdash; <a href="./LICENSE-APACHE">LICENSE-APACHE</a></li>
        <li><b>MIT License</b> &mdash; <a href="./LICENSE-MIT">LICENSE-MIT</a></li>
    </ul>
    <p>at your option.</p>
</div>

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>James Gober.</strong></sup>
</div>
