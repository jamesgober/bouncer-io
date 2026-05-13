<h1 align="center">
    <strong>bouncer-io</strong>
    <br>
    <sup><sub>NETWORK ACCESS GATE FOR RUST</sub></sup>
</h1>

<p align="center">
    <a href="https://crates.io/crates/bouncer-io"><img alt="crates.io" src="https://img.shields.io/crates/v/bouncer-io.svg"></a>
    <a href="https://crates.io/crates/bouncer-io"><img alt="downloads" src="https://img.shields.io/crates/d/bouncer-io.svg"></a>
    <a href="https://docs.rs/bouncer-io"><img alt="docs.rs" src="https://docs.rs/bouncer-io/badge.svg"></a>
    <a href="https://github.com/jamesgober/bouncer-io/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/jamesgober/bouncer-io/actions/workflows/ci.yml/badge.svg"></a>
</p>

<p align="center">
    Rate limit + throttle + suspicious activity detection + active connection termination, all in one access gate.
</p>

---

## Status

Status: DEFERRED (short-term) - placeholder repo to claim the crates.io name. Active design begins when HiveDB has a public-facing network surface. See `.dev/ROADMAP.md`.

This repository is published primarily to reserve the crate name and
to establish the project scaffolding. Implementation work proceeds on
the schedule documented in `.dev/ROADMAP.md`.

## What it does

Network access gate for Rust. Rate limiting, throttling, suspicious-activity detection, and active connection termination in one IO filter. Token bucket / leaky bucket / sliding window limiters, per-key / per-IP / global, with a hook to forcibly cut connections of misbehaving peers already past the gate.

## License

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE)
for the full text.

Copyright (C) 2026 James Gober.
