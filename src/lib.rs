//! Network access gate for Rust. Rate limiting, throttling, suspicious-activity detection, and active connection termination in one IO filter. Token bucket / leaky bucket / sliding window limiters, per-key / per-IP / global, with a hook to forcibly cut connections of misbehaving peers already past the gate.
//!
//! # Status
//!
//! This crate is in early scaffolding. The public API is not yet
//! defined. See [the repository](https://github.com/jamesgober/bouncer-io)
//! and `.dev/ROADMAP.md` for the milestone plan.

#![doc(html_root_url = "https://docs.rs/bouncer-io")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Crate version string, populated by Cargo at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
