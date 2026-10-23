//! # bouncer_io
//!
//! Connection gate for Rust services: admission by address, prefix, fingerprint, session, and account; in-flight revocation through cheap checkpoints; wipe, replace, and eject of revoked requests; ban memory with prefix escalation. Protocol-free.
//!
//! ## Status
//!
//! Design lock. The public API is written down in `docs/API.md`, the design
//! in `dev/PLAN.md`, and the schedule in `dev/ROADMAP.md` (all in the
//! [repository](https://github.com/jamesgober/bouncer-io)). Code lands from
//! `0.3.0`.

#![doc(html_root_url = "https://docs.rs/bouncer-io")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Crate version string, populated by Cargo at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn version_matches_manifest() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert_eq!(VERSION.split('.').count(), 3, "expected MAJOR.MINOR.PATCH");
    }
}
