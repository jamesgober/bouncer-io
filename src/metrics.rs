//! Counters, with the `metrics` feature. Without it the counters do not
//! exist and every [`meter!`] is empty.
//!
//! Counters are per shard, relaxed, on the shard's own cache line. The
//! checkpoint fast path does not touch them: a ticket counts its fast checks
//! in a plain field and adds them to its shard at its next slow path and when
//! it is dropped, so the one-load fast path stays one load.

#[cfg(feature = "metrics")]
use crate::sync::{AtomicU64, Ordering};

/// Adds one to a counter of a [`Meters`], or does nothing without the
/// `metrics` feature.
macro_rules! meter {
    ($meters:expr, $field:ident) => {{
        #[cfg(feature = "metrics")]
        {
            $meters.$field.fetch_add(1, $crate::sync::Ordering::Relaxed);
        }
    }};
    ($meters:expr, $field:ident, $n:expr) => {{
        #[cfg(feature = "metrics")]
        {
            $meters
                .$field
                .fetch_add(u64::from($n), $crate::sync::Ordering::Relaxed);
        }
    }};
}
pub(crate) use meter;

macro_rules! meters {
    ($($(#[$doc:meta])* $field:ident),* $(,)?) => {
        /// One set of counters (per shard, plus one for cold paths).
        #[cfg(feature = "metrics")]
        #[repr(align(64))]
        #[derive(Default)]
        pub(crate) struct Meters {
            $(pub(crate) $field: AtomicU64,)*
        }

        /// Without the feature: nothing.
        #[cfg(not(feature = "metrics"))]
        #[derive(Default)]
        pub(crate) struct Meters;

        /// Counter totals at one moment. Counters only grow, except the
        /// gauges `bans_active` and `journal_queue`.
        ///
        /// # Examples
        ///
        /// ```
        /// let bouncer = bouncer_io::Bouncer::new();
        /// let _conn = bouncer.door("192.0.2.1".parse()?)?;
        /// assert_eq!(bouncer.metrics().admitted, 1);
        /// # Ok::<(), Box<dyn std::error::Error>>(())
        /// ```
        #[cfg(feature = "metrics")]
        #[non_exhaustive]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
        pub struct MetricsSnapshot {
            $($(#[$doc])* pub $field: u64,)*
        }

        #[cfg(feature = "metrics")]
        impl MetricsSnapshot {
            pub(crate) fn add(&mut self, m: &Meters) {
                $(self.$field += m.$field.load(Ordering::Relaxed);)*
            }
        }
    };
}

meters! {
    /// Connections admitted at the door.
    admitted,
    /// Refused at the door: banned.
    refused_ban,
    /// Refused at the door: over budget.
    refused_budget,
    /// Refused at the door: no free ticket.
    refused_registry_full,
    /// Refused at the door by the strict posture.
    refused_posture,
    /// Checkpoints that took the one-load fast path.
    checkpoints_fast,
    /// Checkpoints that took the slow path.
    checkpoints_slow,
    /// Revocations applied.
    revocations,
    /// `deny_and_eject` calls.
    denials,
    /// Connections ejected by bouncer.
    ejections,
    /// Before-commit checkpoints that denied.
    commits_blocked,
    /// Transport egress checks that denied.
    egress_blocked,
    /// Bans in memory now (gauge).
    bans_active,
    /// Bans added.
    bans_added,
    /// Expired bans reclaimed.
    bans_expired,
    /// Bans evicted from a full table.
    bans_evicted,
    /// Prefix escalations.
    bans_escalated,
    /// Bans lifted.
    bans_lifted,
    /// Lane and tenant budget refusals.
    budget_refused,
    /// Strikes received.
    strikes,
    /// Thresholds reached in observe mode.
    thresholds_observed,
    /// Thresholds reached in enforce mode.
    thresholds_enforced,
    /// Maintenance runs.
    sweeps,
    /// Persistence records queued (gauge).
    journal_queue,
}
