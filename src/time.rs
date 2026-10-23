//! The bouncer's time base: monotonic nanoseconds since the bouncer started.

use core::time::Duration;

/// Monotonic time: nanoseconds since the bouncer started.
///
/// In-process expiry uses only this, so stepping the wall clock never
/// shortens a ban. A `Now` older than one already seen makes an expiry check
/// stricter, never looser: nothing expires early.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Bouncer, Now};
/// let bouncer = Bouncer::new();
/// let a = bouncer.now();
/// assert!(bouncer.now() >= a);
/// assert_eq!(Now::from_nanos(5).as_nanos(), 5);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Now(u64);

impl Now {
    /// A time this many nanoseconds after the bouncer started.
    #[must_use]
    pub const fn from_nanos(nanos: u64) -> Now {
        Now(nanos)
    }

    /// Nanoseconds since the bouncer started.
    #[must_use]
    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    /// Whole seconds since the bouncer started, the resolution of ban expiry.
    pub(crate) const fn secs(self) -> u64 {
        self.0 / 1_000_000_000
    }

    pub(crate) fn from_duration(d: Duration) -> Now {
        Now(u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
    }
}

/// Seconds, rounded up, saturating at `u64::MAX`.
pub(crate) fn ceil_secs(d: Duration) -> u64 {
    let whole = d.as_secs();
    if d.subsec_nanos() > 0 {
        whole.saturating_add(1)
    } else {
        whole
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_now_secs_truncates() {
        assert_eq!(Now::from_nanos(1_999_999_999).secs(), 1);
        assert_eq!(Now::from_duration(Duration::from_secs(3)).secs(), 3);
    }

    #[test]
    fn test_ceil_secs_rounds_up() {
        assert_eq!(ceil_secs(Duration::from_millis(1)), 1);
        assert_eq!(ceil_secs(Duration::from_secs(2)), 2);
        assert_eq!(ceil_secs(Duration::MAX), u64::MAX);
    }

    #[test]
    fn test_now_from_huge_duration_saturates() {
        assert_eq!(Now::from_duration(Duration::MAX).as_nanos(), u64::MAX);
    }
}
