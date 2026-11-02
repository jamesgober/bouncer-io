//! Prefix escalation: enough distinct children of one parent banned within a
//! window bans the parent and folds the children into it.
//!
//! The tracker lives inside the ban writer lock, so it costs nothing on the
//! door path. Guards that need the allow list, the trusted proxies, and the
//! shared-address flags are checked by the caller before the parent is banned.

use core::time::Duration;
use std::collections::{HashMap, VecDeque};

use super::table::TableKey;
use crate::{
    error::{ConfigError, ConfigProblem},
    keys::{Cidr, Family},
};

/// Most parents tracked at once.
const MAX_PARENTS: usize = 65_536;

/// When and how far automatic bans escalate to wider prefixes.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Bouncer, EscalationPolicy};
/// use std::time::Duration;
/// let bouncer = Bouncer::builder()
///     .escalation(EscalationPolicy::default().ipv4_threshold(4).window(Duration::from_secs(600)))
///     .try_build()?;
/// for i in 1..=4u8 {
///     bouncer.ban(std::net::IpAddr::from([198, 51, 100, i]))?;
/// }
/// assert!(bouncer.door("198.51.100.200".parse()?).is_err());   // the /24 is banned
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EscalationPolicy {
    pub(crate) ipv4_threshold: u16,
    pub(crate) ipv6_threshold: u16,
    pub(crate) window: Duration,
    pub(crate) factor: u32,
    pub(crate) widest_ipv4: u8,
    pub(crate) widest_ipv6: u8,
    pub(crate) max_children: u16,
    pub(crate) on: bool,
}

impl Default for EscalationPolicy {
    /// IPv4: 8 distinct /32 in one /24. IPv6: 4 distinct /64 in one /56, and
    /// /56 in one /48. Within 1 hour, factor 2, widest /24 and /48, at most
    /// 64 children per parent.
    fn default() -> Self {
        EscalationPolicy {
            ipv4_threshold: 8,
            ipv6_threshold: 4,
            window: Duration::from_secs(3600),
            factor: 2,
            widest_ipv4: 24,
            widest_ipv6: 48,
            max_children: 64,
            on: true,
        }
    }
}

impl EscalationPolicy {
    /// Distinct IPv4 children that escalate a parent (default 8).
    #[must_use]
    pub fn ipv4_threshold(mut self, children: u16) -> Self {
        self.ipv4_threshold = children;
        self
    }

    /// Distinct IPv6 children that escalate a parent (default 4).
    #[must_use]
    pub fn ipv6_threshold(mut self, children: u16) -> Self {
        self.ipv6_threshold = children;
        self
    }

    /// The window the children must be banned within (default 1 hour).
    #[must_use]
    pub fn window(mut self, d: Duration) -> Self {
        self.window = d;
        self
    }

    /// The parent's duration: the longest remaining child times this
    /// (default 2), capped by the duration policy's maximum.
    #[must_use]
    pub fn factor(mut self, f: u32) -> Self {
        self.factor = f;
        self
    }

    /// The widest IPv4 prefix escalation reaches (default /24).
    #[must_use]
    pub fn widest_ipv4(mut self, len: u8) -> Self {
        self.widest_ipv4 = len;
        self
    }

    /// The widest IPv6 prefix escalation reaches (default /48).
    #[must_use]
    pub fn widest_ipv6(mut self, len: u8) -> Self {
        self.widest_ipv6 = len;
        self
    }

    /// Children one parent may hold before inserting another forces
    /// escalation (default 64).
    #[must_use]
    pub fn max_children_per_parent(mut self, n: u16) -> Self {
        self.max_children = n;
        self
    }

    /// No escalation.
    #[must_use]
    pub fn off(mut self) -> Self {
        self.on = false;
        self
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if !self.on {
            return Ok(());
        }
        if self.ipv4_threshold < 2 || self.ipv6_threshold < 2 || self.max_children == 0 {
            return Err(ConfigError::new(
                "escalation",
                ConfigProblem::TooSmall { min: 2 },
            ));
        }
        if self.factor == 0 {
            return Err(ConfigError::new("escalation", ConfigProblem::InvalidFactor));
        }
        if self.window.is_zero() {
            return Err(ConfigError::new(
                "escalation",
                ConfigProblem::InvalidDuration,
            ));
        }
        if self.widest_ipv4 > 32 || self.widest_ipv6 > 128 {
            return Err(ConfigError::new("escalation", ConfigProblem::InvalidLength));
        }
        Ok(())
    }

    fn threshold(&self, family: Family) -> usize {
        let t = match family {
            Family::V4 => self.ipv4_threshold,
            Family::V6 => self.ipv6_threshold,
        };
        usize::from(t.min(self.max_children.saturating_add(1)))
    }

    /// The prefix strikes against `source` also count at, and how many of a
    /// kind's thresholds it takes there: the widest automatic prefix
    /// escalation reaches, and the strikes escalation would need to ban it
    /// from `source` up (each level's fan-in, multiplied). `None` with
    /// escalation off or no automatic length between `source` and the
    /// widest.
    pub(crate) fn strike_prefix(
        &self,
        source: &Cidr,
        is_auto: impl Fn(u8) -> bool,
    ) -> Option<(Cidr, u32)> {
        if !self.on {
            return None;
        }
        let widest = self.widest(source.family());
        let mut levels = 0u32;
        let mut top = None;
        for len in (widest..source.len()).rev() {
            if is_auto(len) {
                levels += 1;
                top = Some(len);
            }
        }
        let fan_in = self.threshold(source.family()) as u32;
        Some((source.parent(top?)?, fan_in.saturating_pow(levels)))
    }

    fn widest(&self, family: Family) -> u8 {
        match family {
            Family::V4 => self.widest_ipv4,
            Family::V6 => self.widest_ipv6,
        }
    }
}

/// What to escalate: the parent and the children to fold into it.
#[derive(Debug, Clone)]
pub(crate) struct Plan {
    pub(crate) parent: Cidr,
    pub(crate) children: Vec<TableKey>,
    /// Longest remaining child duration in seconds; `None` when a child is
    /// permanent.
    pub(crate) longest: Option<u64>,
}

/// Children banned per parent, within the window.
#[derive(Debug, Default)]
pub(crate) struct Tracker {
    /// parent -> (child, noted at secs)
    parents: HashMap<Cidr, Vec<(Cidr, u64)>>,
    /// Parents in the order they were first noted, for evicting the oldest
    /// in constant time. May hold parents already gone; they are skipped.
    order: VecDeque<Cidr>,
}

impl Tracker {
    /// The next prefix up the ladder from `child`: the longest automatic
    /// length shorter than it, no wider than the policy allows.
    pub(crate) fn parent_of(
        policy: &EscalationPolicy,
        child: &Cidr,
        is_auto: impl Fn(u8) -> bool,
    ) -> Option<Cidr> {
        if !policy.on || child.len() == 0 {
            return None;
        }
        let widest = policy.widest(child.family());
        (widest..child.len())
            .rev()
            .find(|&l| is_auto(l))
            .and_then(|l| child.parent(l))
    }

    /// Notes a banned child. Returns the parent and its children when the
    /// threshold (or the per-parent quota) is reached; the parent is then
    /// forgotten here.
    pub(crate) fn note(
        &mut self,
        policy: &EscalationPolicy,
        parent: Cidr,
        child: Cidr,
        now_secs: u64,
    ) -> Option<Vec<Cidr>> {
        let window = policy.window.as_secs().max(1);
        if !self.parents.contains_key(&parent) {
            // Full: forget the parent noted longest ago. One pop per new
            // parent, so a flood of new prefixes costs constant time each.
            while self.parents.len() >= MAX_PARENTS {
                match self.order.pop_front() {
                    Some(old) => {
                        self.parents.remove(&old);
                    }
                    None => break,
                }
            }
            if self.order.len() >= 2 * MAX_PARENTS {
                let parents = &self.parents;
                self.order.retain(|p| parents.contains_key(p));
            }
            self.order.push_back(parent);
        }
        let children = self.parents.entry(parent).or_default();
        children.retain(|&(_, t)| t + window > now_secs);
        match children.iter_mut().find(|(c, _)| *c == child) {
            Some(entry) => entry.1 = now_secs,
            None => children.push((child, now_secs)),
        }
        if children.len() >= policy.threshold(parent.family()) {
            return self
                .parents
                .remove(&parent)
                .map(|v| v.into_iter().map(|(c, _)| c).collect());
        }
        None
    }

    /// Forgets a lifted child: a ban that was lifted does not count toward
    /// its parent's escalation.
    pub(crate) fn forget(&mut self, parent: &Cidr, child: &Cidr) {
        if let Some(children) = self.parents.get_mut(parent) {
            children.retain(|(c, _)| c != child);
            if children.is_empty() {
                self.parents.remove(parent);
            }
        }
    }

    /// Puts a parent's children back (its escalation was refused), keeping at
    /// most the quota, newest first.
    pub(crate) fn restore(
        &mut self,
        policy: &EscalationPolicy,
        parent: Cidr,
        children: &[Cidr],
        now_secs: u64,
    ) {
        let keep = usize::from(policy.max_children);
        let v: Vec<(Cidr, u64)> = children
            .iter()
            .rev()
            .take(keep)
            .map(|&c| (c, now_secs))
            .collect();
        self.parents.insert(parent, v);
    }
}

#[cfg(all(test, not(bouncer_loom)))]
mod tests {
    use super::*;

    fn v4(n: u32) -> Cidr {
        Cidr::host(std::net::IpAddr::from(n.to_be_bytes()))
    }

    #[test]
    fn test_full_tracker_forgets_oldest_in_constant_time() {
        let policy = EscalationPolicy::default();
        let mut t = Tracker::default();
        let started = std::time::Instant::now();
        // Three times the bound, one child per /24: every note is a new parent.
        for i in 0..(3 * MAX_PARENTS as u32) {
            let child = v4(0x0a00_0001 | (i << 8));
            let parent = child.parent(24).unwrap();
            assert!(t.note(&policy, parent, child, 0).is_none());
        }
        assert!(t.parents.len() <= MAX_PARENTS);
        assert!(t.order.len() <= 2 * MAX_PARENTS);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        // The newest parents are kept, so an attack in progress still escalates.
        let last = 3 * MAX_PARENTS as u32 - 1;
        let parent = v4(0x0a00_0001 | (last << 8)).parent(24).unwrap();
        let mut due = None;
        for h in 2..=8u32 {
            let child = v4((0x0a00_0000 | (last << 8)) + h);
            due = t.note(&policy, parent, child, 0);
        }
        assert_eq!(due.map(|c| c.len()), Some(8));
    }
}
