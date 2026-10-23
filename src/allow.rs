//! The allow list: sources automation never acts on.

use crate::{
    bans::compiled::PrefixSet,
    error::{ConfigError, ConfigProblem},
    keys::Cidr,
};

/// Most allow-list entries accepted.
pub(crate) const MAX_ALLOW_ENTRIES: usize = 65_536;

/// What an allow-list entry exempts.
///
/// # Examples
///
/// ```
/// use bouncer_io::AllowKind;
/// assert_ne!(AllowKind::Immune, AllowKind::ExemptBudgets);
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AllowKind {
    /// Never banned, throttled, struck, or revoked by automation; an
    /// administrator ban is refused with `AllowListed`.
    Immune,
    /// Skips rate and concurrency budgets, but can still be banned (load
    /// balancer health checkers).
    ExemptBudgets,
}

/// The allow list, compiled when given to the bouncer and swapped whole.
///
/// # Examples
///
/// ```
/// use bouncer_io::{AllowList, Bouncer};
/// let bouncer = Bouncer::builder()
///     .allow(
///         AllowList::new()
///             .immune("10.20.0.0/16".parse()?, "own infrastructure")
///             .exempt_budgets("192.0.2.200".parse()?, "health checks"),
///     )
///     .try_build()?;
/// assert!(bouncer.ban("10.20.1.1".parse::<std::net::IpAddr>()?).is_err());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Default)]
pub struct AllowList {
    entries: Vec<(Cidr, AllowKind, &'static str)>,
}

impl AllowList {
    /// An empty list.
    #[must_use]
    pub fn new() -> AllowList {
        AllowList::default()
    }

    /// Adds an immune entry.
    #[must_use]
    pub fn immune(mut self, cidr: Cidr, label: &'static str) -> AllowList {
        self.entries.push((cidr, AllowKind::Immune, label));
        self
    }

    /// Adds a budget-exempt entry.
    #[must_use]
    pub fn exempt_budgets(mut self, cidr: Cidr, label: &'static str) -> AllowList {
        self.entries.push((cidr, AllowKind::ExemptBudgets, label));
        self
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` when the list has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Compiles the list. When a prefix appears with both kinds, `Immune` wins.
    pub(crate) fn compile(&self) -> Result<PrefixSet<AllowKind>, ConfigError> {
        if self.entries.len() > MAX_ALLOW_ENTRIES {
            return Err(ConfigError::new("allow", ConfigProblem::AllowListTooLarge));
        }
        let pairs: Vec<(Cidr, AllowKind)> = self.entries.iter().map(|(c, k, _)| (*c, *k)).collect();
        Ok(PrefixSet::build(&pairs, |a, b| {
            if *a == AllowKind::Immune || *b == AllowKind::Immune {
                AllowKind::Immune
            } else {
                *a
            }
        }))
    }
}

/// The strongest allow kind covering an address: `Immune` over `ExemptBudgets`.
pub(crate) fn lookup(set: &PrefixSet<AllowKind>, addr: std::net::IpAddr) -> Option<AllowKind> {
    if set.is_empty() {
        return None;
    }
    let mut found = None;
    set.find_map(addr, |k| {
        if *k == AllowKind::Immune {
            return Some(AllowKind::Immune);
        }
        found = Some(*k);
        None
    })
    .or(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> Cidr {
        s.parse().unwrap()
    }

    #[test]
    fn test_allow_immune_wins_over_exempt() {
        let list = AllowList::new()
            .exempt_budgets(c("10.0.0.0/8"), "lb")
            .immune(c("10.1.0.0/16"), "infra");
        let set = list.compile().unwrap();
        assert_eq!(
            lookup(&set, "10.1.2.3".parse().unwrap()),
            Some(AllowKind::Immune)
        );
        assert_eq!(
            lookup(&set, "10.2.2.3".parse().unwrap()),
            Some(AllowKind::ExemptBudgets)
        );
        assert_eq!(lookup(&set, "11.0.0.1".parse().unwrap()), None);
    }

    #[test]
    fn test_allow_same_prefix_both_kinds_is_immune() {
        let list = AllowList::new()
            .exempt_budgets(c("10.0.0.0/8"), "a")
            .immune(c("10.0.0.0/8"), "b");
        let set = list.compile().unwrap();
        assert_eq!(
            lookup(&set, "10.0.0.1".parse().unwrap()),
            Some(AllowKind::Immune)
        );
        assert_eq!(list.len(), 2);
        assert!(!list.is_empty());
    }

    #[test]
    fn test_allow_too_large_refused() {
        let mut list = AllowList::new();
        for i in 0..=MAX_ALLOW_ENTRIES as u32 {
            list = list.immune(Cidr::host(std::net::IpAddr::from(i.to_be_bytes())), "x");
        }
        assert_eq!(
            list.compile().err().map(|e| e.problem),
            Some(ConfigProblem::AllowListTooLarge)
        );
    }
}
