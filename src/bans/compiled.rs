//! The compiled prefix set: lists that change rarely (the allow list, trusted
//! proxies, administrator prefixes of any length), built once and read
//! without locks.
//!
//! A multibit trie with a stride of six bits and population-count bitmaps,
//! in the style of Poptrie (Asai and Ohara, SIGCOMM 2015): each node has a
//! 64-bit mask of the slots that continue to a child and a 64-bit mask of the
//! slots that hold a prefix ending in this node, and its children and leaves
//! are stored contiguously, so the n-th set bit names the n-th child or leaf.
//! An IPv4 lookup visits at most 6 nodes and an IPv6 lookup at most 22 (11 for
//! prefixes up to /64), whatever the number of prefixes or lengths in use.
//!
//! Each leaf slot holds a chain of every prefix ending in that node that
//! covers the slot, longest first, so a lookup can visit every covering
//! prefix, most specific first.

use std::net::IpAddr;

use crate::keys::{Cidr, Family};

const STRIDE: u32 = 6;
const NONE: u32 = u32::MAX;
/// Levels an IPv6 lookup can visit (128 / 6, rounded up), plus the /0 entry.
const MAX_PATH: usize = 23;

#[derive(Clone, Copy, Default)]
struct Node {
    child_mask: u64,
    leaf_mask: u64,
    child_base: u32,
    leaf_base: u32,
}

/// One link of a leaf chain: an entry and the next (shorter) link.
#[derive(Clone, Copy)]
struct Link {
    entry: u32,
    next: u32,
}

struct Entry<V> {
    value: V,
    len: u8,
}

#[derive(Clone, Copy)]
struct Prefix {
    /// Left-aligned: the first bit of the address is the top bit.
    bits: u128,
    len: u8,
    entry: u32,
}

/// The six-bit index of `bits` at `level`.
#[inline]
fn index(bits: u128, level: u32) -> u32 {
    // The last IPv6 level (bits 126..132) runs past the address; the left
    // shift pads it with zeros.
    ((bits << (STRIDE * level)) >> (128 - STRIDE)) as u32
}

#[inline]
fn left_aligned(cidr: &Cidr) -> u128 {
    match cidr.family() {
        Family::V4 => cidr.bits() << 96,
        Family::V6 => cidr.bits(),
    }
}

#[inline]
fn rank(mask: u64, idx: u32) -> u32 {
    (mask & ((1u64 << idx) - 1)).count_ones()
}

/// An immutable set of prefixes, each with a value.
pub(crate) struct PrefixSet<V> {
    nodes: Vec<Node>,
    leaves: Vec<u32>,
    links: Vec<Link>,
    entries: Vec<Entry<V>>,
    roots: [u32; 2],
    defaults: [u32; 2],
    /// Every prefix as (family slot, left-aligned bits, length), sorted, for
    /// "is anything inside this prefix" (escalation checks; cold).
    spans: Vec<(u8, u128, u8)>,
}

fn family_slot(f: Family) -> usize {
    match f {
        Family::V4 => 0,
        Family::V6 => 1,
    }
}

impl<V: Clone> PrefixSet<V> {
    /// An empty set.
    pub(crate) fn empty() -> Self {
        PrefixSet {
            nodes: Vec::new(),
            leaves: Vec::new(),
            links: Vec::new(),
            entries: Vec::new(),
            roots: [NONE; 2],
            defaults: [NONE; 2],
            spans: Vec::new(),
        }
    }

    /// Builds the set. When a prefix appears twice, `keep` decides which
    /// value survives (it receives the kept value and the new one).
    pub(crate) fn build(input: &[(Cidr, V)], keep: impl Fn(&V, &V) -> V) -> Self {
        let mut sorted: Vec<&(Cidr, V)> = input.iter().collect();
        sorted.sort_by_key(|a| a.0);
        let mut set = PrefixSet::empty();
        set.spans = input
            .iter()
            .map(|(c, _)| (family_slot(c.family()) as u8, left_aligned(c), c.len()))
            .collect();
        set.spans.sort_unstable();
        set.spans.dedup();
        let mut by_family: [Vec<Prefix>; 2] = [Vec::new(), Vec::new()];
        for (cidr, value) in sorted {
            if let Some(last) = set.entries.last_mut() {
                let prev = by_family[family_slot(cidr.family())].last();
                if let Some(p) = prev {
                    if p.len == cidr.len() && p.bits == left_aligned(cidr) {
                        last.value = keep(&last.value, value);
                        continue;
                    }
                }
            }
            let entry = set.entries.len() as u32;
            set.entries.push(Entry {
                value: value.clone(),
                len: cidr.len(),
            });
            by_family[family_slot(cidr.family())].push(Prefix {
                bits: left_aligned(cidr),
                len: cidr.len(),
                entry,
            });
        }
        for (slot, prefixes) in by_family.iter().enumerate() {
            // A /0 entry covers everything; there is at most one per family.
            let (zero, rest): (Vec<Prefix>, Vec<Prefix>) =
                prefixes.iter().partition(|p| p.len == 0);
            if let Some(z) = zero.first() {
                set.defaults[slot] = set.push_link(z.entry, NONE);
            }
            if !rest.is_empty() {
                let root = set.nodes.len();
                set.nodes.push(Node::default());
                set.roots[slot] = root as u32;
                set.build_node(root, &rest, 0);
            }
        }
        set
    }

    fn push_link(&mut self, entry: u32, next: u32) -> u32 {
        self.links.push(Link { entry, next });
        (self.links.len() - 1) as u32
    }

    /// Fills node `at` from `prefixes`, every one longer than `6 * level`
    /// and sorted by bits.
    fn build_node(&mut self, at: usize, prefixes: &[Prefix], level: u32) {
        let end = STRIDE * (level + 1);
        // Leaf chains for prefixes ending in this node, longest first.
        let mut ending: Vec<Prefix> = prefixes
            .iter()
            .copied()
            .filter(|p| u32::from(p.len) <= end)
            .collect();
        ending.sort_by_key(|p| core::cmp::Reverse(p.len));
        let mut heads = [NONE; 64];
        let mut tails = [NONE; 64];
        for p in &ending {
            let fixed = u32::from(p.len) - STRIDE * level;
            let span = 1u32 << (STRIDE - fixed);
            let base = index(p.bits, level) & !(span - 1);
            for s in base..base + span {
                let link = self.push_link(p.entry, NONE);
                let s = s as usize;
                if heads[s] == NONE {
                    heads[s] = link;
                } else {
                    self.links[tails[s] as usize].next = link;
                }
                tails[s] = link;
            }
        }
        let mut node = Node {
            leaf_base: self.leaves.len() as u32,
            ..Node::default()
        };
        for (s, &h) in heads.iter().enumerate() {
            if h != NONE {
                node.leaf_mask |= 1u64 << s;
                self.leaves.push(h);
            }
        }
        // Children: prefixes continuing past this node, grouped by slot (they
        // are sorted by bits, so each group is contiguous).
        let longer: Vec<Prefix> = prefixes
            .iter()
            .copied()
            .filter(|p| u32::from(p.len) > end)
            .collect();
        let mut groups: Vec<(u32, usize, usize)> = Vec::new();
        let mut i = 0;
        while i < longer.len() {
            let idx = index(longer[i].bits, level);
            let mut j = i;
            while j < longer.len() && index(longer[j].bits, level) == idx {
                j += 1;
            }
            groups.push((idx, i, j));
            node.child_mask |= 1u64 << idx;
            i = j;
        }
        node.child_base = self.nodes.len() as u32;
        self.nodes
            .extend(std::iter::repeat_n(Node::default(), groups.len()));
        self.nodes[at] = node;
        for (n, &(_, from, to)) in groups.iter().enumerate() {
            self.build_node(node.child_base as usize + n, &longer[from..to], level + 1);
        }
    }
}

impl<V> PrefixSet<V> {
    /// Number of prefixes.
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Visits the values of every prefix covering the first `max_len` bits
    /// of `bits` (and no longer than `max_len`), most specific first, until
    /// `visit` returns `Some`.
    #[inline]
    fn walk<T>(
        &self,
        family: Family,
        bits: u128,
        max_len: u8,
        mut visit: impl FnMut(&V) -> Option<T>,
    ) -> Option<T> {
        let slot = family_slot(family);
        let mut path = [NONE; MAX_PATH];
        let mut depth = 0;
        if self.defaults[slot] != NONE {
            path[0] = self.defaults[slot];
            depth = 1;
        }
        let mut node_index = self.roots[slot];
        let mut level = 0u32;
        while node_index != NONE && depth < MAX_PATH {
            let node = &self.nodes[node_index as usize];
            let idx = index(bits, level);
            let bit = 1u64 << idx;
            if node.leaf_mask & bit != 0 {
                path[depth] = self.leaves[(node.leaf_base + rank(node.leaf_mask, idx)) as usize];
                depth += 1;
            }
            if node.child_mask & bit == 0 || STRIDE * (level + 1) >= u32::from(max_len) {
                break;
            }
            node_index = node.child_base + rank(node.child_mask, idx);
            level += 1;
        }
        for &head in path[..depth].iter().rev() {
            let mut link = head;
            while link != NONE {
                let l = self.links[link as usize];
                let e = &self.entries[l.entry as usize];
                if e.len <= max_len {
                    if let Some(t) = visit(&e.value) {
                        return Some(t);
                    }
                }
                link = l.next;
            }
        }
        None
    }

    /// Every value whose prefix contains `addr`, most specific first, until
    /// `visit` returns `Some`.
    #[inline]
    pub(crate) fn find_map<T>(
        &self,
        addr: IpAddr,
        visit: impl FnMut(&V) -> Option<T>,
    ) -> Option<T> {
        let host = Cidr::host(addr);
        self.walk(host.family(), left_aligned(&host), host.len(), visit)
    }

    /// Every value whose prefix contains all of `cidr`, most specific first,
    /// until `visit` returns `Some`.
    pub(crate) fn find_covering_map<T>(
        &self,
        cidr: &Cidr,
        visit: impl FnMut(&V) -> Option<T>,
    ) -> Option<T> {
        self.walk(cidr.family(), left_aligned(cidr), cidr.len(), visit)
    }

    /// `true` when some prefix contains `addr`.
    pub(crate) fn contains_addr(&self, addr: IpAddr) -> bool {
        self.find_map(addr, |_| Some(())).is_some()
    }

    /// `true` when some prefix contains all of `cidr`.
    pub(crate) fn covers(&self, cidr: &Cidr) -> bool {
        self.find_covering_map(cidr, |_| Some(())).is_some()
    }

    /// `true` when some prefix overlaps `cidr`: contains it, or lies inside it.
    pub(crate) fn overlaps(&self, cidr: &Cidr) -> bool {
        if self.covers(cidr) {
            return true;
        }
        let fam = family_slot(cidr.family()) as u8;
        let start = left_aligned(cidr);
        // Left-aligned, a prefix of length L spans start ..= start | (2^(128-L) - 1).
        let host = 128 - u32::from(cidr.len());
        let end = if host >= 128 {
            u128::MAX
        } else {
            start | ((1u128 << host) - 1)
        };
        let i = self
            .spans
            .partition_point(|&(f, b, _)| (f, b) < (fam, start));
        self.spans[i..]
            .iter()
            .take_while(|&&(f, b, _)| f == fam && b <= end)
            .any(|&(_, _, len)| len >= cidr.len())
    }

    /// Bytes reserved.
    pub(crate) fn bytes(&self) -> u64 {
        (self.nodes.capacity() * core::mem::size_of::<Node>()
            + self.spans.capacity() * core::mem::size_of::<(u8, u128, u8)>()
            + self.leaves.capacity() * 4
            + self.links.capacity() * core::mem::size_of::<Link>()
            + self.entries.capacity() * core::mem::size_of::<Entry<V>>()) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> Cidr {
        s.parse().unwrap()
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn test_prefix_set_finds_most_specific_first() {
        let set = PrefixSet::build(
            &[
                (c("10.0.0.0/8"), 8u8),
                (c("10.1.0.0/16"), 16),
                (c("2001:db8::/32"), 32),
            ],
            |a, _| *a,
        );
        assert_eq!(set.len(), 3);
        assert_eq!(set.find_map(ip("10.1.2.3"), |v| Some(*v)), Some(16));
        assert_eq!(set.find_map(ip("10.2.2.3"), |v| Some(*v)), Some(8));
        assert_eq!(set.find_map(ip("11.0.0.1"), |v| Some(*v)), None);
        assert_eq!(set.find_map(ip("2001:db8:1::1"), |v| Some(*v)), Some(32));
        assert!(set.contains_addr(ip("::ffff:10.9.9.9")));
    }

    #[test]
    fn test_prefix_set_visits_every_covering_prefix() {
        let set = PrefixSet::build(
            &[
                (c("10.0.0.0/8"), 8u8),
                (c("10.0.0.0/9"), 9),
                (c("10.0.0.0/10"), 10),
                (c("10.0.0.0/24"), 24),
            ],
            |a, _| *a,
        );
        let mut seen = Vec::new();
        let _ = set.find_map(ip("10.0.0.1"), |v| {
            seen.push(*v);
            None::<()>
        });
        assert_eq!(seen, [24, 10, 9, 8]);
        assert_eq!(
            set.find_map(ip("10.1.2.3"), |v| (*v == 8).then_some(*v)),
            Some(8)
        );
    }

    #[test]
    fn test_prefix_set_covers() {
        let set = PrefixSet::build(&[(c("10.0.0.0/8"), ())], |a, _| *a);
        assert!(set.covers(&c("10.20.0.0/16")));
        assert!(set.covers(&c("10.0.0.0/8")));
        assert!(!set.covers(&c("10.0.0.0/7")));
        assert!(!set.covers(&c("0.0.0.0/0")));
        assert!(!set.covers(&c("11.0.0.0/16")));
        let host = PrefixSet::build(&[(c("10.9.0.1/32"), ())], |a, _| *a);
        assert!(host.covers(&c("10.9.0.1/32")));
        assert!(!host.covers(&c("10.9.0.0/24")));
    }

    #[test]
    fn test_prefix_set_duplicates_merged() {
        let set = PrefixSet::build(&[(c("10.0.0.0/8"), 1u8), (c("10.0.0.0/8"), 5)], |a, b| {
            (*a).max(*b)
        });
        assert_eq!(set.len(), 1);
        assert_eq!(set.find_map(ip("10.0.0.1"), |v| Some(*v)), Some(5));
    }

    #[test]
    fn test_prefix_set_zero_length_matches_everything() {
        let set = PrefixSet::build(
            &[(c("0.0.0.0/0"), 1u8), (c("::/0"), 2), (c("10.0.0.0/8"), 3)],
            |a, _| *a,
        );
        assert_eq!(set.find_map(ip("8.8.8.8"), |v| Some(*v)), Some(1));
        assert_eq!(set.find_map(ip("10.0.0.1"), |v| Some(*v)), Some(3));
        assert_eq!(set.find_map(ip("2001:db8::1"), |v| Some(*v)), Some(2));
    }

    #[test]
    fn test_prefix_set_every_length_v4_and_v6() {
        for len in 0..=32u8 {
            let p = Cidr::new(ip("203.0.113.77"), len).unwrap();
            let set = PrefixSet::build(&[(p, ())], |a, _| *a);
            assert!(set.contains_addr(ip("203.0.113.77")), "/{len}");
            let outside = if len == 0 {
                None
            } else {
                Some(ip("203.0.113.77"))
            };
            if let Some(a) = outside {
                let flipped = IpAddr::from(
                    (u32::from_be_bytes([203, 0, 113, 77]) ^ (1 << (32 - u32::from(len))))
                        .to_be_bytes(),
                );
                assert!(
                    !set.contains_addr(flipped),
                    "/{len} must not cover {flipped} ({a})"
                );
            }
        }
        for len in 0..=128u8 {
            let base = ip("2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff");
            let set = PrefixSet::build(&[(Cidr::new(base, len).unwrap(), ())], |a, _| *a);
            assert!(set.contains_addr(base), "/{len}");
            if len > 0 {
                let bits = u128::from_be_bytes(match base {
                    IpAddr::V6(v) => v.octets(),
                    IpAddr::V4(_) => unreachable!(),
                }) ^ (1u128 << (128 - u32::from(len)));
                let flipped = IpAddr::V6(std::net::Ipv6Addr::from(bits));
                assert!(!set.contains_addr(flipped), "/{len}");
            }
        }
    }

    #[test]
    fn test_prefix_set_matches_linear_scan() {
        let mut x = 0x1234_5678_9abc_def0u64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut entries = Vec::new();
        for i in 0..2000u32 {
            let r = next();
            let cidr = if r % 2 == 0 {
                Cidr::new(
                    IpAddr::from(((r >> 8) as u32 & 0xff00_0000 | (r >> 40) as u32).to_be_bytes()),
                    (r % 33) as u8,
                )
                .unwrap()
            } else {
                Cidr::new(
                    IpAddr::V6(std::net::Ipv6Addr::from(
                        (u128::from(next()) << 64) | (0x2001u128 << 112),
                    )),
                    (r % 129) as u8,
                )
                .unwrap()
            };
            entries.push((cidr, i));
        }
        let set = PrefixSet::build(&entries, |a, b| (*a).min(*b));
        for _ in 0..5000 {
            let r = next();
            let addr = if r % 2 == 0 {
                IpAddr::from(
                    ((r >> 8) as u32 & 0xff00_0000 | (next() as u32 & 0x00ff_ffff)).to_be_bytes(),
                )
            } else {
                IpAddr::V6(std::net::Ipv6Addr::from(
                    (u128::from(next()) << 64) | (0x2001u128 << 112) | u128::from(next() & 0xff),
                ))
            };
            let expect = entries.iter().any(|(c, _)| c.contains(addr));
            assert_eq!(set.contains_addr(addr), expect, "{addr}");
        }
    }

    #[test]
    fn test_prefix_set_many_entries() {
        let entries: Vec<(Cidr, u32)> = (0..10_000u32)
            .map(|i| {
                (
                    Cidr::new(IpAddr::from((i << 8).to_be_bytes()), 24).unwrap(),
                    i,
                )
            })
            .collect();
        let set = PrefixSet::build(&entries, |a, _| *a);
        for i in (0..10_000u32).step_by(97) {
            let addr = IpAddr::from(((i << 8) | 7).to_be_bytes());
            assert_eq!(set.find_map(addr, |v| Some(*v)), Some(i));
        }
        assert!(PrefixSet::<()>::empty().is_empty());
        assert!(set.bytes() > 0);
    }
}
