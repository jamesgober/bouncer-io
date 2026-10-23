//! Sharing across nodes: node ids, deltas, and merge rules.

/// A node of a cluster, stamped on every record it exports. 0 is not a
/// valid node id.
///
/// # Examples
///
/// ```
/// use bouncer_io::{Bouncer, NodeId};
/// let bouncer = Bouncer::builder().node(NodeId(3)).try_build()?;
/// # let _ = bouncer;
/// assert!(Bouncer::builder().node(NodeId(0)).try_build().is_err());
/// # Ok::<(), bouncer_io::BouncerError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub u16);
