//! The scope record: the declared runtime footprint of one container.
//!
//! This is the cgroup-plane half of the `ScopeSet` described in
//! docs/ARCHITECTURE.md §3.3.1: the record of the objects the engine creates
//! for a container, written *before* each object exists, and the single input
//! to teardown (invariant I5 — teardown is derived from the record, never
//! from a guess). The isolation-plane members of the record — veth names, the
//! netns path, the mount points — join it in stage 4.
//!
//! Invariant I4 (crash convergence) reads the declared record back on restart
//! and re-derives the desired tree from it: a scope cgroup without a record
//! is an orphan to sweep, and a record without its cgroup is a repair to run.

use r3s_proto::ContainerId;

/// The declared runtime footprint of one container.
///
/// Both paths are relative — `cgroup` to the cgroup2 mount root, `bundle` to
/// the state base — so a relocated root relocates the whole footprint with it,
/// and neither path can escape its own root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeSet {
    /// The container this footprint belongs to.
    pub id: ContainerId,
    /// The QoS slice the scope sits in: a slice *name*, not a path.
    pub slice: String,
    /// The scope cgroup, relative to the cgroup2 mount root.
    pub cgroup: String,
    /// The bundle directory, relative to the state base.
    pub bundle: String,
}

impl ScopeSet {
    /// Names the footprint. The record is declared, not discovered: it is
    /// what the engine is *about to* create, and it is what
    /// [`crate::CgroupTree::remove_scope`] consumes.
    pub fn new(
        id: ContainerId,
        slice: impl Into<String>,
        cgroup: impl Into<String>,
        bundle: impl Into<String>,
    ) -> Self {
        Self {
            id,
            slice: slice.into(),
            cgroup: cgroup.into(),
            bundle: bundle.into(),
        }
    }
}
