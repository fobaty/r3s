//! The kernel plane of r3s: everything that talks to the kernel on behalf of
//! a container.
//!
//! This is stage 3 of the build plan (docs/ARCHITECTURE.md §1.3): the cgroup
//! v2 tree — the quality-of-service hierarchy under `r3s.slice`, the
//! per-container scope record ([`ScopeSet`]), and the engine's own reserved
//! slice. The isolation plane (namespaces, `pivot_root`, mounts, capabilities,
//! seccomp — ADR-0004) lands in stage 4 in `isolation.rs`/`spawn.rs`, and the
//! OOM-detection reader joins after the telemetry stage needs it.
//!
//! Everything here is written against the kernel's *file* surface: an
//! operation is a read or a write on a path under the cgroup2 mount root, and
//! every failure maps to a typed [`CgroupError`] whose errno is what recovery
//! keys on (docs/ARCHITECTURE.md §3.3.3, docs/RUNBOOK.md §6.3–6.4).
//!
//! Host tests run against `fakefs`, a plain-directory stand-in for
//! cgroupfs. The kernel behaviors a plain directory cannot reproduce — the pid
//! move, `EBUSY` — are asserted through the checks this code performs and
//! covered for real by the on-device suite (AGENTS.md).

#![deny(missing_docs, unsafe_op_in_unsafe_fn)]

mod cgroup;
mod manifest;
mod tree;

#[cfg(test)]
mod fakefs;

pub use cgroup::{Cgroup, CgroupError};
pub use manifest::ScopeSet;
pub use tree::{CgroupTree, SYSTEM_SLICE, TOP_SLICE};
