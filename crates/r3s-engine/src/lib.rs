//! The reconciler: single-writer loop that drives observed state toward
//! declared state.
//!
//! This is Stage 1, Week 5 (docs/ARCHITECTURE.md §5.1). The engine holds no
//! policy of its own; it observes the state store and the kernel, then applies
//! commands from the command surface (`r3s-proto::Command`). Every mutation
//! goes through the WAL — there is no direct write path.
//!
//! Core responsibilities:
//!
//! * **Reconcile loop**: every tick (configurable, default 1 s) sample
//!   cgroup events, `/proc/<pid>/stat`, and netlink, then drive observed state
//!   toward declared state. A `kill -9 r3sd` followed by restart must converge
//!   to the declared state without manual cleanup (P5).
//! * **Lifecycle state machine**: each container has a phase (`Phase`) and
//!   transitions are governed by a legality table. Transitions live in exactly
//!   one function and are table-tested.
//! * **Restart policy**: `OnFailure`, `Always`, `Never` with backoff and
//!     crash-loop detection.
//! * **Orphan sweep**: detect containers whose PID is gone but state remains,
//!     clean up cgroups, mounts, netns objects.
//! * **Signal handling**: graceful shutdown on `SIGTERM`, reload on `SIGHUP`.
//!
//! The engine is a library crate. The binary entry point (`r3s-bin`) wires it
//! to the SSH plane and the CLI.

#![deny(missing_docs, unsafe_op_in_unsafe_fn)]

pub mod reconciler;
pub mod lifecycle;
pub mod signal;
pub mod sweep;

pub use reconciler::Reconciler;
pub use lifecycle::TransitionError;
// Phase is re-exported from r3s-proto for convenience
pub use r3s_proto::state::Phase;
pub use signal::SignalHandler;
pub use sweep::OrphanSweeper;
