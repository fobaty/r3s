//! Orphan sweeper: detect and clean up containers whose PID is gone but state
//! remains in the store.
//!
//! This runs on every reconcile tick. An "orphan" is a container in `Running`
//! or `Pending` phase whose PID no longer exists in `/proc`. The sweeper:
//!
//! 1. Checks each running/pending container's PID.
//! 2. If the PID is gone, marks the container as `Exited` and cleans up
//!    cgroups, mounts, and netns objects.
//! 3. Logs the cleanup for audit purposes.

use r3s_proto::{ContainerId, Phase, StoreError};
use r3s_store::Store;
use tracing::info;

/// Orphan sweeper. Scans the store for orphans and cleans them up.
pub struct OrphanSweeper {
    /// The state store backing this sweeper.
    store: Store,
}

impl OrphanSweeper {
    /// Create a new orphan sweeper backed by the given store.
    pub fn new(store: Store) -> Self {
        Self { store }
    }

    /// Scan for orphans and clean them up.
    pub fn sweep(&self) -> Result<usize, r3s_proto::StoreError> {
        let state = self.store.state()?;
        let mut cleaned = 0;

        for container in &state.containers {
            // Only check containers that should be running
            if container.phase != Phase::Running && container.phase != Phase::Pending {
                continue;
            }

            // TODO: check if PID exists in /proc
            // For now, this is a placeholder
            let pid = container.pid.unwrap_or(0);
            if pid == 0 {
                continue;
            }

            // If PID is gone, clean up
            // TODO: implement actual orphan detection and cleanup
            info!(container_id = %container.spec.id, pid, "orphan detected (placeholder)");
            cleaned += 1;
        }

        Ok(cleaned)
    }
}
