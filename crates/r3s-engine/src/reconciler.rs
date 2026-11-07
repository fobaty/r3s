//! The reconciler loop: observe → compare → apply.
//!
//! Every tick (default 1 s) the reconciler:
//!
//! 1. Reads the current state from the store (`Store::state()`).
//! 2. Samples kernel state (cgroup events, `/proc/<pid>/stat`).
//! 3. Compares observed vs declared state.
//! 4. Applies missing mutations via the command surface.
//!
//! The reconciler is the *only* writer to the state store. All mutations go
//! through `Store::append`/`commit`, which means every change is WAL-logged
//! and crash-recoverable.

use std::time::Duration;

use r3s_proto::{Command, Phase, StoreError};
use r3s_store::Store;
use tracing::{info, warn};

/// Reconciler tick interval. Configurable via CLI/env in Stage 2.
const DEFAULT_TICK_INTERVAL: Duration = Duration::from_secs(1);

/// The reconciler loop. Driven by a tokio interval timer.
pub struct Reconciler {
    /// The state store backing this reconciler.
    store: Store,
    /// How often to tick the reconcile loop.
    tick_interval: Duration,
}

impl Reconciler {
    /// Create a new reconciler backed by the given store.
    pub fn new(store: Store) -> Self {
        Self {
            store,
            tick_interval: DEFAULT_TICK_INTERVAL,
        }
    }

    /// Set a custom tick interval.
    pub fn with_tick_interval(mut self, interval: Duration) -> Self {
        self.tick_interval = interval;
        self
    }

    /// Run the reconciler loop. This is an infinite loop that exits only on
    /// signal (handled by `SignalHandler`) or fatal error.
    pub async fn run(&mut self) -> Result<(), StoreError> {
        info!(
            tick_interval = ?self.tick_interval,
            "reconciler starting"
        );

        // TODO: integrate with SignalHandler for graceful shutdown
        // For now, this is a placeholder loop.

        Ok(())
    }

    /// Single reconcile iteration: observe → compare → apply.
    ///
    /// TODO: implement observation logic (cgroup events, pid status)
    /// TODO: implement application logic
    fn reconcile_once(&self) -> Result<(), StoreError> {
        // 1. Observe: read current state from store
        let state = self.store.state()?;

        // 2. Compare: for each container, check if observed state matches declared
        // TODO: implement observation logic (cgroup events, pid status)

        // 3. Apply: for any discrepancies, issue Commands
        // TODO: implement application logic

        info!(
            containers = state.containers.len(),
            "reconcile tick complete"
        );

        Ok(())
    }
}
