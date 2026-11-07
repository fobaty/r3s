//! The r3s daemon entry point.
//!
//! This binary wires together:
//! - `r3s-store::Store` — the transactional state store
//! - `r3s-engine::Reconciler` — the single-writer reconcile loop
//! - `r3s-engine::SignalHandler` — graceful shutdown on SIGTERM
//! - (Stage 2+) `r3s-sshd` — embedded SSH management plane
//!
//! The daemon starts, opens the store, initializes the reconciler, and runs
//! the reconcile loop until signaled.

#![deny(missing_docs, unsafe_op_in_unsafe_fn)]

use anyhow::{Context, Result};
use r3s_engine::{Reconciler, SignalHandler};
use r3s_store::Store;
use tracing::{info, level_filters::LevelFilter};
use tracing_subscriber::fmt::Subscriber;

fn main() -> Result<()> {
    // Initialize logging
    let subscriber = Subscriber::builder()
        .with_max_level(LevelFilter::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("r3s daemon starting");

    // Open the state store (default path: /var/lib/r3s/state)
    use std::path::Path;
    let store = Store::open(Path::new("/var/lib/r3s/state"))
        .context("failed to open state store")?;

    info!(root = %store.layout().root().display(), "store opened");

    // Create reconciler
    let mut reconciler = Reconciler::new(store);

    // Start signal handler for graceful shutdown
    let (signal_handler, shutdown_rx) = SignalHandler::new();

    // Run reconcile loop with shutdown support
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            // TODO: integrate shutdown_rx into reconciler run loop
            // For now, this is a placeholder
            info!("reconciler running (placeholder)");

            // In a real implementation, we would await shutdown_rx here
            // and break the reconcile loop when signaled
        });

    info!("r3s daemon stopped");
    Ok(())
}
