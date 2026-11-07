//! Signal handling for graceful shutdown and reload.
//!
//! - `SIGTERM`: graceful shutdown — stop accepting new commands, drain running
//!   containers, exit cleanly.
//! - `SIGHUP`: reload configuration (Stage 2+).
//!
//! The signal handler uses `tokio::signal` and communicates shutdown requests
//! via a mpsc channel to the reconciler loop.

use tokio::sync::mpsc;
use tokio::signal;
use tracing::info;

/// Signal handler. Drives graceful shutdown on SIGTERM.
pub struct SignalHandler {
    /// Channel sender — used internally, never exposed.
    _shutdown_tx: mpsc::Sender<()>,
}

impl SignalHandler {
    /// Create a new signal handler and start listening for signals.
    /// Returns a `SignalHandler` and a receiver that awaits the shutdown signal.
    pub fn new() -> (Self, mpsc::Receiver<()>) {
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        // Clone the sender for the signal listener
        let shutdown_tx_clone = shutdown_tx.clone();

        // Start signal listener in background
        tokio::spawn(async move {
            let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("failed to create SIGTERM handler");
            let mut sighup = signal::unix::signal(signal::unix::SignalKind::hangup())
                .expect("failed to create SIGHUP handler");

            tokio::select! {
                _ = sigterm.recv() => {
                    info!("SIGTERM received, initiating graceful shutdown");
                    let _ = shutdown_tx_clone.send(()).await;
                }
                _ = sighup.recv() => {
                    info!("SIGHUP received, configuration reload not yet implemented");
                }
            }
        });

        (Self { _shutdown_tx: shutdown_tx }, shutdown_rx)
    }
}
