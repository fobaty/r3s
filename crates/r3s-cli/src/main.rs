//! The r3s CLI binary entry point.

#![deny(missing_docs, unsafe_op_in_unsafe_fn)]

use anyhow::{Context, Result};
use r3s_cli::{CliParser, Router, ExitCode};
use r3s_store::Store;
use tracing::{info, level_filters::LevelFilter};
use tracing_subscriber::fmt::Subscriber;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    let subscriber = Subscriber::builder()
        .with_max_level(LevelFilter::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Parse CLI input
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: r3s <command> [arguments]");
        return Err(anyhow::anyhow!("missing command"));
    }

    let input = args[1..].join(" ");
    let cmd = CliParser::parse(&input)
        .context("failed to parse CLI command")?;

    info!(command = ?cmd, "CLI command parsed");

    // Open store (for commands that need it)
    let store = Store::open(std::path::Path::new("/var/lib/r3s/state"))
        .context("failed to open state store")?;

    // Route command to engine
    let router = Router::new(store);
    router.route(cmd).await?;

    info!("command executed successfully");
    Ok(())
}
