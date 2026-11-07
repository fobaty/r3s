//! Command router: dispatches parsed CLI commands to the engine.

use r3s_proto::{Command, StoreError};
use r3s_store::{Store, WalEntry};
use tracing::info;

/// Router that translates `CliCommand` into `r3s-proto::Command` and
/// sends it to the engine via the store's WAL.
pub struct Router {
    store: Store,
}

impl Router {
    /// Create a new router backed by the given store.
    pub fn new(store: Store) -> Self {
        Self { store }
    }

    /// Route a CLI command to the engine by appending an Intent to the WAL.
    pub async fn route(&self, cmd: crate::parser::CliCommand) -> Result<(), StoreError> {
        let proto_cmd = match cmd {
            crate::parser::CliCommand::ContainerCreate { spec } => {
                // TODO: parse spec string into ContainerSpec
                return Err(StoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "container create not yet implemented",
                )));
            }
            crate::parser::CliCommand::ContainerStart { id } => {
                let mut bytes = [0u8; 16];
                bytes[..id.len().min(16)].copy_from_slice(id.as_bytes());
                Command::StartContainer(r3s_proto::id::ContainerId::from_bytes(bytes))
            }
            crate::parser::CliCommand::ContainerStop { id } => {
                let mut bytes = [0u8; 16];
                bytes[..id.len().min(16)].copy_from_slice(id.as_bytes());
                Command::StopContainer {
                    id: r3s_proto::id::ContainerId::from_bytes(bytes),
                    grace: std::time::Duration::from_secs(10),
                }
            }
            crate::parser::CliCommand::ContainerRemove { id, force } => {
                let mut bytes = [0u8; 16];
                bytes[..id.len().min(16)].copy_from_slice(id.as_bytes());
                Command::RemoveContainer {
                    id: r3s_proto::id::ContainerId::from_bytes(bytes),
                    force,
                }
            }
            crate::parser::CliCommand::ImagePull { ref_ } => {
                return Err(StoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "image pull not yet implemented",
                )));
            }
            crate::parser::CliCommand::Ps | crate::parser::CliCommand::Stats | crate::parser::CliCommand::Version => {
                // These are read-only commands, handled separately
                return Ok(());
            }
        };

        info!(command = ?proto_cmd, "routing command to engine");

        // Append an Intent to the WAL
        let entry = WalEntry::Intent {
            command: Box::new(proto_cmd),
            actor: "cli".to_string(),
        };

        self.store.append(&entry)?;
        self.store.commit()?;

        Ok(())
    }
}
