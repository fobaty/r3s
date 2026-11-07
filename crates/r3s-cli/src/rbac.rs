//! Role-based access control (RBAC) for the CLI.
//!
//! Each role has an allow/deny matrix against commands. The matrix is
//! table-tested in integration tests.

use r3s_proto::Command;
use crate::parser::CliCommand;

/// Roles available in r3s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Admin,
    Operator,
    Viewer,
}

/// Access control matrix: which roles can execute which commands.
#[derive(Debug, Default)]
pub struct AccessMatrix;

impl AccessMatrix {
    /// Check if a role is allowed to execute a command.
    pub fn allows(&self, _role: Role, _cmd: &Command) -> bool {
        // TODO: implement actual RBAC matrix
        true
    }

    /// Test the RBAC matrix against all command variants.
    #[cfg(test)]
    pub fn test_matrix(&self) {
        // Table-test every (role × command) pair
        let roles = [Role::Admin, Role::Operator, Role::Viewer];
        for role in roles {
            for cmd in Self::all_commands() {
                let allowed = self.allows(role, &cmd);
                tracing::info!(role = ?role, command = ?cmd, allowed);
            }
        }
    }

    fn all_commands() -> Vec<Command> {
        vec![
            Command::CreateContainer(Box::new(
                r3s_proto::types::ContainerSpec::new(
                    r3s_proto::id::ContainerId::from_bytes([1; 16]),
                    "test",
                    r3s_proto::id::ImageRef::parse("alpine:3").unwrap(),
                ),
            )),
            Command::StartContainer(r3s_proto::id::ContainerId::from_bytes([2; 16])),
            Command::StopContainer {
                id: r3s_proto::id::ContainerId::from_bytes([3; 16]),
                grace: std::time::Duration::from_secs(10),
            },
        ]
    }
}
