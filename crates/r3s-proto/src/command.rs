//! The command surface: the only way to mutate engine state.
//!
//! Every mutating operation the CLI, the control plane or the reconciler can
//! perform is one of these variants. That is deliberate: the audit log, the
//! intent WAL and the RBAC capability check all key off this enum, and a
//! mutation that bypasses it would bypass all three.

use std::time::Duration;

use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

use crate::id::ContainerId;
use crate::state::RestartPolicy;
use crate::types::{ContainerSpec, MountSpec, ResourceLimits, Signal};

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq,
)]
#[non_exhaustive]
pub enum Command {
    CreateContainer(Box<ContainerSpec>),
    StartContainer(ContainerId),
    /// `grace` is the SIGTERM→SIGKILL window.
    StopContainer {
        id: ContainerId,
        grace: Duration,
    },
    KillContainer {
        id: ContainerId,
        signal: Signal,
    },
    RemoveContainer {
        id: ContainerId,
        force: bool,
    },
    /// `live` uses `cgroup.frozen`; a real pause does not drop the cgroup.
    PauseContainer {
        id: ContainerId,
    },
    ResumeContainer(ContainerId),
    AttachVolume {
        container: ContainerId,
        mount: Box<MountSpec>,
    },
    DetachVolume {
        container: ContainerId,
        target: String,
    },
    /// Applied without a restart: a `cpu.max` write is instant, a `memory.max`
    /// write is not safe live and the engine rejects it with a typed error.
    UpdateLimits {
        id: ContainerId,
        limits: ResourceLimits,
    },
    SetRestartPolicy {
        id: ContainerId,
        policy: RestartPolicy,
    },
    RenameContainer {
        id: ContainerId,
        name: String,
    },
}

impl Command {
    /// Whether the command changes the world and therefore must be audit-logged
    /// and RBAC-checked as a mutating action.
    pub const fn is_mutating(&self) -> bool {
        true
    }

    /// The container a command targets, for RBAC and for the audit line.
    pub fn target(&self) -> Option<ContainerId> {
        match self {
            Command::CreateContainer(spec) => Some(spec.id),
            Command::StartContainer(id)
            | Command::StopContainer { id, .. }
            | Command::KillContainer { id, .. }
            | Command::RemoveContainer { id, .. }
            | Command::PauseContainer { id }
            | Command::ResumeContainer(id)
            | Command::UpdateLimits { id, .. }
            | Command::SetRestartPolicy { id, .. }
            | Command::RenameContainer { id, .. } => Some(*id),
            Command::AttachVolume { container, .. } | Command::DetachVolume { container, .. } => {
                Some(*container)
            }
        }
    }
}

/// What the engine did with a command. Carries the observed effect so the CLI
/// can report it without a second round trip.
#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq,
)]
#[non_exhaustive]
pub enum CommandAck {
    Accepted {
        id: ContainerId,
        phase: crate::state::Phase,
    },
    NoChange {
        reason: String,
    },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CommandError {
    #[error("illegal transition {from} -> {to}")]
    IllegalTransition {
        from: &'static str,
        to: &'static str,
    },
    #[error("not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("cannot apply a memory limit to a running container; restart required")]
    MemoryLimitRequiresRestart,
    #[error("{0}")]
    Rejected(String),
    #[error("not permitted for this role")]
    Denied,
}

/// Events published to SSH clients and (in Stage 4) to peers.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum EngineEvent {
    ContainerChanged(ContainerId),
    ImageProgress {
        image: String,
        received: u64,
        total: u64,
    },
    /// A container died; `reason` is the CLI-facing explanation.
    ContainerExited {
        id: ContainerId,
        reason: String,
    },
    NodeUnhealthy {
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::ImageRef;

    fn spec() -> ContainerSpec {
        ContainerSpec::new(
            ContainerId::from_bytes([7; 16]),
            "web",
            ImageRef::parse("alpine:3").expect("ok"),
        )
    }

    #[test]
    fn every_command_reports_its_target() {
        let id = ContainerId::from_bytes([7; 16]);
        let commands = [
            Command::CreateContainer(Box::new(spec())),
            Command::StartContainer(id),
            Command::StopContainer {
                id,
                grace: Duration::from_secs(10),
            },
            Command::KillContainer {
                id,
                signal: Signal::Kill,
            },
            Command::RemoveContainer { id, force: false },
            Command::PauseContainer { id },
            Command::ResumeContainer(id),
            Command::UpdateLimits {
                id,
                limits: ResourceLimits::default(),
            },
            Command::SetRestartPolicy {
                id,
                policy: RestartPolicy::Always,
            },
            Command::AttachVolume {
                container: id,
                mount: Box::new(MountSpec::bind("/a", "/b")),
            },
            Command::DetachVolume {
                container: id,
                target: "/b".into(),
            },
            Command::RenameContainer {
                id,
                name: "x".into(),
            },
        ];
        for cmd in commands {
            assert_eq!(cmd.target(), Some(id), "{cmd:?} lost its target");
            assert!(cmd.is_mutating());
        }
    }

    #[test]
    fn commands_survive_an_archive_roundtrip() {
        let cmd = Command::StopContainer {
            id: ContainerId::from_bytes([3; 16]),
            grace: Duration::from_secs(30),
        };
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&cmd).expect("archives");
        let back: Command =
            rkyv::from_bytes::<Command, rkyv::rancor::Error>(&bytes).expect("deserialises");
        assert_eq!(back, cmd);
    }
}
