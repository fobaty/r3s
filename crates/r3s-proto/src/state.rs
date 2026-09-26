//! Runtime state: what the engine *observes*, as opposed to what was declared.

use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

use crate::id::ContainerId;
use crate::types::ContainerSpec;

/// Lifecycle state machine. Legal transitions live in
/// [`Phase::can_transition_to`]; nothing else may change a phase.
#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    Serialize,
    Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
)]
#[non_exhaustive]
pub enum Phase {
    /// Accepted, nothing created yet.
    Pending,
    /// Kernel objects are being created.
    Creating,
    /// Payload is PID 1 of its namespace.
    Running,
    /// All processes are frozen (`cgroup.freeze`).
    Paused,
    /// SIGTERM sent, grace period running.
    Stopping,
    /// Reaped; `exit` is populated.
    Exited,
    /// Creation or apply failed terminally; `exit` is populated.
    Failed,
}

impl Phase {
    /// The transition table, in one place. Table-tested in `tests` below.
    pub const fn can_transition_to(self, next: Phase) -> bool {
        use Phase::{Creating, Exited, Failed, Paused, Pending, Running, Stopping};
        matches!(
            (self, next),
            (Pending, Creating)
                | (Pending, Failed)
                | (Creating, Running)
                | (Creating, Failed)
                | (Creating, Stopping)
                | (Running, Paused)
                | (Running, Stopping)
                | (Paused, Running)
                | (Paused, Stopping)
                | (Stopping, Exited)
                | (Stopping, Failed)
        )
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Phase::Exited | Phase::Failed)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Phase::Pending => "pending",
            Phase::Creating => "creating",
            Phase::Running => "running",
            Phase::Paused => "paused",
            Phase::Stopping => "stopping",
            Phase::Exited => "exited",
            Phase::Failed => "failed",
        }
    }

    /// A human status column, like `docker ps` STATUS.
    pub fn status_text(self, exit: Option<&ExitRecord>) -> String {
        match (self, exit) {
            (Phase::Running, None) => "up".to_owned(),
            (Phase::Paused, _) => "paused".to_owned(),
            (Phase::Pending, _) | (Phase::Creating, _) => "starting".to_owned(),
            (Phase::Stopping, _) => "stopping".to_owned(),
            (_, Some(e)) if e.oom_killed => format!("exited (oom) in {}s", e.uptime_secs),
            (_, Some(e)) => match e.code {
                0 => format!("exited (0) in {}s", e.uptime_secs),
                other => format!("exited ({other}) in {}s", e.uptime_secs),
            },
            (Phase::Failed, None) => "failed".to_owned(),
            _ => "unknown".to_owned(),
        }
    }
}

impl std::fmt::Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    Serialize,
    Deserialize,
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
)]
pub enum RestartPolicy {
    #[default]
    No,
    OnFailure,
    Always,
    UnlessStopped,
}

impl RestartPolicy {
    pub const fn wants_restart(self, exit: &ExitRecord) -> bool {
        match self {
            RestartPolicy::No => false,
            RestartPolicy::OnFailure => exit.code != 0 || exit.oom_killed,
            RestartPolicy::Always => true,
            RestartPolicy::UnlessStopped => !exit.user_requested,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            RestartPolicy::No => "no",
            RestartPolicy::OnFailure => "on-failure",
            RestartPolicy::Always => "always",
            RestartPolicy::UnlessStopped => "unless-stopped",
        }
    }
}

/// Why a container died. `oom_killed` is the field that answers the most
/// common support question about a container runtime, so it is resolved from
/// `memory.events` *before* the process is reaped and then frozen here.
#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    Serialize,
    Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Default,
)]
pub struct ExitRecord {
    /// Exit code, or 128+signal when the container was signalled.
    pub code: i32,
    /// Set from `memory.events:oom_kill` while the cgroup still existed.
    pub oom_killed: bool,
    /// The operator asked for it (`stop`, `rm`, `kill`).
    pub user_requested: bool,
    pub uptime_secs: u64,
    pub finished_at_unix: u64,
}

impl ExitRecord {
    pub fn code_for_signal(signal: i32) -> i32 {
        128 + signal
    }
}

/// A fixed-size, allocation-free health snapshot.
///
/// `Copy` and `#[repr(C)]` because this value is written into the mmap'd
/// telemetry ring and read by `r3s stats` without deserialising anything
/// (ADR-0003). Field order and width are part of the ring's on-disk format:
/// changing them requires a ring version bump, not a quiet edit.
#[repr(C)]
#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    Serialize,
    Deserialize,
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
)]
pub struct HealthReport {
    pub container: ContainerId,
    /// Monotonic nanoseconds since engine start.
    pub sampled_at_mono_ns: u64,
    /// `memory.current` for the container's cgroup.
    pub memory_current: u64,
    pub memory_max: u64,
    /// `memory.events:oom_kill`, cumulative.
    pub oom_kills: u64,
    /// `pids.current`.
    pub pids: u32,
    /// `cpu.stat` usage delta since the previous sample, in microseconds.
    pub cpu_usage_us: u64,
    pub io_read_bytes: u64,
    pub io_write_bytes: u64,
}

impl HealthReport {
    /// Memory pressure as a fraction of the limit, saturating at 1.0. Used by
    /// `stats` for the colour bar; never divides by zero because `memory_max`
    /// of 0 is normalised to 1 by the sampler.
    pub fn memory_fraction(&self) -> f32 {
        let max = self.memory_max.max(1);
        (self.memory_current as f32 / max as f32).clamp(0.0, 1.0)
    }
}

/// One telemetry ring record.
///
/// `#[repr(C)]` and a fixed 32-byte stride because the ring is raw bytes in an
/// mmap, not an archive: there is nothing to validate here beyond the cursor,
/// and a variable-size record would make slot addressing a division. The
/// 32-bit counters are deltas since the previous sample, saturated rather than
/// wrapped, so a graph stays flat instead of falling off a cliff (UNSAFE.md
/// J-10, J-11).
///
/// Field order and width are part of the ring's on-disk format: changing them
/// requires bumping `RING_VERSION` in `r3s-store`, not a quiet edit.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MetricSample {
    pub sampled_at_mono_ns: u64,
    /// `memory.current` in bytes; saturates at 4 GiB, which on this hardware is
    /// already a node-wide event rather than a per-container one.
    pub memory_current: u32,
    /// `cpu.stat` usage delta since the previous sample, microseconds.
    pub cpu_usage_us: u32,
    pub pids: u16,
    /// Deltas since the previous sample, saturated at 4 GiB.
    pub io_read_bytes: u32,
    pub io_write_bytes: u32,
}

/// Declared plus observed state for one container.
#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq,
)]
pub struct ContainerState {
    pub spec: ContainerSpec,
    pub phase: Phase,
    /// The ns-init PID, not the payload PID.
    pub pid: Option<u32>,
    pub exit: Option<ExitRecord>,
    pub restart_count: u32,
    pub health: HealthReport,
    /// Wall-clock nanoseconds of the last successful apply.
    pub applied_at_unix_ns: u64,
    /// Monotonic timestamp of the last failed apply; drives the retry backoff.
    pub retry_after_unix_secs: u64,
}

impl ContainerState {
    pub fn new(spec: ContainerSpec) -> Self {
        Self {
            health: HealthReport {
                container: spec.id,
                ..HealthReport::default()
            },
            spec,
            phase: Phase::Pending,
            pid: None,
            exit: None,
            restart_count: 0,
            applied_at_unix_ns: 0,
            retry_after_unix_secs: 0,
        }
    }
}

/// The whole declared state, archived as one unit. This is what the snapshot
/// file contains and what the CLI reads zero-copy.
#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    Serialize,
    Deserialize,
    Clone,
    Debug,
    Default,
    PartialEq,
)]
pub struct StateSnapshot {
    pub store_version: u32,
    /// Unix nanoseconds when this snapshot was written.
    pub written_at_unix_ns: u64,
    /// Sorted by id: the archive must be byte-deterministic for the migration
    /// fixtures and the snapshot CRC to mean anything.
    pub containers: Vec<ContainerState>,
    /// Allocated container addresses, so a restart reuses instead of drifting.
    pub allocated_addresses: Vec<u32>,
    pub next_address_hint: u32,
}

impl StateSnapshot {
    pub fn get(&self, id: &ContainerId) -> Option<&ContainerState> {
        self.containers.iter().find(|c| &c.spec.id == id)
    }

    pub fn insert(&mut self, state: ContainerState) {
        match self
            .containers
            .binary_search_by(|c| c.spec.id.cmp(&state.spec.id))
        {
            Ok(at) => self.containers[at] = state,
            Err(at) => self.containers.insert(at, state),
        }
    }

    pub fn remove(&mut self, id: &ContainerId) -> Option<ContainerState> {
        self.containers
            .binary_search_by(|c| c.spec.id.cmp(id))
            .ok()
            .map(|at| self.containers.remove(at))
    }

    /// Name-prefix candidates for the CLI's name resolution. The caller still
    /// has to apply `ContainerId::resolve_prefix`'s ambiguity rule, because
    /// this returns every hit rather than picking one.
    pub fn find_by_name(&self, prefix: &str) -> Vec<(ContainerId, &str)> {
        self.containers
            .iter()
            .filter(|c| c.spec.name.starts_with(prefix))
            .map(|c| (c.spec.id, c.spec.name.as_str()))
            .collect()
    }

    pub fn running(&self) -> impl Iterator<Item = &ContainerState> {
        self.containers.iter().filter(|c| c.phase == Phase::Running)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::ImageRef;

    fn state(name: &str) -> ContainerState {
        ContainerState::new(ContainerSpec::new(
            ContainerId::from_bytes([name.as_bytes()[0]; 16]),
            name,
            ImageRef::parse("alpine:3").expect("parses"),
        ))
    }

    #[test]
    fn transition_table_is_exhaustive_over_known_pairs() {
        use Phase::*;
        let all = [Pending, Creating, Running, Paused, Stopping, Exited, Failed];
        let allowed = [
            (Pending, Creating),
            (Pending, Failed),
            (Creating, Running),
            (Creating, Stopping),
            (Creating, Failed),
            (Running, Paused),
            (Running, Stopping),
            (Paused, Running),
            (Paused, Stopping),
            (Stopping, Exited),
            (Stopping, Failed),
        ];
        for from in all {
            for to in all {
                assert_eq!(
                    from.can_transition_to(to),
                    allowed.contains(&(from, to)),
                    "table disagrees for {from} -> {to}"
                );
            }
        }
    }

    #[test]
    fn terminal_states_have_no_exits() {
        assert!(Phase::Exited.is_terminal());
        assert!(Phase::Failed.is_terminal());
        assert!(!Phase::Stopping.is_terminal());
        for from in [Phase::Exited, Phase::Failed] {
            for to in [Phase::Pending, Phase::Running, Phase::Creating] {
                assert!(
                    !from.can_transition_to(to),
                    "{from} -> {to} must be illegal"
                );
            }
        }
    }

    #[test]
    fn snapshot_keeps_containers_sorted_by_id() {
        let mut snap = StateSnapshot::default();
        for name in ["z", "a", "m"] {
            snap.insert(state(name));
        }
        let ids: Vec<_> = snap.containers.iter().map(|c| c.spec.id).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
    }

    #[test]
    fn snapshot_archives_deterministically() {
        let mut a = StateSnapshot::default();
        let mut b = StateSnapshot::default();
        for name in ["b", "a"] {
            a.insert(state(name));
        }
        for name in ["a", "b"] {
            b.insert(state(name));
        }
        let a = rkyv::to_bytes::<rkyv::rancor::Error>(&a).expect("archives");
        let b = rkyv::to_bytes::<rkyv::rancor::Error>(&b).expect("archives");
        assert_eq!(
            a.as_slice(),
            b.as_slice(),
            "insertion order must not affect the archive"
        );
    }

    #[test]
    fn restart_policy_reads_the_exit_record() {
        let clean = ExitRecord {
            code: 0,
            ..ExitRecord::default()
        };
        let crash = ExitRecord {
            code: 1,
            ..ExitRecord::default()
        };
        let oom = ExitRecord {
            code: 0,
            oom_killed: true,
            ..ExitRecord::default()
        };
        let stopped = ExitRecord {
            code: 0,
            user_requested: true,
            ..ExitRecord::default()
        };

        assert!(!RestartPolicy::No.wants_restart(&crash));
        assert!(RestartPolicy::OnFailure.wants_restart(&crash));
        assert!(!RestartPolicy::OnFailure.wants_restart(&clean));
        assert!(RestartPolicy::OnFailure.wants_restart(&oom));
        assert!(RestartPolicy::Always.wants_restart(&clean));
        assert!(RestartPolicy::UnlessStopped.wants_restart(&clean));
        assert!(!RestartPolicy::UnlessStopped.wants_restart(&stopped));
    }

    #[test]
    fn health_report_saturates_instead_of_dividing_by_zero() {
        let h = HealthReport {
            memory_current: 10,
            memory_max: 0,
            ..HealthReport::default()
        };
        assert_eq!(h.memory_fraction(), 1.0);
    }
}
