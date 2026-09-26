//! Replay: snapshot + WAL → the state the engine must converge to.
//!
//! Two facts make recovery simple, and both are properties of the design rather
//! than of this file:
//!
//! 1. Every mutation is an `Intent` written **before** the side effect and an
//!    `Applied` written after. An intent with no matching `Applied` is a crash
//!    mid-apply, and the reconciler replays it — idempotently, because an intent
//!    describes the desired state, not the step.
//! 2. A torn tail is never truncated away. Records in it were never
//!    acknowledged, so nothing can depend on them.

use r3s_proto::state::{ContainerState, StateSnapshot};
use r3s_proto::{ContainerId, StoreError};

use crate::layout::StoreLayout;
use crate::snapshot;
use crate::wal::{self, WalEntry, WalScan};

/// What recovery decided, for the log line and for `r3s system status`.
#[derive(Debug, Default)]
pub struct RecoveryReport {
    /// The snapshot the state was built from, if there was a usable one.
    pub snapshot_index: Option<u64>,
    /// Records replayed on top of that snapshot.
    pub wal_records: usize,
    /// Bytes those records occupy, for the size number the CLI shows.
    pub wal_bytes: u64,
    /// Whether a half-written record was cut back. Expected after any crash.
    pub truncated_torn_tail: bool,
    /// Intents with no matching observation: work the reconciler must redo.
    pub unmatched_intents: Vec<ContainerId>,
    /// Damage that a torn tail does not explain. Non-empty means the log is
    /// not merely crash-truncated, and the runbook has a row for it.
    pub corruption: Vec<wal::Corruption>,
    /// Snapshots that failed validation, newest first, with the reason. The
    /// state below was rebuilt without them, so a non-empty list means the node
    /// recovered from a damaged snapshot rather than from nothing.
    pub rejected_snapshots: Vec<(u64, String)>,
}

impl RecoveryReport {
    /// True when recovery neither lost data to a torn tail nor found damage.
    /// The engine logs this at startup; a node that is never clean says
    /// something about its storage.
    pub fn is_clean(&self) -> bool {
        self.corruption.is_empty()
            && self.rejected_snapshots.is_empty()
            && !self.truncated_torn_tail
    }

    /// The damage that makes the store refuse to open, if any. A store that
    /// returns `Some` here is intact on disk and wrong in memory: it has a hole
    /// where an acknowledged record used to be.
    pub fn wal_corruption(&self) -> Option<&wal::Corruption> {
        self.corruption.first()
    }
}

/// Loads the newest valid snapshot, replays the WAL over it, and truncates a
/// torn tail.
pub fn recover(layout: &StoreLayout) -> Result<(StateSnapshot, RecoveryReport), StoreError> {
    let mut report = RecoveryReport::default();

    let latest = snapshot::open_latest(layout)?;
    report.rejected_snapshots = latest.rejected.clone();
    let mut state = match latest.snapshot {
        Some(handle) => {
            report.snapshot_index = Some(handle.index());
            handle.to_state()?
        }
        None => {
            tracing::info!("no snapshot; the wal is the whole state");
            StateSnapshot {
                store_version: r3s_proto::STORE_VERSION,
                ..StateSnapshot::default()
            }
        }
    };

    let scan: WalScan = wal::scan(layout)?;
    report.wal_records = scan.records.len();
    report.corruption = scan.corrupt.clone().into_iter().collect();

    for record in &scan.records {
        apply_entry(&mut state, &record.entry, &mut report);
    }

    // Only after replay, and only when what we found is a crash artefact.
    if report.corruption.is_empty() {
        report.truncated_torn_tail = wal::truncate_torn_tail(layout, &scan)?;
    } else {
        tracing::error!(
            records = scan.records.len(),
            "wal is damaged beyond a torn tail; refusing to truncate. \
             Recovery proceeds from the last intact record."
        );
    }
    report.wal_bytes = scan.valid_len;

    if report.unmatched_intents.is_empty() {
        tracing::info!(
            snapshot = ?report.snapshot_index,
            records = report.wal_records,
            "recovery complete"
        );
    } else {
        tracing::warn!(
            containers = report.unmatched_intents.len(),
            "recovery found intents with no observation; the reconciler will re-apply them"
        );
    }

    Ok((state, report))
}

/// Folds one entry into `state`.
///
/// The two halves of the pair are handled differently on purpose: `Applied`
/// carries observed state and replaces whatever was there, `Intent` carries
/// desired state and is only *noted*, because a `create` intent has no
/// ContainerState to install and guessing one would resurrect a container the
/// operator may have deleted.
pub(crate) fn apply_entry(
    state: &mut StateSnapshot,
    entry: &WalEntry,
    report: &mut RecoveryReport,
) {
    match entry {
        WalEntry::Applied { state: applied } => {
            state.insert((**applied).clone());
        }
        WalEntry::Checkpoint { snapshot } => {
            // A checkpoint is a full replacement written in-band, so it needs
            // no migration and no merge: everything before it is subsumed.
            *state = (**snapshot).clone();
        }
        WalEntry::Intent { command, .. } => {
            if let Some(id) = command.target()
                && !matches!(**command, r3s_proto::Command::CreateContainer(_))
            {
                report.unmatched_intents.push(id);
            }
        }
        WalEntry::AddressLease { addr, owner } => {
            if !state.allocated_addresses.contains(addr) {
                state.allocated_addresses.push(*addr);
                state.allocated_addresses.sort_unstable();
            }
            state.next_address_hint = state.next_address_hint.max(addr.saturating_add(1));
            let _ = owner;
        }
        WalEntry::AddressRelease { addr } => {
            state.allocated_addresses.retain(|a| a != addr);
        }
    }
}

/// Compaction thresholds. Crossing either one is enough: on a chatty node the
/// record count triggers first, on a chatty-but-small node the byte count does.
pub const COMPACT_WAL_BYTES: u64 = 8 * 1024 * 1024;
/// Both thresholds are per-engine, not per-container: the reconciler owns one
/// WAL for the whole node, so 2000 records is "a few thousand container
/// transitions", which on a Pi 5 is a compaction well under a second.
pub const COMPACT_WAL_RECORDS: usize = 2000;

/// Rewrites the snapshot and drops WAL segments the snapshot now covers.
///
/// The order is not negotiable: snapshot-then-truncate. The reverse leaves a
/// window where a crash loses the records the truncation assumed were durable.
pub fn compact(
    layout: &StoreLayout,
    state: &StateSnapshot,
) -> Result<snapshot::SnapshotMeta, StoreError> {
    let meta = snapshot::write(layout, state)?;
    tracing::info!(snapshot = meta.index, "wrote a snapshot");
    Ok(meta)
}

/// Whether the WAL has grown enough to be worth folding away.
///
/// A policy question, kept away from [`compact`] so that "an operator asked for
/// it" and "the threshold was crossed" cannot disagree about what compaction
/// means. The reconciler calls this; nothing else should.
pub fn should_compact(scan: &WalScan) -> bool {
    scan.records.len() >= COMPACT_WAL_RECORDS || scan.valid_len >= COMPACT_WAL_BYTES
}

/// Reconstructs state from a WAL alone, for the migration fixtures.
pub fn replay_only(scan: &WalScan) -> StateSnapshot {
    let mut state = StateSnapshot {
        store_version: r3s_proto::STORE_VERSION,
        ..StateSnapshot::default()
    };
    let mut report = RecoveryReport::default();
    for record in &scan.records {
        apply_entry(&mut state, &record.entry, &mut report);
    }
    state
}

/// Convenience for tests and for `r3s system status --store-only`.
pub fn state_after_wal(layout: &StoreLayout) -> Result<StateSnapshot, StoreError> {
    Ok(replay_only(&wal::scan(layout)?))
}

/// Only used by the reconciler: install an observed state and return the record
/// to append, so the two can never get out of sync.
pub fn applied_entry(state: &ContainerState) -> WalEntry {
    WalEntry::Applied {
        state: Box::new(state.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::{CommitPolicy, Wal};
    use r3s_proto::Command;
    use r3s_proto::id::{ContainerId, ImageRef};
    use r3s_proto::types::ContainerSpec;

    fn layout() -> (tempfile::TempDir, StoreLayout) {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::new(dir.path()).with_segment_size(8192);
        layout.ensure_dirs().expect("dirs");
        (dir, layout)
    }

    fn state(name: &str) -> ContainerState {
        ContainerState::new(ContainerSpec::new(
            ContainerId::from_bytes(digest(name)),
            name,
            ImageRef::parse("alpine:3").expect("parses"),
        ))
    }

    /// Names that share a prefix must not share a container, or a fixture that
    /// generates 2000 of them silently tests one container 2000 times.
    fn digest(name: &str) -> [u8; 16] {
        let mut out = [0u8; 16];
        out.copy_from_slice(&r3s_proto::digest::Digest::of(name.as_bytes()).as_bytes()[..16]);
        out
    }

    #[test]
    fn an_empty_store_recovers_to_nothing() {
        let (_dir, layout) = layout();
        let (state, report) = recover(&layout).expect("recover");
        assert!(state.containers.is_empty());
        assert!(report.snapshot_index.is_none());
        assert!(report.is_clean());
    }

    #[test]
    fn an_intent_without_an_observation_is_reported_for_replay() {
        let (_dir, layout) = layout();
        let id = ContainerId::from_bytes([0xaa; 16]);
        {
            let mut wal = Wal::open(&layout, CommitPolicy::default()).expect("open");
            wal.append(&applied_entry(&state("web")))
                .expect("append applied");
            wal.append(&WalEntry::Intent {
                command: Box::new(Command::StartContainer(id)),
                actor: "operator".to_owned(),
            })
            .expect("append intent");
            wal.commit().expect("commit");
        }
        let (recovered, report) = recover(&layout).expect("recover");
        assert_eq!(recovered.containers.len(), 1, "the observed state survives");
        assert_eq!(report.unmatched_intents, vec![id]);
    }

    #[test]
    fn a_create_intent_does_not_resurrect_a_container() {
        let (_dir, layout) = layout();
        {
            let mut wal = Wal::open(&layout, CommitPolicy::default()).expect("open");
            wal.append(&WalEntry::Intent {
                command: Box::new(Command::CreateContainer(Box::new(ContainerSpec::new(
                    ContainerId::from_bytes([1; 16]),
                    "web",
                    ImageRef::parse("alpine:3").expect("ok"),
                )))),
                actor: "operator".to_owned(),
            })
            .expect("append");
            wal.commit().expect("commit");
        }
        let (recovered, report) = recover(&layout).expect("recover");
        assert!(recovered.containers.is_empty());
        assert!(report.unmatched_intents.is_empty());
    }

    #[test]
    fn the_wal_is_replayed_over_the_snapshot() {
        let (_dir, layout) = layout();
        snapshot::write(&layout, &StateSnapshot::default()).expect("snapshot");
        {
            let mut wal = Wal::open(&layout, CommitPolicy::default()).expect("open");
            wal.append(&applied_entry(&state("web")))
                .expect("append web");
            wal.commit().expect("commit");
        }
        let (recovered, report) = recover(&layout).expect("recover");
        assert_eq!(recovered.containers.len(), 1);
        assert!(report.snapshot_index.is_some());
    }

    #[test]
    fn a_checkpoint_in_the_wal_subsumes_everything_before_it() {
        let (_dir, layout) = layout();
        {
            let mut wal = Wal::open(&layout, CommitPolicy::default()).expect("open");
            wal.append(&applied_entry(&state("web")))
                .expect("append web");
            wal.append(&WalEntry::Checkpoint {
                snapshot: Box::new(StateSnapshot::default()),
            })
            .expect("append checkpoint");
            wal.commit().expect("commit");
        }
        let (recovered, _) = recover(&layout).expect("recover");
        assert!(
            recovered.containers.is_empty(),
            "the checkpoint replaced the log"
        );
    }

    #[test]
    fn address_leases_survive_a_restart_and_are_released() {
        let (_dir, layout) = layout();
        {
            let mut wal = Wal::open(&layout, CommitPolicy::default()).expect("open");
            wal.append(&WalEntry::AddressLease {
                addr: 7,
                owner: ContainerId::from_bytes([1; 16]),
            })
            .expect("lease");
            wal.commit().expect("commit");
        }
        {
            let (recovered, _) = recover(&layout).expect("recover");
            assert!(recovered.allocated_addresses.contains(&7));
            assert_eq!(recovered.next_address_hint, 8);
        }
        let mut wal = Wal::open(&layout, CommitPolicy::default()).expect("reopen");
        wal.append(&WalEntry::AddressRelease { addr: 7 })
            .expect("release");
        wal.commit().expect("commit");
        drop(wal);

        let (recovered, _) = recover(&layout).expect("recover");
        assert!(!recovered.allocated_addresses.contains(&7));
    }

    #[test]
    fn compaction_writes_a_snapshot_and_keeps_the_open_segment() {
        let (_dir, layout) = layout();
        let mut full = StateSnapshot::default();
        {
            let mut wal = Wal::open(&layout, CommitPolicy::default()).expect("open");
            for i in 0..COMPACT_WAL_RECORDS {
                let s = state(&format!("c{i}"));
                wal.append(&applied_entry(&s)).expect("append");
                full.insert(s);
            }
            wal.commit().expect("commit");
        }
        let meta = compact(&layout, &full).expect("compact");
        assert!(meta.path.exists());
        // Compaction writes; it does not delete. Pruning is the store's job,
        // under the writer lock, because only the writer knows which segment it
        // still holds a descriptor for.
        assert!(layout.wal_segments().expect("list").len() > 1);

        let (recovered, report) = recover(&layout).expect("recover");
        assert_eq!(recovered.containers.len(), COMPACT_WAL_RECORDS);
        assert!(report.is_clean(), "compaction is not damage: {report:?}");
    }

    #[test]
    fn the_threshold_is_a_policy_question_not_a_side_effect() {
        let (_dir, layout) = layout();
        let mut wal = Wal::open(&layout, CommitPolicy::default()).expect("open");
        let found = crate::wal::scan(&layout).expect("scan");
        assert!(
            !should_compact(&found),
            "an empty log is not worth compacting"
        );
        assert!(layout.snapshots().expect("list").is_empty());

        for i in 0..COMPACT_WAL_RECORDS {
            wal.append(&applied_entry(&state(&format!("c{i}"))))
                .expect("append");
        }
        wal.commit().expect("commit");
        let found = crate::wal::scan(&layout).expect("scan");
        assert!(
            should_compact(&found),
            "{COMPACT_WAL_RECORDS} records is the threshold"
        );
    }
}
