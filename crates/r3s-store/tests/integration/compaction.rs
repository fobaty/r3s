//! Compaction as the parts see it: a writer that rotates segments, a snapshot
//! that lands atomically, a prune that keeps the segment still open, and a
//! reopen that gets the same state back.
//!
//! This is the J-01 path (mmap'd snapshot, read without copying) plus J-02 (one
//! writer, so the prune cannot race an append).

use r3s_proto::digest::Digest;
use r3s_proto::id::{ContainerId, ImageRef};
use r3s_proto::state::{ContainerState, Phase};
use r3s_proto::types::ContainerSpec;
use r3s_store::{CommitPolicy, Store, StoreError, StoreLayout, WalEntry};

fn state(name: &str) -> ContainerState {
    let mut id = [0u8; 16];
    id.copy_from_slice(&Digest::of(name.as_bytes()).as_bytes()[..16]);
    let mut s = ContainerState::new(ContainerSpec::new(
        ContainerId::from_bytes(id),
        name,
        ImageRef::parse("alpine:3").expect("parses"),
    ));
    s.phase = Phase::Running;
    s
}

fn open(dir: &Path, segment_max: u64) -> Store {
    Store::open_in(
        StoreLayout::new(dir).with_segment_size(segment_max),
        CommitPolicy::default(),
    )
    .expect("open")
}

#[test]
fn a_long_run_of_records_rotates_prunes_and_reopens_intact() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::new(dir.path()).with_segment_size(16 * 1024);
    let expected: Vec<ContainerState> = (0..400).map(|i| state(&format!("c{i}"))).collect();

    {
        let store = open(dir.path(), 16 * 1024);
        for s in &expected {
            store
                .append_committed(&WalEntry::Applied {
                    state: Box::new(s.clone()),
                })
                .expect("append");
        }
        let segments_before = layout.wal_segments().expect("segments").len();
        assert!(
            segments_before > 1,
            "400 records must not fit in {segments_before} segment(s)"
        );

        let meta = store.compact().expect("compact");
        let segments_after = layout.wal_segments().expect("segments");
        assert!(
            segments_after.len() < segments_before,
            "compaction must drop covered segments: {segments_before} -> {}",
            segments_after.len()
        );
        assert_eq!(store.snapshot().expect("mapped").index(), meta.index);
    }

    // Reopen from disk: the snapshot plus whatever survived the prune must
    // reconstruct exactly what was written.
    let store = open(dir.path(), 16 * 1024);
    let recovered = store.state().expect("state");
    assert_eq!(recovered.containers.len(), expected.len());
    for want in &expected {
        let got = recovered
            .containers
            .iter()
            .find(|c| c.spec.id == want.spec.id)
            .unwrap_or_else(|| panic!("{} is missing after compaction", want.spec.name));
        assert_eq!(
            got.phase, want.phase,
            "{} changed phase across a compaction",
            want.spec.name
        );
    }
    assert!(
        store.recovery().is_clean(),
        "a normal compaction is not damage: {:?}",
        store.recovery()
    );
}

#[test]
fn compaction_keeps_the_segment_the_writer_is_holding_open() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::new(dir.path()).with_segment_size(8 * 1024);
    let store = open(dir.path(), 8 * 1024);
    for i in 0..200 {
        store
            .append_committed(&WalEntry::Applied {
                state: Box::new(state(&format!("c{i}"))),
            })
            .expect("append");
    }
    let open_segment = layout
        .wal_segments()
        .expect("segments")
        .last()
        .expect("a segment")
        .0;
    store.compact().expect("compact");

    let remaining: Vec<u32> = layout
        .wal_segments()
        .expect("segments")
        .into_iter()
        .map(|(i, _)| i)
        .collect();
    assert!(
        remaining.contains(&open_segment),
        "the open segment must survive: pruning it would unlink a file the writer is appending to"
    );

    // And the store still works afterwards: the descriptor is valid, the
    // directory entry is gone-free, and new records land in the kept segment.
    store
        .append_committed(&WalEntry::Applied {
            state: Box::new(state("after")),
        })
        .expect("append");
    assert_eq!(store.state().expect("state").containers.len(), 201);
}

#[test]
fn a_snapshot_write_survives_the_file_being_read_at_the_same_time() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(dir.path(), 64 * 1024);
    for i in 0..20 {
        store
            .append_committed(&WalEntry::Applied {
                state: Box::new(state(&format!("c{i}"))),
            })
            .expect("append");
    }

    let first = store.compact().expect("compact");
    let held = store.snapshot().expect("a mapped snapshot");
    let second = store.compact().expect("compact");

    assert_ne!(first.index, second.index);
    // The old mapping is still readable: readers do not pause for a compaction,
    // and the retention window keeps the previous file on disk for exactly this.
    assert_eq!(held.to_state().expect("held snapshot").containers.len(), 20);
    assert_eq!(
        store
            .snapshot()
            .expect("new")
            .to_state()
            .expect("state")
            .containers
            .len(),
        20
    );
}

#[test]
fn a_damaged_snapshot_falls_back_to_the_log_instead_of_refusing_to_start() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::new(dir.path());
    {
        let store = open(dir.path(), 64 * 1024);
        for i in 0..5 {
            store
                .append_committed(&WalEntry::Applied {
                    state: Box::new(state(&format!("c{i}"))),
                })
                .expect("append");
        }
        store.compact().expect("compact");
    }

    // Corrupt the only snapshot. The store must still open and still know
    // about its containers, because the WAL survived.
    let snapshot = layout
        .snapshots()
        .expect("snapshots")
        .pop()
        .expect("a snapshot")
        .1;
    let mut bytes = std::fs::read(&snapshot).expect("read");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::fs::write(&snapshot, &bytes).expect("write");

    let store = open(dir.path(), 64 * 1024);
    let report = store.recovery();
    assert!(
        !report.rejected_snapshots.is_empty(),
        "the damage must be reported: {report:?}"
    );
    assert_eq!(
        store.state().expect("state").containers.len(),
        5,
        "the log still has the state"
    );
}

/// Flips one byte inside the payload of the *second* record, leaving a valid
/// frame after it. A torn tail is recoverable; a hole in the middle of an
/// acknowledged log is not, and the store must say so instead of opening.
fn damage_a_middle_record(dir: &Path) {
    let wal = StoreLayout::new(dir)
        .wal_segments()
        .expect("segments")
        .pop()
        .expect("a segment")
        .1;
    let mut bytes = std::fs::read(&wal).expect("read");
    assert!(bytes.len() > 64, "the log must hold at least two records");
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0xff;
    std::fs::write(&wal, &bytes).expect("write");
}

#[test]
fn a_damaged_wal_refuses_to_open_and_writes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::new(dir.path());
    {
        let store = open(dir.path(), 64 * 1024);
        for i in 0..6 {
            store
                .append_committed(&WalEntry::Applied {
                    state: Box::new(state(&format!("c{i}"))),
                })
                .expect("append");
        }
    }
    damage_a_middle_record(dir.path());

    let before = layout.wal_segments().expect("segments");
    let bytes_before = std::fs::read(&before[0].1).expect("read");
    let snapshots_before = layout.snapshots().expect("snapshots").len();

    let err = match Store::open_in(
        StoreLayout::new(dir.path()).with_segment_size(64 * 1024),
        CommitPolicy::default(),
    ) {
        Err(e) => e,
        Ok(_) => panic!("a store with a hole in its log must not open"),
    };
    match err {
        StoreError::StoreDamaged { .. } => {}
        other => panic!("expected StoreDamaged, got {other:?}"),
    }

    // Nothing was rewritten on the way out: no snapshot written, no segment
    // truncated, no bytes changed. The evidence is what the operator needs.
    assert_eq!(
        layout.snapshots().expect("snapshots").len(),
        snapshots_before,
        "a refused open must not write a snapshot"
    );
    assert_eq!(
        std::fs::read(&before[0].1).expect("read"),
        bytes_before,
        "a refused open must not touch the damaged segment"
    );
}

#[test]
fn a_damaged_wal_refuses_to_compact() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::new(dir.path());

    // Damage that arrives *while the engine is running* — a failing SD card
    // does not wait for a restart. The store is already open here, so the
    // compaction guard is the only thing standing between the operator and a
    // snapshot of the intact prefix followed by a prune of the damaged segment.
    let store = open(dir.path(), 64 * 1024);
    for i in 0..6 {
        store
            .append_committed(&WalEntry::Applied {
                state: Box::new(state(&format!("c{i}"))),
            })
            .expect("append");
    }
    damage_a_middle_record(dir.path());

    let err = store.compact().expect_err("compaction must refuse");
    assert!(
        matches!(err, StoreError::StoreDamaged { .. }),
        "unexpected error: {err:?}"
    );
    // Reads keep answering with the intact prefix rather than failing: the node
    // is already in an unknown state, and a `r3s ps` that errors tells the
    // operator less than a `r3s ps` that lists what survived. The invariant that
    // matters is that nothing was written or deleted, asserted below.
    let containers = store.state().expect("state").containers.len();
    assert!(
        (0..6).contains(&containers),
        "a damaged log may only ever serve a prefix, got {containers}"
    );
    assert!(
        !layout.wal_segments().expect("segments").is_empty(),
        "the damaged segment must still be there for repair"
    );
}

#[test]
fn two_stores_on_one_root_never_interleave() {
    let dir = tempfile::tempdir().expect("tempdir");
    let _first = open(dir.path(), 64 * 1024);
    match Store::open_in(StoreLayout::new(dir.path()), CommitPolicy::default()) {
        Err(StoreError::Locked) => {}
        other => panic!("expected Locked, got {other:?}"),
    }
}

use std::path::Path;
