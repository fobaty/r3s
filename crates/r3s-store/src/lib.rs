//! The transactional state store.
//!
//! One engine per node, one writer per store, crash-safe at every instruction.
//! Three parts:
//!
//! * [`wal`] — append-only intent log, framed, CRC'd, group-committed;
//! * [`snapshot`] — mmap'd `rkyv` archive of the whole state, written and
//!   renamed atomically;
//! * [`ring`] — fixed-stride telemetry per container, no allocation, bounded.
//!
//! The store holds no policy. It does not know what a container is; it knows
//! how to make a set of bytes durable and how to read them back. Everything
//! about *when* to write lives in `r3s-engine`, which is the only writer.

//! `unsafe` is confined to `mmap` (J-01), the `flock` guard (J-02) and the
//! ring's shared atomic cursors (J-11). All three are registered in
//! `docs/UNSAFE.md` and referenced from the `SAFETY:` comment on each block.

#![deny(missing_docs, unsafe_op_in_unsafe_fn)]

pub mod layout;
pub mod recovery;
pub mod ring;
pub mod snapshot;
pub mod wal;

use std::fs::File;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, RwLock};

use nix::fcntl::{Flock, FlockArg};
use r3s_proto::state::StateSnapshot;
// The store's error type is the protocol's: an operator matches on
// `StoreError::Locked` from `r3s system status` and from this crate, and two
// enums with the same variants would make that a guess.
pub use r3s_proto::StoreError;

pub use layout::StoreLayout;
pub use recovery::{COMPACT_WAL_BYTES, COMPACT_WAL_RECORDS, RecoveryReport};
pub use ring::{DEFAULT_CAPACITY as RING_CAPACITY, RingReader, RingWriter};
pub use snapshot::{Snapshot, SnapshotMeta};
pub use wal::{CommitPolicy, Wal, WalEntry, WalScan};

/// The exclusive lock on a node's state directory.
///
/// The guard owns the `File`, so the `flock` is released on drop — including
/// on `panic = "abort"`, where no unwinding runs. Nothing has to be undone by a
/// signal handler that may not execute, and a killed engine leaves no stale
/// lock: the kernel drops it when the fd closes.
#[derive(Debug)]
pub struct StoreLock {
    /// Held, never read: dropping it releases the `flock`.
    _guard: Flock<File>,
    path: std::path::PathBuf,
}

impl StoreLock {
    /// Takes `LOCK_EX` without waiting. A second engine gets `Locked` instead of
    /// blocking forever behind a live one, which is the difference between a
    /// clear error and a node that looks hung.
    pub fn acquire(root: &Path) -> Result<Self, StoreError> {
        let path = root.join("LOCK");
        let file = File::options()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| StoreError::Path {
                path: path.display().to_string(),
                source: e,
            })?;

        // SAFETY: J-02. `flock` is the only mechanism the kernel offers for
        // "one writer per node" that survives `exec` and does not need a
        // daemon, a lease file, or a PID sweep to detect a crashed holder.
        match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(guard) => Ok(Self {
                _guard: guard,
                path,
            }),
            // The file is returned with the error, and closing it releases
            // anything the failed attempt may have left.
            Err((_file, nix::errno::Errno::EWOULDBLOCK)) => Err(StoreError::Locked),
            Err((_file, e)) => Err(StoreError::Io(std::io::Error::from(e))),
        }
    }

    /// Where the lock file lives, for the log line that says which node's
    /// store a `Locked` error is about.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Everything mutable about a store. Behind one mutex, held for the length of
/// one append or one commit, never across a syscall the caller can block on.
#[derive(Debug)]
struct Writer {
    wal: Wal,
}

/// The store handle. Cheap to clone (`Arc` inside), safe to share across
/// threads, and — by the absence of `&mut self` on every method — impossible to
/// write to from two places at once.
#[derive(Debug, Clone)]
pub struct Store {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    layout: StoreLayout,
    // Held for the process lifetime, never used for reading: its only job is to
    // keep the `flock` alive and to make the store un-constructible twice.
    _lock: StoreLock,
    writer: Mutex<Writer>,
    snapshot: RwLock<Option<Arc<Snapshot>>>,
    recovery: RecoveryReport,
}

impl Store {
    /// Opens the store: takes the lock, recovers, and maps the newest snapshot.
    pub fn open(root: &Path) -> Result<Self, StoreError> {
        Self::open_with(root, CommitPolicy::default())
    }

    /// As [`Store::open`], with an explicit group-commit policy. The policy is
    /// the store's loss window, so it is a parameter rather than a constant:
    /// a node that must not lose an acknowledged intent passes a smaller one.
    pub fn open_with(root: &Path, policy: CommitPolicy) -> Result<Self, StoreError> {
        Self::open_in(StoreLayout::new(root), policy)
    }

    /// As [`Store::open_with`], with a layout the caller built. Only tests and
    /// the migration fixtures need this: they want a segment size small enough
    /// to rotate inside a test, not a second way to configure a node.
    /// Open (and lock) a store, recovering it first.
    ///
    /// A torn tail is truncated and the store opens. Damage in the middle of the
    /// log is not survivable and returns [`StoreError::StoreDamaged`] with
    /// nothing written: see [`RecoveryReport::wal_corruption`].
    pub fn open_in(layout: StoreLayout, policy: CommitPolicy) -> Result<Self, StoreError> {
        let root = layout.root().to_path_buf();
        layout.ensure_dirs().map_err(|e| StoreError::Path {
            path: layout.root().display().to_string(),
            source: e,
        })?;

        // The lock comes before recovery: two engines replaying the same WAL and
        // both writing a snapshot is exactly the corruption the lock exists to
        // prevent, and it would be the *second* engine to corrupt the store.
        let lock = StoreLock::acquire(&root)?;
        let (state, recovery) = recovery::recover(&layout)?;

        // Damage in the middle of the log is not a crash to recover from, it is
        // an acknowledged record that no longer exists. Opening a writer on top
        // of it would let the engine report success for state it does not have,
        // and would let the next compaction delete the evidence. Fail here,
        // with nothing written, and let the operator decide: a store that cannot
        // be opened is recoverable, a store that is silently wrong is not.
        //
        // A *torn tail* is not in this list: a record that was never
        // acknowledged can be truncated, and `recover` already did that.
        if let Some(damage) = recovery.wal_corruption() {
            return Err(damage.to_error());
        }

        let snapshot = match snapshot::open_latest(&layout)?.snapshot {
            Some(handle) => Some(handle),
            None => {
                // First open, or a store whose only snapshot is gone. Write one
                // now so the next open has something to mmap.
                let meta = snapshot::write(&layout, &state)?;
                Some(Arc::new(snapshot::open(&meta.path, meta.index)?))
            }
        };

        let wal = Wal::open(&layout, policy)?;
        tracing::info!(
            root = %layout.root().display(),
            snapshot = ?recovery.snapshot_index,
            wal_records = recovery.wal_records,
            "store open"
        );

        Ok(Self {
            inner: Arc::new(Inner {
                layout,
                _lock: lock,
                writer: Mutex::new(Writer { wal }),
                snapshot: RwLock::new(snapshot),
                recovery,
            }),
        })
    }

    /// The on-disk layout this store was opened with.
    pub fn layout(&self) -> &StoreLayout {
        &self.inner.layout
    }

    /// What the last open decided: which snapshot it used, how much of the WAL
    /// replayed, and whether anything was damaged. This is what
    /// `r3s system status --store-only` prints.
    pub fn recovery(&self) -> &RecoveryReport {
        &self.inner.recovery
    }

    fn writer(&self) -> MutexGuard<'_, Writer> {
        // A poisoned mutex means a writer panicked mid-append. The WAL is
        // framed and CRC'd precisely so that a recovered-from-poison writer is
        // still correct: take the data and keep going rather than propagating
        // the panic into the reconciler loop.
        self.inner
            .writer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Appends an entry. Not durable until [`Store::commit`].
    /// Appends an entry to the write buffer. Durable only after
    /// [`Store::commit`]; the returned sequence number is the caller's handle
    /// for "did this get acknowledged yet".
    pub fn append(&self, entry: &WalEntry) -> Result<u64, StoreError> {
        self.writer().wal.append(entry)
    }

    /// Appends and commits in one call, for the paths that are rare enough not
    /// to need batching (a lease, a rename).
    /// Append and `fdatasync` in one call, for the rare writes that are not
    /// worth batching: address leases, renames, restart-policy changes.
    pub fn append_committed(&self, entry: &WalEntry) -> Result<u64, StoreError> {
        let mut writer = self.writer();
        let seq = writer.wal.append(entry)?;
        writer.wal.commit()?;
        Ok(seq)
    }

    /// Flushes and `fdatasync`s everything pending.
    /// Flushes the write buffer and `fdatasync`s it. After this returns, every
    /// record appended so far survives a power cut.
    pub fn commit(&self) -> Result<(), StoreError> {
        self.writer().wal.commit()
    }

    /// Whether a group-commit threshold has been crossed. The caller owns the
    /// timer; the store deliberately has no thread of its own.
    /// Whether a group-commit threshold has been crossed. The caller owns the
    /// timer — a store with its own thread would have to be joined, and this
    /// one is a library, not a daemon.
    pub fn should_commit(&self) -> bool {
        self.writer().wal.should_commit()
    }

    /// Bytes written but not yet durable. The documented loss window.
    /// Bytes written but not yet durable: the documented loss window, and what
    /// the CLI shows next to the WAL size.
    pub fn loss_window_bytes(&self) -> u64 {
        self.writer().wal.loss_window_bytes()
    }

    /// Total WAL bytes, including the part not yet synced.
    pub fn wal_len(&self) -> u64 {
        self.writer().wal.len()
    }

    /// The mapped snapshot, if there is one. `None` only before the first
    /// compaction on a store whose snapshot was written but not yet mapped.
    pub fn snapshot(&self) -> Option<Arc<Snapshot>> {
        self.inner
            .snapshot
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Materialised state: snapshot plus WAL replay. This is what the reconciler
    /// reconciles against; the CLI prefers [`Store::snapshot`].
    ///
    /// Damage that appears while the store is open stops *writes*
    /// ([`Store::compact`] refuses) but not reads: the state here is the intact
    /// prefix, because that is all the log can prove. Failing the read instead
    /// would leave the operator with no way to see what survived, which is the
    /// one thing worth having at 3 a.m. The next open is where it becomes fatal.
    pub fn state(&self) -> Result<StateSnapshot, StoreError> {
        let mut state = match self.snapshot() {
            Some(handle) => handle.to_state()?,
            None => StateSnapshot {
                store_version: r3s_proto::STORE_VERSION,
                ..StateSnapshot::default()
            },
        };
        let scan = wal::scan(&self.inner.layout)?;
        let mut report = RecoveryReport::default();
        for record in &scan.records {
            recovery::apply_entry(&mut state, &record.entry, &mut report);
        }
        state.written_at_unix_ns = unix_nanos();
        Ok(state)
    }

    /// Folds the current state into a snapshot, swaps the mapping, and drops
    /// the WAL segments the snapshot now covers.
    ///
    /// The state is read *here*, under the writer lock, rather than taken as an
    /// argument. A caller-supplied state is a footgun: between the caller's read
    /// and this call the writer may have rotated to a new segment, and pruning
    /// up to that segment would delete records the supplied state never saw.
    pub fn compact(&self) -> Result<SnapshotMeta, StoreError> {
        let mut writer = self.writer();
        writer.wal.commit()?;

        let scan = wal::scan(&self.inner.layout)?;
        // Same reasoning as `open_in`, one step later in the lifecycle: a
        // snapshot built from a damaged prefix plus a prune of the segment that
        // holds the damage would turn a recoverable incident into lost data.
        // Refusing here keeps the damaged bytes on disk for `r3s store repair`.
        if let Some(damage) = &scan.corrupt {
            return Err(damage.to_error());
        }
        let mut state = match self.snapshot() {
            Some(handle) => handle.to_state()?,
            None => StateSnapshot {
                store_version: r3s_proto::STORE_VERSION,
                ..StateSnapshot::default()
            },
        };
        let mut report = RecoveryReport::default();
        for record in &scan.records {
            recovery::apply_entry(&mut state, &record.entry, &mut report);
        }

        let meta = recovery::compact(&self.inner.layout, &state)?;
        // Everything the snapshot now covers is below the open segment, and the
        // open segment is the only file the writer holds a descriptor for.
        let open_segment = writer.wal.segment();
        let pruned = writer.wal.prune(&self.inner.layout, open_segment)?;
        tracing::info!(snapshot = meta.index, pruned, "compacted");

        let handle = snapshot::open(&meta.path, meta.index)?;
        let handle = Arc::new(handle);
        // Readers holding the old `Arc` keep their mapping; the new one is
        // visible to everyone who asks after this line. No lock is held across
        // the write, because `compact` already finished it.
        match self.inner.snapshot.write() {
            Ok(mut slot) => *slot = Some(handle),
            Err(poisoned) => *poisoned.into_inner() = Some(handle),
        }
        Ok(meta)
    }

    /// Whether the WAL has grown enough to be worth compacting. Threshold
    /// policy lives in the store so that a caller cannot compact a store it
    /// only has a shared reference to, and so the answer accounts for records
    /// still sitting in the write buffer.
    pub fn should_compact(&self) -> Result<bool, StoreError> {
        let writer = self.writer();
        Ok(recovery::should_compact(&wal::scan(&self.inner.layout)?))
            .map(|should| should || writer.wal.pending_records() > 0)
    }

    /// The telemetry ring for one container, created on first use. `capacity` is
    /// the number of samples retained; changing it for an existing ring is
    /// refused, because resizing under a live reader would lose history silently.
    pub fn telemetry(
        &self,
        id: r3s_proto::ContainerId,
        capacity: u32,
    ) -> Result<RingWriter, StoreError> {
        RingWriter::create(&self.inner.layout.telemetry_ring(id), capacity)
    }

    /// A read-only view of one container's ring, for the CLI. Reads the live
    /// cursor, so a long-lived handle keeps up with the sampler.
    pub fn telemetry_reader(
        &self,
        id: r3s_proto::ContainerId,
        capacity: u32,
    ) -> Result<RingReader, StoreError> {
        RingReader::open(&self.inner.layout.telemetry_ring(id), capacity)
    }
}

fn unix_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use r3s_proto::id::{ContainerId, ImageRef};
    use r3s_proto::state::{ContainerState, Phase};
    use r3s_proto::types::ContainerSpec;

    fn store(dir: &tempfile::TempDir) -> Store {
        Store::open(dir.path()).expect("open")
    }

    fn state(name: &str) -> ContainerState {
        // Two names that share a first byte must not share a container, or a
        // fixture generating many names silently tests one container.
        let mut id = [0u8; 16];
        id.copy_from_slice(&r3s_proto::Digest::of(name.as_bytes()).as_bytes()[..16]);
        let mut s = ContainerState::new(ContainerSpec::new(
            ContainerId::from_bytes(id),
            name,
            ImageRef::parse("alpine:3").expect("parses"),
        ));
        s.phase = Phase::Running;
        s.pid = Some(4242);
        s
    }

    #[test]
    fn append_commit_reopen_shows_the_state() {
        let dir = tempfile::tempdir().expect("tempdir");
        {
            let store = store(&dir);
            store
                .append(&recovery::applied_entry(&state("web")))
                .expect("append");
            store.commit().expect("commit");
        }
        let store = store(&dir);
        let recovered = store.state().expect("state");
        assert_eq!(recovered.containers.len(), 1);
        assert_eq!(recovered.containers[0].spec.name, "web");
        assert_eq!(recovered.containers[0].phase, Phase::Running);
    }

    #[test]
    fn a_second_store_on_the_same_root_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let _first = store(&dir);
        let err = Store::open(dir.path()).expect_err("must be refused");
        assert!(matches!(err, StoreError::Locked), "{err:?}");
    }

    #[test]
    fn the_lock_is_released_when_the_store_drops() {
        let dir = tempfile::tempdir().expect("tempdir");
        {
            let _first = store(&dir);
            assert!(Store::open(dir.path()).is_err());
        }
        assert!(
            Store::open(dir.path()).is_ok(),
            "the lock must not outlive the handle"
        );
    }

    #[test]
    fn compaction_publishes_a_new_snapshot_the_readers_see() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(&dir);
        let before = store.snapshot().expect("a snapshot at open");

        // The state is folded from the store itself, not handed in: a
        // caller-supplied state is exactly how a compaction ends up deleting
        // records it never saw.
        for name in ["web", "db"] {
            store
                .append_committed(&recovery::applied_entry(&state(name)))
                .expect("append");
        }
        // Below the threshold the store says no, and an explicit compact still
        // does the work: policy decides *when*, not *what*.
        assert!(
            !store.should_compact().expect("threshold"),
            "two records are not a reason to compact"
        );
        let meta = store.compact().expect("compact");

        let after = store.snapshot().expect("a snapshot after compact");
        assert_eq!(after.index(), meta.index);
        assert_ne!(before.index(), after.index());
        // The old handle is still valid: that is the no-read-pause guarantee.
        assert_eq!(before.to_state().expect("old snapshot").containers.len(), 0);
        assert_eq!(after.to_state().expect("new snapshot").containers.len(), 2);
    }

    #[test]
    fn the_loss_window_shrinks_to_zero_after_a_commit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(&dir);
        for _ in 0..10 {
            store
                .append(&recovery::applied_entry(&state("web")))
                .expect("append");
        }
        assert!(store.loss_window_bytes() > 0);
        store.commit().expect("commit");
        assert_eq!(store.loss_window_bytes(), 0);
    }

    #[test]
    fn append_committed_is_durable_on_return() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(&dir);
        store
            .append_committed(&recovery::applied_entry(&state("db")))
            .expect("append");
        assert_eq!(store.loss_window_bytes(), 0);
        assert_eq!(store.state().expect("state").containers.len(), 1);
    }

    #[test]
    fn telemetry_rings_are_per_container() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(&dir);
        let web = ContainerId::from_bytes([1; 16]);
        let db = ContainerId::from_bytes([2; 16]);

        let mut web_ring = store.telemetry(web, 64).expect("web ring");
        web_ring.push_sample(1, 100, 1, 1, 0, 0);
        let db_ring = store.telemetry(db, 64).expect("db ring");
        assert_eq!(
            db_ring.head(),
            0,
            "a different container is a different ring"
        );
        assert_eq!(store.telemetry_reader(web, 64).expect("read").len(), 1);
    }
}
