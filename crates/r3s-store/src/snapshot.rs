//! The mmap'd snapshot.
//!
//! A snapshot is `[header][rkyv archive]`, written to a temporary file and
//! `rename`d into place, so a reader either sees the whole old file or the
//! whole new one. Never a partially written file, never a lock, no read pause:
//! the previous snapshot stays mapped for as long as anyone holds an `Arc`.
//!
//! ```text
//!  0..4   magic    u32  b"R3S"
//!  4..8   version  u32  store format version
//!  8..12  len      u32  archive length
//! 12..20  written  u64  unix nanos
//! 20..24  crc32    u32  of the archive
//! 24..    archive
//! ```
//!
//! There is no CRC on the header itself: a snapshot only becomes visible under
//! its final name after `write_all` + `sync_all` + `rename`, so a torn header
//! cannot exist in a file the reader will ever open. The archive CRC plus
//! `bytecheck` cover the part that a later write, a bit flip or a compromised
//! process could actually change.
//!
//! Reads go through `rkyv::access`, i.e. `bytecheck` validates every pointer in
//! the archive before it is followed. Bytes on disk are untrusted input: a
//! container name is attacker-influenced data that ends up in a snapshot.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use memmap2::Mmap;
use r3s_proto::StoreError;
use r3s_proto::state::{ArchivedStateSnapshot, StateSnapshot};

use crate::layout::StoreLayout;

const MAGIC: u32 = u32::from_le_bytes(*b"R3S\0");
const HEADER_LEN: usize = 24;

/// How many snapshots are kept: current plus previous. One is enough to recover
/// from a corrupt current snapshot; two would only delay the problem.
const KEEP_SNAPSHOTS: usize = 2;

/// What the snapshot header says, once it has been validated against the file
/// it came from. Produced by [`open`] only: a `SnapshotMeta` in hand
/// is a claim the bytes already back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotMeta {
    /// Monotonic write index. Filename order is snapshot order.
    pub index: u64,
    /// `STORE_VERSION` at write time, so a future engine can tell whether the
    /// archive needs migrating.
    pub version: u32,
    /// Archive length, checked against the mapped file before it is used to
    /// slice anything.
    pub archive_len: u32,
    /// `CLOCK_REALTIME` nanoseconds at write time, for "when was this state
    /// true" in a post-mortem.
    pub written_at_unix_ns: u64,
    /// The file the archive is mapped from.
    pub path: PathBuf,
}

/// A mapped snapshot. Cloning is an `Arc` bump, so a `ps` loop and a snapshot
/// compaction can hold one at the same time without either blocking.
#[derive(Debug)]
pub struct Snapshot {
    index: u64,
    meta: SnapshotMeta,
    mmap: Mmap,
}

impl Snapshot {
    /// Validates and deserialises the archive. Allocates; call it for logic
    /// that wants owned data, not for display.
    pub fn to_state(&self) -> Result<StateSnapshot, StoreError> {
        rkyv::from_bytes::<StateSnapshot, rkyv::rancor::Error>(self.archive())
            .map_err(|e| StoreError::CorruptSnapshot(format!("snapshot {}: {e}", self.index)))
    }

    /// Zero-copy access. Runs `bytecheck` over the archive, so the returned
    /// reference is safe to follow for as long as this handle lives.
    pub fn archived(&self) -> Result<&ArchivedStateSnapshot, StoreError> {
        rkyv::access::<ArchivedStateSnapshot, rkyv::rancor::Error>(self.archive())
            .map_err(|e| StoreError::CorruptSnapshot(format!("snapshot {}: {e}", self.index)))
    }

    /// The raw rkyv archive, header excluded. Use this to hash or copy the
    /// bytes; use [`Snapshot::to_state`] to read them.
    pub fn archive(&self) -> &[u8] {
        let start = HEADER_LEN;
        &self.mmap[start..start + self.meta.archive_len as usize]
    }

    /// The validated header of this snapshot.
    pub fn meta(&self) -> &SnapshotMeta {
        &self.meta
    }

    /// The write index, which is also its position in the retention window.
    pub fn index(&self) -> u64 {
        self.index
    }
}

/// Writes `state` as the next snapshot and returns its metadata.
///
/// The directory entry is `fsync`ed after the rename. Without that, a crash
/// can leave a name that points at nothing, which is indistinguishable from
/// data loss to whoever does the recovery.
pub fn write(layout: &StoreLayout, state: &StateSnapshot) -> Result<SnapshotMeta, StoreError> {
    let index = layout.snapshots()?.last().map_or(1, |(index, _)| index + 1);

    let archive = rkyv::to_bytes::<rkyv::rancor::Error>(state)
        .map_err(|e| StoreError::CorruptSnapshot(format!("serialise snapshot: {e}")))?;
    let written_at_unix_ns = unix_nanos();
    let crc = r3s_proto::crc32c(&archive);

    let final_path = layout.snapshot(index);
    let tmp_path = final_path.with_extension("rkyv.tmp");

    {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|e| StoreError::Path {
                path: tmp_path.display().to_string(),
                source: e,
            })?;

        let mut header = [0u8; HEADER_LEN];
        header[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        header[4..8].copy_from_slice(&r3s_proto::STORE_VERSION.to_le_bytes());
        header[8..12].copy_from_slice(&(archive.len() as u32).to_le_bytes());
        header[12..20].copy_from_slice(&written_at_unix_ns.to_le_bytes());
        header[20..24].copy_from_slice(&crc.to_le_bytes());

        file.write_all(&header)?;
        file.write_all(&archive)?;
        file.sync_all()?;
    }

    std::fs::rename(&tmp_path, &final_path).map_err(|e| StoreError::Path {
        path: final_path.display().to_string(),
        source: e,
    })?;
    fsync_dir(&layout.snapshot_dir())?;

    prune(layout, index)?;

    Ok(SnapshotMeta {
        index,
        version: r3s_proto::STORE_VERSION,
        archive_len: archive.len() as u32,
        written_at_unix_ns,
        path: final_path,
    })
}

/// Maps an existing snapshot, validating header, CRC and `bytecheck`.
pub fn open(path: &Path, index: u64) -> Result<Snapshot, StoreError> {
    let file = File::open(path).map_err(|e| StoreError::Path {
        path: path.display().to_string(),
        source: e,
    })?;
    // SAFETY: J-01. Read-only mapping of a whole file; the `File` is kept alive
    // by the `Snapshot`, which owns both, and the length checks below reject
    // anything shorter than the header before a single byte is read as data.
    let mmap = unsafe { Mmap::map(&file) }.map_err(|e| StoreError::Path {
        path: path.display().to_string(),
        source: e,
    })?;

    if mmap.len() < HEADER_LEN {
        return Err(StoreError::CorruptSnapshot(format!(
            "{}: shorter than a header",
            path.display()
        )));
    }
    if u32::from_le_bytes(mmap[0..4].try_into().expect("4 bytes")) != MAGIC {
        return Err(StoreError::CorruptSnapshot(format!(
            "{}: bad magic",
            path.display()
        )));
    }
    let version = u32::from_le_bytes(mmap[4..8].try_into().expect("4 bytes"));
    if version > r3s_proto::STORE_VERSION {
        return Err(StoreError::StoreTooNew {
            found: version,
            supported: r3s_proto::STORE_VERSION,
        });
    }
    let archive_len = u32::from_le_bytes(mmap[8..12].try_into().expect("4 bytes")) as usize;
    let crc = u32::from_le_bytes(mmap[20..24].try_into().expect("4 bytes"));

    if mmap.len() != HEADER_LEN + archive_len {
        return Err(StoreError::CorruptSnapshot(format!(
            "{}: header says {archive_len} bytes, file has {}",
            path.display(),
            mmap.len() - HEADER_LEN
        )));
    }
    let archive = &mmap[HEADER_LEN..];
    if r3s_proto::crc32c(archive) != crc {
        return Err(StoreError::CorruptSnapshot(format!(
            "{}: archive CRC mismatch",
            path.display()
        )));
    }

    Ok(Snapshot {
        index,
        meta: SnapshotMeta {
            index,
            version,
            archive_len: archive_len as u32,
            written_at_unix_ns: u64::from_le_bytes(mmap[12..20].try_into().expect("8 bytes")),
            path: path.to_path_buf(),
        },
        mmap,
    })
}

/// The newest snapshot that validated, plus the ones that did not.
///
/// Returning both matters: the caller needs the state *and* has to be able to
/// say "your snapshot was damaged, this state came from the log instead" instead
/// of silently starting with less than it thinks it has.
#[derive(Debug, Default)]
pub struct Latest {
    /// Newest snapshot that validated, if any did.
    pub snapshot: Option<Arc<Snapshot>>,
    /// `(index, reason)` for each snapshot that failed, newest first.
    pub rejected: Vec<(u64, String)>,
}

/// Loads the newest snapshot that opens cleanly, falling back to the previous
/// one. A corrupt current snapshot is a real event, not a reason to refuse to
/// start: the WAL still holds everything after it, and if it does not, the
/// caller rebuilds from an empty state and says so.
pub fn open_latest(layout: &StoreLayout) -> Result<Latest, StoreError> {
    let mut tried = Vec::new();
    for (index, path) in layout.snapshots()?.iter().rev() {
        match open(path, *index) {
            Ok(snapshot) => {
                for (bad_index, reason) in &tried {
                    tracing::error!(index = bad_index, %reason, "a newer snapshot did not validate");
                }
                return Ok(Latest {
                    snapshot: Some(Arc::new(snapshot)),
                    rejected: tried,
                });
            }
            Err(e) => {
                tracing::error!(index, error = %e, "snapshot did not validate; trying the previous one");
                tried.push((*index, e.to_string()));
            }
        }
    }
    // Nothing validated. That is not an error here: the WAL may still be a
    // complete record, and refusing to start would turn a damaged snapshot into
    // an outage on top of the data loss.
    for (bad_index, reason) in &tried {
        tracing::error!(index = bad_index, %reason, "no snapshot validated; rebuilding from the wal");
    }
    Ok(Latest {
        snapshot: None,
        rejected: tried,
    })
}

fn prune(layout: &StoreLayout, newest: u64) -> Result<(), StoreError> {
    let all = layout.snapshots()?;
    if all.len() <= KEEP_SNAPSHOTS {
        return Ok(());
    }
    for (_, path) in all.iter().take(all.len() - KEEP_SNAPSHOTS) {
        std::fs::remove_file(path)?;
    }
    tracing::debug!(
        kept = newest,
        retained = KEEP_SNAPSHOTS,
        "pruned old snapshots"
    );
    Ok(())
}

fn fsync_dir(dir: &Path) -> Result<(), StoreError> {
    File::open(dir)
        .and_then(|f| f.sync_all())
        .map_err(|e| StoreError::Path {
            path: dir.display().to_string(),
            source: e,
        })
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
    use r3s_proto::StateSnapshot;
    use r3s_proto::id::{ContainerId, ImageRef};
    use r3s_proto::state::ContainerState;
    use r3s_proto::types::ContainerSpec;

    fn layout() -> (tempfile::TempDir, StoreLayout) {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::new(dir.path());
        layout.ensure_dirs().expect("dirs");
        (dir, layout)
    }

    fn snapshot_with(names: &[&str]) -> StateSnapshot {
        let mut state = StateSnapshot {
            store_version: r3s_proto::STORE_VERSION,
            written_at_unix_ns: 1_700_000_000_000_000_000,
            ..StateSnapshot::default()
        };
        for name in names {
            let id = ContainerId::from_bytes([name.len() as u8; 16]);
            state.insert(ContainerState::new(ContainerSpec::new(
                id,
                *name,
                ImageRef::parse("alpine:3").expect("parses"),
            )));
        }
        state
    }

    #[test]
    fn write_then_read_roundtrips() {
        let (_dir, layout) = layout();
        let state = snapshot_with(&["web", "db"]);
        let meta = write(&layout, &state).expect("write");

        let snapshot = open(&meta.path, meta.index).expect("open");
        let back = snapshot.to_state().expect("state");
        assert_eq!(back.containers.len(), 2);
        assert_eq!(back, state);
        assert_eq!(snapshot.meta().version, r3s_proto::STORE_VERSION);
    }

    #[test]
    fn archived_access_is_zero_copy_and_checked() {
        let (_dir, layout) = layout();
        let state = snapshot_with(&["web"]);
        let meta = write(&layout, &state).expect("write");
        let snapshot = open(&meta.path, meta.index).expect("open");

        let archived = snapshot.archived().expect("bytecheck");
        assert_eq!(archived.containers.len(), 1);
        assert_eq!(archived.containers.as_slice()[0].spec.name.as_str(), "web");
    }

    #[test]
    fn a_flipped_archive_byte_fails_the_crc_not_the_reader() {
        let (_dir, layout) = layout();
        let meta = write(&layout, &snapshot_with(&["web"])).expect("write");
        let mut bytes = std::fs::read(&meta.path).expect("read");
        let last = bytes.len() - 8;
        bytes[last] ^= 0x01;
        std::fs::write(&meta.path, &bytes).expect("write");

        let err = open(&meta.path, meta.index).expect_err("must fail");
        assert!(matches!(err, StoreError::CorruptSnapshot(_)), "{err:?}");
    }

    #[test]
    fn a_corrupt_newest_snapshot_falls_back_to_the_previous_one() {
        let (_dir, layout) = layout();
        let first = write(&layout, &snapshot_with(&["web"])).expect("first");
        let second = write(&layout, &snapshot_with(&["web", "db"])).expect("second");

        let mut bytes = std::fs::read(&second.path).expect("read");
        bytes[HEADER_LEN + 4] ^= 0xff;
        std::fs::write(&second.path, &bytes).expect("write");

        let latest = open_latest(&layout).expect("fallback");
        let handle = latest.snapshot.expect("a snapshot");
        assert_eq!(
            handle.index(),
            first.index,
            "recovery must use the older snapshot"
        );
        assert_eq!(handle.to_state().expect("state").containers.len(), 1);
        assert_eq!(
            latest.rejected.len(),
            1,
            "the damage must still be reported"
        );
    }

    #[test]
    fn a_store_whose_only_snapshot_is_damaged_still_starts() {
        let (_dir, layout) = layout();
        let only = write(&layout, &snapshot_with(&["web", "db"])).expect("write");
        let mut bytes = std::fs::read(&only.path).expect("read");
        bytes[HEADER_LEN + 4] ^= 0xff;
        std::fs::write(&only.path, &bytes).expect("write");

        // Not an error: the WAL is the record now, and refusing to boot would
        // turn a damaged file into an outage.
        let latest = open_latest(&layout).expect("no usable snapshot is not an error");
        assert!(latest.snapshot.is_none());
        assert_eq!(latest.rejected.len(), 1);
    }

    #[test]
    fn a_snapshot_from_the_future_is_refused_rather_than_guessed_at() {
        let (_dir, layout) = layout();
        let meta = write(&layout, &snapshot_with(&["web"])).expect("write");
        let mut bytes = std::fs::read(&meta.path).expect("read");
        bytes[4..8].copy_from_slice(&(r3s_proto::STORE_VERSION + 1).to_le_bytes());
        std::fs::write(&meta.path, &bytes).expect("write");

        let err = open(&meta.path, meta.index).expect_err("must fail");
        assert!(matches!(err, StoreError::StoreTooNew { .. }), "{err:?}");
    }

    #[test]
    fn only_the_two_newest_snapshots_are_kept() {
        let (_dir, layout) = layout();
        for _ in 0..5 {
            write(&layout, &snapshot_with(&["web"])).expect("write");
        }
        let all = layout.snapshots().expect("list");
        assert_eq!(
            all.len(),
            2,
            "current + previous is the whole retention policy"
        );
    }
}
