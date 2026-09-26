//! On-disk layout.
//!
//! ```text
//! <root>/
//! ├── LOCK                flock(LOCK_EX): one engine per node
//! ├── wal/000001.log      append-only, framed records, CRC per record
//! ├── wal/000002.log      rotated at wal_segment_max_bytes
//! ├── snap/000042.rkyv    mmap'd snapshot; current + previous are kept
//! └── telemetry/<id>.ring fixed-stride ring, mmap'd
//! ```
//!
//! Every path is derived from one root and validated once at open, so no
//! component of a path is ever taken from a container name, a mount target or
//! a volume name — the one place where a path-traversal bug would become a
//! host-write primitive.

use std::path::{Path, PathBuf};

use r3s_proto::id::ContainerId;

/// Default segment size. Large enough that a chatty workload does not rotate
/// every few seconds, small enough that a snapshot rewrite after a crash is
/// fast on an SD card.
pub const WAL_SEGMENT_DEFAULT: u64 = 64 * 1024 * 1024;

/// The maximum a WAL record may claim to be. A corrupt length field would
/// otherwise make the reader try to allocate 4 GiB before noticing the file
/// ended.
pub const WAL_MAX_RECORD_BYTES: u32 = 1 << 20;

/// The set of paths a store uses, plus the tunables that decide when it
/// rewrites them. Cheap to clone and immutable once built, so it can be handed
/// to every subsystem without sharing a `&mut`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreLayout {
    root: PathBuf,
    wal_segment_max_bytes: u64,
}

impl StoreLayout {
    /// A layout rooted at `root` with the default segment size. The directory
    /// is not created here; [`StoreLayout::ensure_dirs`] does that, because
    /// building a layout must not have side effects an error path could skip.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            wal_segment_max_bytes: WAL_SEGMENT_DEFAULT,
        }
    }

    /// Overrides the WAL segment size. Smaller segments make compaction cheap,
    /// larger ones make it rare; both are correct, so the caller picks.
    ///
    /// # Panics
    ///
    /// On zero, which would rotate the WAL on every append.
    pub fn with_segment_size(mut self, bytes: u64) -> Self {
        assert!(
            bytes > 0,
            "a zero segment size would rotate on every append"
        );
        self.wal_segment_max_bytes = bytes;
        self
    }

    /// The state directory this layout was built from.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The `flock` target: one exclusive writer per node.
    pub fn lock_file(&self) -> PathBuf {
        self.root.join("LOCK")
    }

    /// Directory holding the rotated WAL segments.
    pub fn wal_dir(&self) -> PathBuf {
        self.root.join("wal")
    }

    /// Directory holding the rkyv snapshots.
    pub fn snapshot_dir(&self) -> PathBuf {
        self.root.join("snap")
    }

    /// Directory holding the per-container telemetry rings.
    pub fn telemetry_dir(&self) -> PathBuf {
        self.root.join("telemetry")
    }

    /// One WAL segment. The index is zero-padded so directory order matches
    /// replay order on every filesystem, including ones with case-folding.
    pub fn wal_segment(&self, index: u32) -> PathBuf {
        self.wal_dir().join(format!("{index:06}.log"))
    }

    /// Snapshots are zero-padded so `ls` sorts them chronologically, which is
    /// what an operator does under pressure at 3 a.m.
    pub fn snapshot(&self, index: u64) -> PathBuf {
        self.snapshot_dir().join(format!("{index:06}.rkyv"))
    }

    /// The ring for `id`. Derived from the identifier, never from the container
    /// name: a name is operator input and may contain `../`.
    pub fn telemetry_ring(&self, id: ContainerId) -> PathBuf {
        self.telemetry_dir().join(format!("{}.ring", id.to_hex()))
    }

    /// Creates the directory tree. Idempotent, so it doubles as a check that
    /// the state directory is writable before anything is written into it.
    pub fn ensure_dirs(&self) -> std::io::Result<()> {
        for dir in [
            self.root.clone(),
            self.wal_dir(),
            self.snapshot_dir(),
            self.telemetry_dir(),
        ] {
            std::fs::create_dir_all(&dir)?;
        }
        Ok(())
    }

    /// Segments present on disk, oldest first. A non-numeric or partial name is
    /// ignored rather than treated as index 0: a half-written file from a crash
    /// is not a segment.
    pub fn wal_segments(&self) -> std::io::Result<Vec<(u32, PathBuf)>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(self.wal_dir())? {
            let path = entry?.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some(stem) = name.strip_suffix(".log") else {
                continue;
            };
            let Ok(index) = stem.parse::<u32>() else {
                continue;
            };
            out.push((index, path));
        }
        out.sort_by_key(|(index, _)| *index);
        Ok(out)
    }

    /// Snapshots present on disk, oldest first.
    pub fn snapshots(&self) -> std::io::Result<Vec<(u64, PathBuf)>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(self.snapshot_dir())? {
            let path = entry?.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some(stem) = name.strip_suffix(".rkyv") else {
                continue;
            };
            let Ok(index) = stem.parse::<u64>() else {
                continue;
            };
            out.push((index, path));
        }
        out.sort_by_key(|(index, _)| *index);
        Ok(out)
    }

    /// The size at which the writer rolls over to a new segment.
    pub fn segment_max_bytes(&self) -> u64 {
        self.wal_segment_max_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_sort_chronologically() {
        let layout = StoreLayout::new("/srv/r3s");
        assert_eq!(layout.snapshot(2).file_name().unwrap(), "000002.rkyv");
        assert_eq!(layout.wal_segment(11).file_name().unwrap(), "000011.log");
    }

    #[test]
    fn ring_path_is_derived_from_the_id_not_the_name() {
        let layout = StoreLayout::new("/srv/r3s");
        let id = ContainerId::from_bytes([0xab; 16]);
        let path = layout.telemetry_ring(id);
        assert!(path.starts_with(layout.telemetry_dir()));
        assert_eq!(
            path.file_name().and_then(|n| n.to_str()),
            Some(format!("{}.ring", id.to_hex()).as_str())
        );
    }
}
