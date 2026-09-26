//! The telemetry ring.
//!
//! One fixed-stride ring per container, `mmap`'d, written by a single sampler
//! task and read by the CLI. Retention is a ring, not a GC policy, so the
//! memory cost is bounded by construction and no code path can grow it.
//!
//! The record layout is `MetricSample` from `r3s-proto`: 32 bytes, `#[repr(C)]`,
//! no rkyv. This module owns the byte encoding of that struct, and the two must
//! change together — see the layout test.
//!
//! ```text
//! header (32 bytes, cache-line aligned)
//!   0..8   magic     u64  b"R3SRING"
//!   8..12  version   u32
//!  12..16  capacity  u32   records
//!  16..24  head      u64   next slot to write   (release-written by the sampler)
//!  24..32  tail      u64   next slot to read    (acquire-read by the reader)
//! records: capacity × MetricSample (32 bytes)
//! ```
//!
//! The header's `head` is the only field written by the sampler and read by the
//! CLI. Publication is a release store of `head` *after* the record bytes are
//! written, and the reader is an acquire load, so a reader can never observe a
//! slot index whose payload has not landed. Everything else is immutable after
//! `create`.
//!
//! `#[repr(C)]` and the 24-byte stride are a documented on-disk format: changing
//! either requires bumping `RING_VERSION`, because an older binary reading a
//! newer ring would silently misinterpret every sample.

use std::fs::OpenOptions;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use memmap2::{Mmap, MmapMut};
use r3s_proto::MetricSample;
use r3s_proto::StoreError;

const MAGIC: u64 = u64::from_le_bytes(*b"R3SRING\0");
const RING_VERSION: u32 = 1;
const HEADER_LEN: usize = 32;

/// 4096 × 32 B + 32 B header = 128 KiB. Chosen so one container's history is
/// ~68 minutes at 1 Hz and 16 containers cost 2 MiB of page cache in total,
/// which is a rounding error next to the 8 GiB of RAM on the board.
pub const DEFAULT_CAPACITY: u32 = 4096;

/// A stride that is not 32 would silently mis-address every record.
const STRIDE: usize = std::mem::size_of::<MetricSample>();
const _: () = assert!(STRIDE == 32);

/// The two cursors, aliasing the mapped header rather than copying it.
///
/// Copying them would be the bug this type exists to prevent: a reader that
/// took a *snapshot* of `head` at open time would never observe a sample
/// written after that, and the ring would look permanently empty from the CLI
/// while the engine believed it was publishing telemetry.
///
/// The raw pointers are derived from a mapping the owning struct holds, and
/// every dereference happens under the invariant spelled out in
/// [`Cursor::from_base`]. They are never handed out, never exposed, and never
/// aliased as a plain `u64`.
#[derive(Debug)]
struct Cursor {
    head: *const AtomicU64,
    tail: *const AtomicU64,
}

impl Cursor {
    /// # Safety invariant
    ///
    /// `base` must point at a mapping of at least 32 bytes that stays alive and
    /// unmoved for as long as the returned `Cursor` is used, whose bytes 0..32
    /// hold the ring header, and which is 8-byte aligned. All three hold: the
    /// mapping begins at a page boundary, `mmap` cannot be resized, and the
    /// owning `RingWriter`/`RingReader` owns the `MmapMut`/`Mmap` and is
    /// destroyed only after the cursor goes with it.
    ///
    /// `head` and `tail` are only ever touched as `AtomicU64`, which is what
    /// makes concurrent access to the same bytes defined: the writer publishes
    /// with a release store, readers observe with an acquire load.
    unsafe fn from_base(base: *mut u8) -> Self {
        Self {
            // SAFETY: J-11. Page-aligned base + 16 is 8-byte aligned; the
            // mapping is at least 32 bytes, so both cursors are in bounds.
            head: unsafe { base.add(16).cast::<AtomicU64>() },
            tail: unsafe { base.add(24).cast::<AtomicU64>() },
        }
    }

    fn head(&self) -> u64 {
        // SAFETY: J-11. The cursor is only reachable from a struct that owns
        // the mapping it points into (invariant documented above).
        unsafe { (*self.head).load(Ordering::Acquire) }
    }

    fn set_head(&self, value: u64) {
        // SAFETY: J-11. The store is the publication point: the record bytes
        // are already written when it happens.
        unsafe { (*self.head).store(value, Ordering::Release) };
    }

    fn tail(&self) -> u64 {
        // SAFETY: J-11, as `head`.
        unsafe { (*self.tail).load(Ordering::Acquire) }
    }
}

/// A read-only view. Cheap to clone: it is a pointer to the mapping plus a copy
/// of the header cursors.
#[derive(Debug)]
pub struct RingReader {
    mmap: Mmap,
    capacity: u32,
    cursor: Cursor,
}

/// The writer. One per container, owned by the single sampler task.
#[derive(Debug)]
pub struct RingWriter {
    mmap: MmapMut,
    path: std::path::PathBuf,
    capacity: u32,
    cursor: Cursor,
}

// SAFETY: J-11. `Cursor` holds pointers into `mmap`, and `RingWriter` owns that
// `MmapMut`, so moving the struct to another thread moves the mapping with it
// and the pointers stay valid. Sharing is safe for the same reason plus the
// atomic access discipline: `push` needs `&mut self`, so there is at most one
// writer, and readers only ever touch `Cursor::head`/`tail` atomically.
unsafe impl Send for RingWriter {}
// SAFETY: J-11, as `Send`, plus no non-atomic field is mutated behind a shared
// reference: `push` takes `&mut self`, and the rest are read-only.
unsafe impl Sync for RingWriter {}

impl RingWriter {
    /// Creates the ring, or opens it if it already exists with a matching
    /// capacity. Resizing a live ring would discard history and can race the
    /// reader, so a capacity change means a new file.
    pub fn create(path: &Path, capacity: u32) -> Result<Self, StoreError> {
        if capacity == 0 {
            return Err(StoreError::CorruptSnapshot(
                "telemetry ring capacity must be non-zero".into(),
            ));
        }
        let bytes = ring_bytes(capacity);

        if !path.exists() {
            let file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(path)
                .map_err(|e| StoreError::Path {
                    path: path.display().to_string(),
                    source: e,
                })?;
            file.set_len(bytes as u64).map_err(|e| StoreError::Path {
                path: path.display().to_string(),
                source: e,
            })?;
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| StoreError::Path {
                path: path.display().to_string(),
                source: e,
            })?;
        let len = file.metadata()?.len() as usize;
        if len < bytes {
            return Err(StoreError::CorruptSnapshot(format!(
                "{}: {len} bytes, need {bytes} for a {capacity}-record ring",
                path.display()
            )));
        }

        // SAFETY: the mapping is exactly the file, and this process holds the
        // store's exclusive lock, so no other writer exists. The header is
        // written below through the same mapping, not through `File`, so the
        // page cache and the mapping cannot disagree.
        // SAFETY: J-01. The file is only ever this ring, sized to the page
        // multiple `ring_bytes` already asked for, and the `File` outlives the
        // mapping because the struct owns both.
        let mut mmap = unsafe { MmapMut::map_mut(&file) }.map_err(|e| StoreError::Path {
            path: path.display().to_string(),
            source: e,
        })?;

        if u64::from_le_bytes(mmap[0..8].try_into().expect("8 bytes")) != MAGIC {
            mmap[0..8].copy_from_slice(&MAGIC.to_le_bytes());
            mmap[8..12].copy_from_slice(&RING_VERSION.to_le_bytes());
            mmap[12..16].copy_from_slice(&capacity.to_le_bytes());
            mmap[16..24].copy_from_slice(&0u64.to_le_bytes());
            mmap[24..32].copy_from_slice(&0u64.to_le_bytes());
            mmap.flush_range(0, HEADER_LEN)
                .map_err(|e| StoreError::Path {
                    path: path.display().to_string(),
                    source: e,
                })?;
        } else {
            let version = u32::from_le_bytes(mmap[8..12].try_into().expect("4 bytes"));
            if version != RING_VERSION {
                return Err(StoreError::StoreTooNew {
                    found: version,
                    supported: RING_VERSION,
                });
            }
            let stored = u32::from_le_bytes(mmap[12..16].try_into().expect("4 bytes"));
            if stored != capacity {
                return Err(StoreError::CorruptSnapshot(format!(
                    "{}: ring holds {stored} records, asked for {capacity}; \
                     a capacity change needs a new file, not a resize",
                    path.display()
                )));
            }
        }

        // SAFETY: the mapping is `bytes` long and at least 32 of those bytes
        // were just initialised with the ring header.
        // SAFETY: J-11. `mmap` is a live mapping of at least `HEADER_LEN`
        // bytes, and the struct owns it for as long as the cursor is used.
        let cursor = unsafe { Cursor::from_base(mmap.as_mut_ptr()) };
        Ok(Self {
            mmap,
            path: path.to_path_buf(),
            capacity,
            cursor,
        })
    }

    /// Appends one sample, overwriting the oldest when full.
    ///
    /// The sample is written as raw bytes into a slot this process owns, and the
    /// cursor is only advanced afterwards with a release store. A reader that
    /// observes the new `head` is therefore guaranteed to see the record.
    pub fn push(&mut self, sample: &MetricSample) {
        let head = self.cursor.head();
        let slot = (head % u64::from(self.capacity)) as usize;
        let offset = HEADER_LEN + slot * STRIDE;
        let bytes = to_bytes(sample);
        self.mmap[offset..offset + bytes.len()].copy_from_slice(&bytes);
        self.cursor.set_head(head + 1);
    }

    /// Publishes a `MetricSample` from raw cgroup values, saturating every
    /// counter at the field's width. A 24-byte record cannot hold a 64-bit
    /// counter, and wrapping would make a graph lie; saturating makes it flat.
    pub fn push_sample(
        &mut self,
        sampled_at_mono_ns: u64,
        memory_current: u32,
        cpu_usage_us: u32,
        pids: u16,
        io_read_bytes: u32,
        io_write_bytes: u32,
    ) {
        self.push(&MetricSample {
            sampled_at_mono_ns,
            memory_current,
            cpu_usage_us,
            pids,
            io_read_bytes,
            io_write_bytes,
        });
    }

    /// The writer's position, i.e. the sequence number the next sample gets.
    pub fn head(&self) -> u64 {
        self.cursor.head()
    }

    /// Samples retained before the ring starts overwriting.
    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// A second, read-only mapping of the same file. Both mappings are
    /// `MAP_SHARED`, so the page cache is common and a sample written through
    /// one is visible through the other without an `msync`: the release store
    /// in [`RingWriter::push`] is what orders the record bytes before the
    /// cursor, and the reader's acquire load is what orders them after.
    pub fn reader(&self) -> Result<RingReader, StoreError> {
        RingReader::open(&self.path, self.capacity)
    }

    /// The backing file, so the CLI can label a ring with its own path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl RingReader {
    /// Maps an existing ring read-only. The capacity argument must match the
    /// one the writer created the file with: the stride is not stored per slot,
    /// so a wrong value would decode garbage rather than fail.
    pub fn open(path: &Path, capacity: u32) -> Result<Self, StoreError> {
        let file = OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|e| StoreError::Path {
                path: path.display().to_string(),
                source: e,
            })?;
        // SAFETY: read-only mapping of a file this process either created or
        // validated. The CLI may read a ring while the engine writes it, so the
        // bytes are genuinely changing: every field read goes through
        // `from_bytes` on a slot the cursor says is published, and a partially
        // written slot is simply not visible until `head` moves.
        // SAFETY: J-01, as in `create`. Read-only: the reader never writes
        // through this mapping, only reads published slots.
        let mmap = unsafe { Mmap::map(&file) }.map_err(|e| StoreError::Path {
            path: path.display().to_string(),
            source: e,
        })?;

        if mmap.len() < HEADER_LEN {
            return Err(StoreError::CorruptSnapshot(format!(
                "{}: shorter than a ring header",
                path.display()
            )));
        }
        if u64::from_le_bytes(mmap[0..8].try_into().expect("8 bytes")) != MAGIC {
            return Err(StoreError::CorruptSnapshot(format!(
                "{}: not a telemetry ring",
                path.display()
            )));
        }
        let version = u32::from_le_bytes(mmap[8..12].try_into().expect("4 bytes"));
        if version != RING_VERSION {
            return Err(StoreError::StoreTooNew {
                found: version,
                supported: RING_VERSION,
            });
        }
        let stored = u32::from_le_bytes(mmap[12..16].try_into().expect("4 bytes"));
        if stored != capacity {
            return Err(StoreError::CorruptSnapshot(format!(
                "{}: capacity {stored} does not match the requested {capacity}",
                path.display()
            )));
        }

        // SAFETY: mapping is >= 32 bytes and the header was validated above.
        // SAFETY: J-11. The cast erases the mapping's mutability for the
        // pointer type, not for the access: `Cursor` only ever *reads* these
        // two words (its `set_head` is private to the writer), and the
        // alignment and length invariants hold for a read-only mapping just as
        // they do for a writable one.
        let cursor = unsafe { Cursor::from_base(mmap.as_ptr() as *mut u8) };
        Ok(Self {
            mmap,
            capacity,
            cursor,
        })
    }

    /// The writer's current position, read live. A reader that asks again sees
    /// later samples; it is a cursor, not a snapshot.
    pub fn head(&self) -> u64 {
        self.cursor.head()
    }

    /// Oldest sequence number still intact. This never advances: the writer
    /// overwrites the oldest slot in place, so retention is a window that slides
    /// forward rather than a queue that drains.
    pub fn tail(&self) -> u64 {
        self.cursor.tail()
    }

    /// Samples currently readable, at most `capacity`.
    pub fn len(&self) -> usize {
        self.cursor
            .head()
            .saturating_sub(self.cursor.tail())
            .min(u64::from(self.capacity)) as usize
    }

    /// Whether no sample has been published yet.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The most recent `n` samples, oldest first.
    pub fn recent(&self, n: usize) -> Vec<MetricSample> {
        let head = self.cursor.head();
        let take = n.min(self.len()) as u64;
        let first = head.saturating_sub(take);
        (first..head).map(|seq| self.sample(seq)).collect()
    }

    /// Reads the record for a sequence number. `seq` is clamped into
    /// `[tail, head)`: a slot outside that range may be mid-write, and reading
    /// it anyway would show a half-updated sample as a real one.
    fn sample(&self, seq: u64) -> MetricSample {
        let head = self.cursor.head();
        let clamped = seq.clamp(self.cursor.tail(), head.saturating_sub(1));
        let slot = (clamped % u64::from(self.capacity)) as usize;
        let offset = HEADER_LEN + slot * STRIDE;
        from_bytes(&self.mmap[offset..offset + STRIDE])
    }

    /// Oldest-to-newest iteration over everything still in the ring.
    pub fn iter(&self) -> impl Iterator<Item = MetricSample> + '_ {
        let count = self.len() as u64;
        let first = self.cursor.head().saturating_sub(count);
        (0..count).map(move |i| self.sample(first + i))
    }
}

// SAFETY: J-11. `RingReader` owns its `Mmap` and its `Cursor` points into it,
// so the pointers survive a move to another thread. It is immutable after
// `open`, and every access to the shared bytes is atomic or a read of an
// already-published record, so sharing it between threads is sound.
unsafe impl Send for RingReader {}
// SAFETY: J-11, as `Send`. `RingReader` has no interior mutability at all.
unsafe impl Sync for RingReader {}

fn ring_bytes(capacity: u32) -> usize {
    HEADER_LEN + capacity as usize * STRIDE
}

fn to_bytes(sample: &MetricSample) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&sample.sampled_at_mono_ns.to_le_bytes());
    out[8..12].copy_from_slice(&sample.memory_current.to_le_bytes());
    out[12..16].copy_from_slice(&sample.cpu_usage_us.to_le_bytes());
    out[16..18].copy_from_slice(&sample.pids.to_le_bytes());
    out[20..24].copy_from_slice(&sample.io_read_bytes.to_le_bytes());
    out[24..28].copy_from_slice(&sample.io_write_bytes.to_le_bytes());
    out
}

fn from_bytes(bytes: &[u8]) -> MetricSample {
    MetricSample {
        sampled_at_mono_ns: u64::from_le_bytes(bytes[0..8].try_into().expect("8 bytes")),
        memory_current: u32::from_le_bytes(bytes[8..12].try_into().expect("4 bytes")),
        cpu_usage_us: u32::from_le_bytes(bytes[12..16].try_into().expect("4 bytes")),
        pids: u16::from_le_bytes(bytes[16..18].try_into().expect("2 bytes")),
        io_read_bytes: u32::from_le_bytes(bytes[20..24].try_into().expect("4 bytes")),
        io_write_bytes: u32::from_le_bytes(bytes[24..28].try_into().expect("4 bytes")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring(dir: &tempfile::TempDir, capacity: u32) -> (std::path::PathBuf, RingWriter) {
        let path = dir.path().join("web.ring");
        let writer = RingWriter::create(&path, capacity).expect("create");
        (path, writer)
    }

    #[test]
    fn the_stride_is_exactly_32_bytes() {
        assert_eq!(STRIDE, 32);
        assert_eq!(ring_bytes(DEFAULT_CAPACITY), HEADER_LEN + 4096 * 32);
    }

    #[test]
    fn a_sample_roundtrips_through_the_mapping() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_path, mut writer) = ring(&dir, 8);
        writer.push_sample(42, 1024, 7, 3, 99, 88);
        writer.push_sample(43, 2048, 9, 4, 100, 89);

        let reader = writer.reader().expect("reader");
        let samples = reader.recent(8);
        assert_eq!(samples.len(), 2);
        assert_eq!(samples[0].sampled_at_mono_ns, 42);
        assert_eq!(samples[0].memory_current, 1024);
        assert_eq!(samples[0].cpu_usage_us, 7);
        assert_eq!(samples[0].pids, 3);
        assert_eq!(samples[0].io_read_bytes, 99);
        assert_eq!(samples[0].io_write_bytes, 88);
        assert_eq!(samples[1].sampled_at_mono_ns, 43);
    }

    #[test]
    fn the_ring_overwrites_the_oldest_instead_of_growing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, mut writer) = ring(&dir, 4);
        for i in 0..10u64 {
            writer.push_sample(i, i as u32, 0, 1, 0, 0);
        }
        assert_eq!(writer.head(), 10);

        let reader = RingReader::open(&path, 4).expect("open");
        assert_eq!(reader.len(), 4, "a 4-slot ring holds 4 records, not 10");
        let samples = reader.recent(10);
        assert_eq!(samples.len(), 4);
        assert_eq!(samples.first().unwrap().sampled_at_mono_ns, 6);
        assert_eq!(samples.last().unwrap().sampled_at_mono_ns, 9);
    }

    #[test]
    fn a_reader_follows_the_writer_live() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, mut writer) = ring(&dir, 4);
        for i in 0..4u64 {
            writer.push_sample(i, 0, 0, 1, 0, 0);
        }
        let reader = RingReader::open(&path, 4).expect("open");
        assert_eq!(reader.head(), 4);

        // The reader must see samples written after it was opened, or the CLI
        // would report an empty ring for a running container forever.
        writer.push_sample(99, 7, 0, 1, 0, 0);
        assert_eq!(reader.head(), 5, "the cursor is aliased, not copied");
        assert_eq!(reader.len(), 4);
        assert_eq!(reader.recent(1)[0].sampled_at_mono_ns, 99);
        assert_eq!(reader.recent(1)[0].memory_current, 7);
    }

    #[test]
    fn a_reader_across_threads_sees_the_writers_samples() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, mut writer) = ring(&dir, 64);
        let reader = RingReader::open(&path, 64).expect("open");

        let handle = std::thread::spawn(move || {
            let mut widest = 0;
            for _ in 0..1000 {
                // Bounds check under a live writer: a torn `head`/`tail` read
                // would show a length outside the window and index past the
                // mapping.
                widest = widest.max(reader.len());
            }
            widest
        });
        for i in 0..1000u64 {
            writer.push_sample(i, 0, 0, 1, 0, 0);
        }
        assert!(handle.join().expect("reader thread") <= 64);

        assert_eq!(writer.head(), 1000);
        let reader = RingReader::open(&path, 64).expect("reopen");
        assert_eq!(reader.len(), 64, "the ring stays bounded, it does not grow");
        assert_eq!(reader.recent(1)[0].sampled_at_mono_ns, 999);
    }

    #[test]
    fn a_mismatched_capacity_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, _writer) = ring(&dir, 16);
        let err = RingReader::open(&path, 32).expect_err("must refuse");
        assert!(matches!(err, StoreError::CorruptSnapshot(_)), "{err:?}");
    }

    #[test]
    fn a_short_file_is_refused_rather_than_read() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("short.ring");
        std::fs::write(&path, b"too short").expect("write");
        let err = RingReader::open(&path, 16).expect_err("must refuse");
        assert!(matches!(err, StoreError::CorruptSnapshot(_)), "{err:?}");
    }

    #[test]
    fn a_zero_capacity_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = RingWriter::create(&dir.path().join("x.ring"), 0).expect_err("must refuse");
        assert!(matches!(err, StoreError::CorruptSnapshot(_)), "{err:?}");
    }
}
