//! The intent WAL.
//!
//! Every mutation is an *intent* written here **before** the side effect it
//! describes, and an *observation* written after. A crash between the two
//! leaves an unmatched intent, which recovery replays idempotently; that is why
//! the engine can be `kill -9`ed at any instruction and still converge.
//!
//! Record framing (little-endian, 24-byte header):
//!
//! ```text
//!  0..4   magic  u32   b"R3W1"
//!  4..8   len    u32   payload length, <= WAL_MAX_RECORD_BYTES
//!  8..16  seq    u64   monotonic across segments
//! 16..20  crc32c u32   of the payload
//! 20..24  crc32c u32   of header[0..20]
//! 24..    payload
//! ```
//!
//! Both CRCs exist because they fail differently: a torn *header* can produce a
//! wild length and a wild offset, and a torn *payload* keeps a sane length. With
//! only one CRC, one of those two cases reads as valid data.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use r3s_proto::StoreError;

use crate::layout::{StoreLayout, WAL_MAX_RECORD_BYTES};

const MAGIC: u32 = u32::from_le_bytes(*b"R3W1");
const HEADER_LEN: usize = 24;

// `#[derive(Archive)]` emits a resolver struct as a *sibling* of the type it
// derives, so an `#[allow]` on the type itself does not reach it, and the
// crate-wide `deny(missing_docs)` fires on a struct nobody can name. The
// resolver is not API, so the one type that needs it lives in a module that
// turns the lint off. Everything hand-written is still documented and still
// checked — by eye, and by review, because the lint is off here.
mod entry {
    #![allow(missing_docs)]

    use r3s_proto::command::Command;
    use r3s_proto::state::{ContainerState, StateSnapshot};
    use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
    use serde::{Deserialize, Serialize};

    /// A WAL entry: the only thing the engine writes to the log.
    // The derive emits its own position/relocation fields, which have no docs and
    // no business being documented.
    #[allow(missing_docs)]
    #[derive(Archive, RkyvSerialize, RkyvDeserialize, Serialize, Deserialize, Clone, Debug)]
    #[non_exhaustive]
    pub enum WalEntry {
        /// Written before the side effect, with the operator that asked for it.
        /// An intent with no matching observation after replay means the process
        /// died mid-flight, and the reconciler has to decide what actually happened
        /// by looking at the kernel — never by assuming success.
        Intent {
            /// The command as submitted, already validated.
            command: Box<Command>,
            /// Who asked, for the audit line and for "was that me".
            actor: String,
        },
        /// Written after the side effect succeeded: the container's new state as
        /// the kernel reported it, not as the caller hoped.
        Applied {
            /// Post-transition state for exactly the container the intent named.
            state: Box<ContainerState>,
        },
        /// The reconciled whole, written when a snapshot rewrite is not worth the
        /// SD-card write and replaying a few hundred records is cheaper.
        Checkpoint {
            /// Complete state; supersedes every record before it.
            snapshot: Box<StateSnapshot>,
        },
        /// Address handed out by the pool, so a restart does not double-lease.
        AddressLease {
            /// Allocated address.
            addr: u32,
            /// Container holding it.
            owner: r3s_proto::ContainerId,
        },
        /// Address returned to the pool.
        AddressRelease {
            /// Freed address.
            addr: u32,
        },
    }
}

pub use entry::WalEntry;

/// One framed record plus where it came from.
#[derive(Debug, Clone)]
pub struct WalRecord {
    /// Store-wide monotonic sequence. Replay order is sequence order, and the
    /// gap left by a rolled-back segment is what compaction uses to prove it
    /// may drop those segments.
    pub seq: u64,
    /// Segment the record was found in.
    pub segment: u32,
    /// Byte offset of the frame within that segment, for the "damaged at N" line.
    pub offset: u64,
    /// The entry itself, CRC already verified.
    pub entry: WalEntry,
}

/// What a scan found, including everything that was *not* clean.
#[derive(Debug, Default)]
pub struct WalScan {
    /// Intact records in sequence order. A scan stops at the first frame it
    /// cannot vouch for, so this is a prefix of the log, never a guess.
    pub records: Vec<WalRecord>,
    /// Bytes that are valid and must be preserved.
    pub valid_len: u64,
    /// A record was cut short by a crash. Normal, and safe to truncate.
    pub torn_tail: bool,
    /// A record failed its CRC and was *not* at the end. The log is damaged.
    pub corrupt: Option<Corruption>,
}

/// Damage the scan could not explain as a crash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Corruption {
    /// Segment that holds it.
    pub segment: u32,
    /// Byte offset of the frame.
    pub offset: u64,
    /// Sequence the frame claimed, or 0 if the header was too broken to say.
    pub seq: u64,
    /// Which check failed.
    pub reason: CorruptionReason,
}

/// Why a frame was rejected. Every variant is a runbook row, because
/// "the state is wrong" without "this is what was wrong" costs an hour at 3 a.m.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorruptionReason {
    /// The 4-byte frame header did not match.
    HeaderCrc,
    /// The header was fine, the body was not: a torn write, a bad SD card, or
    /// a bug. `scan` only calls this corruption at a non-final frame.
    PayloadCrc,
    /// Not a WAL frame at all — usually a file that is not a segment.
    BadMagic,
    /// The length field is zero, above the cap, or runs past the segment end.
    LengthOutOfRange,
}

impl CorruptionReason {
    /// The runbook wording. Kept here so the error an operator sees, the log
    /// line, and the runbook row cannot drift apart.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HeaderCrc => "frame header CRC mismatch",
            Self::PayloadCrc => "record payload CRC mismatch",
            Self::BadMagic => "not a WAL frame (bad magic)",
            Self::LengthOutOfRange => "record length out of range",
        }
    }
}

impl Corruption {
    /// The typed failure the store surfaces instead of opening on damaged data.
    pub fn to_error(&self) -> StoreError {
        StoreError::StoreDamaged {
            segment: self.segment,
            offset: self.offset,
            reason: self.reason.as_str(),
        }
    }
}

/// Group-commit thresholds. `sync_data` on an SD card costs milliseconds, so
/// the writer coalesces; the loss window is `delay` and is a documented
/// property of the store, not an accident.
#[derive(Debug, Clone, Copy)]
pub struct CommitPolicy {
    /// Longest an appended record may sit unsynced. 5 ms is below the ~16 ms a
    /// human notices in a `create` call and above the cost of one `fdatasync`
    /// on a Pi 5's SD card.
    pub max_delay: Duration,
    /// Commit once this many bytes are buffered.
    pub max_bytes: usize,
    /// Commit once this many records are buffered, so a burst of small
    /// transitions cannot sit in the loss window indefinitely.
    pub max_records: usize,
}

impl Default for CommitPolicy {
    fn default() -> Self {
        Self {
            max_delay: Duration::from_millis(5),
            max_bytes: 64 * 1024,
            max_records: 256,
        }
    }
}

/// The writer. Single-writer by construction: `Store` owns exactly one, behind
/// a mutex, and the `flock` on `LOCK` is what keeps a second *process* out.
#[derive(Debug)]
pub struct Wal {
    file: File,
    path: PathBuf,
    segment: u32,
    len: u64,
    next_seq: u64,
    policy: CommitPolicy,
    pending: Vec<u8>,
    pending_records: usize,
    first_pending: std::time::Instant,
    synced_len: u64,
    /// The cap, kept here because rotation happens on every append.
    segment_max: u64,
    /// Where segments live, so rotation can name the next one without the
    /// writer re-deriving paths the layout already owns.
    wal_dir: PathBuf,
}

impl PartialEq for WalEntry {
    /// Structural comparison, including the `Box` payloads, so a test can
    /// assert that a round-tripped record is the record that went in.
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                WalEntry::Intent {
                    command: a,
                    actor: a_actor,
                },
                WalEntry::Intent {
                    command: b,
                    actor: b_actor,
                },
            ) => a == b && a_actor == b_actor,
            (WalEntry::Applied { state: a }, WalEntry::Applied { state: b }) => a == b,
            (WalEntry::Checkpoint { snapshot: a }, WalEntry::Checkpoint { snapshot: b }) => a == b,
            (
                WalEntry::AddressLease {
                    addr: a_addr,
                    owner: a_owner,
                },
                WalEntry::AddressLease {
                    addr: b_addr,
                    owner: b_owner,
                },
            ) => a_addr == b_addr && a_owner == b_owner,
            (WalEntry::AddressRelease { addr: a }, WalEntry::AddressRelease { addr: b }) => a == b,
            _ => false,
        }
    }
}

impl Wal {
    /// Opens the newest segment for append, creating segment 1 if the directory
    /// is empty. Existing records are not read: the writer appends, and
    /// [`scan`] is the reader. A torn tail is *not* truncated here — the writer
    /// must not destroy evidence; `Store::open` decides, via recovery.
    pub fn open(layout: &StoreLayout, policy: CommitPolicy) -> Result<Self, StoreError> {
        let segments = layout.wal_segments()?;
        let (segment, path, len) = match segments.last() {
            Some((index, path)) => (*index, path.clone(), std::fs::metadata(path)?.len()),
            None => {
                let index = 1;
                let path = layout.wal_segment(index);
                (index, path, 0)
            }
        };

        // Appending past the segment cap would make one crash cost a full
        // segment of replay; rotating keeps the loss window predictable.
        let (segment, path, len) = if len >= layout.segment_max_bytes() {
            let index = segment + 1;
            let path = layout.wal_segment(index);
            (index, path, 0)
        } else {
            (segment, path, len)
        };

        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)
            .map_err(|e| StoreError::Path {
                path: path.display().to_string(),
                source: e,
            })?;

        let next_seq = scan(layout)?.records.last().map_or(1, |r| r.seq + 1);

        Ok(Self {
            file,
            path,
            segment,
            len,
            next_seq,
            policy,
            pending: Vec::new(),
            pending_records: 0,
            first_pending: std::time::Instant::now(),
            synced_len: len,
            segment_max: layout.segment_max_bytes(),
            wal_dir: layout.wal_dir(),
        })
    }

    /// The segment currently being appended to.
    pub fn segment(&self) -> u32 {
        self.segment
    }

    /// The file currently being appended to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Total bytes written to the current segment, synced or not.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the current segment has no bytes yet.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Bytes durable on the medium. The CLI shows this next to the WAL length
    /// because the gap is the loss window.
    /// Bytes covered by the last successful `fdatasync`. Anything above this is
    /// the documented loss window.
    pub fn synced_len(&self) -> u64 {
        self.synced_len
    }

    /// Records appended since the last commit.
    pub fn pending_records(&self) -> usize {
        self.pending_records
    }

    /// Frames and writes one entry, assigning the next sequence number. Does
    /// not sync: the caller commits when [`Wal::should_commit`] says so, or on
    /// any write that must be durable before the next step.
    pub fn append(&mut self, entry: &WalEntry) -> Result<u64, StoreError> {
        let seq = self.next_seq;
        let payload = rkyv::to_bytes::<rkyv::rancor::Error>(entry)
            .map_err(|e| StoreError::CorruptSnapshot(format!("serialise wal entry: {e}")))?;
        if payload.len() > WAL_MAX_RECORD_BYTES as usize {
            return Err(StoreError::CorruptSnapshot(format!(
                "wal record of {} bytes exceeds the {} byte cap",
                payload.len(),
                WAL_MAX_RECORD_BYTES
            )));
        }

        // Rotate *before* framing, not at commit: a record must never straddle
        // two segments, and the uncommitted buffer has to follow the file it
        // was measured against. `commit` is what decides whether the old
        // segment stays open long enough to be worth keeping.
        let frame = (HEADER_LEN + payload.len()) as u64;
        if self.len + frame > self.segment_max {
            self.rotate()?;
        }

        self.pending
            .extend_from_slice(&encode_header(seq, payload.len(), &payload));
        self.pending.extend_from_slice(&payload);
        self.next_seq += 1;
        if self.pending_records == 0 {
            self.first_pending = std::time::Instant::now();
        }
        self.pending_records += 1;
        self.len += (HEADER_LEN + payload.len()) as u64;
        Ok(seq)
    }

    /// `fdatasync`s the current segment. After this, every record appended
    /// before the call survives a power cut.
    pub fn commit(&mut self) -> Result<(), StoreError> {
        if self.pending.is_empty() {
            return Ok(());
        }
        self.file
            .write_all(&self.pending)
            .map_err(|e| StoreError::Path {
                path: self.path.display().to_string(),
                source: e,
            })?;
        self.pending.clear();
        self.pending_records = 0;
        self.file.sync_data().map_err(|e| StoreError::Path {
            path: self.path.display().to_string(),
            source: e,
        })?;
        self.synced_len = self.len;
        Ok(())
    }

    /// True when a threshold has been crossed and `commit` should be called.
    /// The caller decides *when* — a background task owns the timer, because
    /// the WAL must not block the reconciler on a timer of its own.
    pub fn should_commit(&self) -> bool {
        if self.pending.is_empty() {
            return false;
        }
        self.pending.len() >= self.policy.max_bytes
            || self.pending_records >= self.policy.max_records
            || self.first_pending.elapsed() >= self.policy.max_delay
    }

    /// Closes the current segment and continues in the next one.
    ///
    /// Buffered records are committed first: a segment that is closed with
    /// records still in memory is a segment whose contents exist in exactly one
    /// place, and that place is a buffer on a crashed node.
    fn rotate(&mut self) -> Result<(), StoreError> {
        self.commit()?;
        let next = self.segment.checked_add(1).ok_or_else(|| {
            StoreError::CorruptSnapshot(format!(
                "wal segment counter overflowed at {}",
                self.segment
            ))
        })?;
        let path = self.wal_dir.join(format!("{next:06}.log"));
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)
            .map_err(|e| StoreError::Path {
                path: path.display().to_string(),
                source: e,
            })?;
        self.file = file;
        self.path = path;
        self.segment = next;
        self.len = 0;
        self.synced_len = 0;
        tracing::debug!(segment = next, "rotated the wal");
        Ok(())
    }

    /// Unsynced bytes: what a power cut right now would cost.
    pub fn loss_window_bytes(&self) -> u64 {
        self.len - self.synced_len
    }

    /// Deletes segments below `keep_before` and returns how many went. Called
    /// only by compaction, and only after a snapshot that covers them is
    /// durable: deleting first would be deleting data that is not yet
    /// recoverable anywhere else.
    pub fn prune(&mut self, layout: &StoreLayout, keep_before: u32) -> Result<usize, StoreError> {
        let mut removed = 0;
        for (index, path) in layout.wal_segments()? {
            if index < keep_before && index != self.segment {
                std::fs::remove_file(&path).map_err(|e| StoreError::Path {
                    path: path.display().to_string(),
                    source: e,
                })?;
                removed += 1;
            }
        }
        Ok(removed)
    }
}

impl Drop for Wal {
    fn drop(&mut self) {
        // Best effort: a panic during Drop must not mask the original error.
        let _ = self.commit();
    }
}

fn encode_header(seq: u64, payload_len: usize, payload: &[u8]) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    header[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    header[4..8].copy_from_slice(&(payload_len as u32).to_le_bytes());
    header[8..16].copy_from_slice(&seq.to_le_bytes());
    header[16..20].copy_from_slice(&r3s_proto::crc32c(payload).to_le_bytes());
    let header_crc = r3s_proto::crc32c(&header[0..20]);
    header[20..24].copy_from_slice(&header_crc.to_le_bytes());
    header
}

/// Reads every segment in order and returns the intact prefix.
///
/// Stops at the first frame it cannot vouch for, because a log is only useful
/// while its prefix is trustworthy: silently skipping a damaged record in the
/// middle would replay the rest and produce a state nobody can reconstruct.
pub fn scan(layout: &StoreLayout) -> Result<WalScan, StoreError> {
    let mut out = WalScan::default();
    for (segment, path) in layout.wal_segments()? {
        let mut file = File::open(&path).map_err(|e| StoreError::Path {
            path: path.display().to_string(),
            source: e,
        })?;
        let file_len = file.metadata()?.len();
        let mut offset = 0u64;

        while offset < file_len {
            let remaining = file_len - offset;
            if remaining < HEADER_LEN as u64 {
                out.torn_tail = true;
                break;
            }

            let mut header = [0u8; HEADER_LEN];
            file.seek(SeekFrom::Start(offset))?;
            file.read_exact(&mut header)?;
            if let Some(reason) = validate_header(&header) {
                // A header that does not describe itself is damage, whatever its
                // position: a torn *payload* is a crash, a torn *header* is a
                // wild length or a wild sequence number, and this log must not
                // guess which happened.
                out.torn_tail = false;
                out.corrupt = Some(Corruption {
                    segment,
                    offset,
                    seq: seq_of(&header),
                    reason,
                });
                break;
            }

            let payload_len =
                u32::from_le_bytes(header[4..8].try_into().expect("4 bytes")) as usize;
            let total = HEADER_LEN + payload_len;
            if (total as u64) > remaining {
                // The header is intact and the body is short: a crash between
                // the two writes. Safe to truncate back to the frame boundary,
                // and the records lost by doing so were never acknowledged.
                out.torn_tail = true;
                break;
            }

            let mut payload = vec![0u8; payload_len];
            file.read_exact(&mut payload)?;
            if r3s_proto::crc32c(&payload)
                != u32::from_le_bytes(header[16..20].try_into().expect("4 bytes"))
            {
                out.corrupt = Some(Corruption {
                    segment,
                    offset,
                    seq: seq_of(&header),
                    reason: CorruptionReason::PayloadCrc,
                });
                break;
            }

            let entry: WalEntry = rkyv::from_bytes::<WalEntry, rkyv::rancor::Error>(&payload)
                .map_err(|e| StoreError::CorruptSnapshot(format!("wal record at {offset}: {e}")))?;
            out.records.push(WalRecord {
                seq: seq_of(&header),
                segment,
                offset,
                entry,
            });
            offset += total as u64;
        }

        out.valid_len += offset;
    }
    Ok(out)
}

fn seq_of(header: &[u8; HEADER_LEN]) -> u64 {
    u64::from_le_bytes(header[8..16].try_into().expect("8 bytes"))
}

/// `None` when the header is self-consistent, `Some(reason)` when it is not.
///
/// A length that runs past the end of the file is *not* checked here: that is a
/// torn tail, and conflating it with a bad length is what would let a crash
/// look like disk rot.
fn validate_header(header: &[u8; HEADER_LEN]) -> Option<CorruptionReason> {
    if u32::from_le_bytes(header[0..4].try_into().expect("4 bytes")) != MAGIC {
        return Some(CorruptionReason::BadMagic);
    }
    if r3s_proto::crc32c(&header[0..20])
        != u32::from_le_bytes(header[20..24].try_into().expect("4 bytes"))
    {
        return Some(CorruptionReason::HeaderCrc);
    }
    let payload_len = u32::from_le_bytes(header[4..8].try_into().expect("4 bytes"));
    if payload_len > WAL_MAX_RECORD_BYTES {
        return Some(CorruptionReason::LengthOutOfRange);
    }
    None
}

/// Cuts a segment back to its last intact frame, for a crash that happened
/// mid-write. Refuses when the scan reported *corruption*, not a torn tail: a
/// damaged record in the middle of the log must be preserved for the operator,
/// not deleted because the reader happened to stop there.
pub fn truncate_torn_tail(layout: &StoreLayout, scan: &WalScan) -> Result<bool, StoreError> {
    if !scan.torn_tail || scan.corrupt.is_some() {
        return Ok(false);
    }
    let Some((segment, path)) = layout.wal_segments()?.pop() else {
        return Ok(false);
    };

    let file_len = std::fs::metadata(&path)?.len();
    let valid_in_last = scan
        .valid_len
        .saturating_sub(total_len_of_earlier(layout, segment)?);
    if valid_in_last >= file_len {
        return Ok(false);
    }
    let file = OpenOptions::new().write(true).open(&path)?;
    file.set_len(valid_in_last)?;
    file.sync_all()?;
    tracing::warn!(
        segment,
        from = file_len,
        to = valid_in_last,
        "truncated a torn wal tail; the records in it were never acknowledged"
    );
    Ok(true)
}

fn total_len_of_earlier(layout: &StoreLayout, segment: u32) -> Result<u64, StoreError> {
    let mut total = 0;
    for (index, path) in layout.wal_segments()? {
        if index < segment {
            total += std::fs::metadata(&path)?.len();
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use r3s_proto::Command;
    use r3s_proto::id::{ContainerId, ImageRef};
    use r3s_proto::state::ContainerState;
    use r3s_proto::types::ContainerSpec;

    fn layout() -> (tempfile::TempDir, StoreLayout) {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::new(dir.path()).with_segment_size(4096);
        layout.ensure_dirs().expect("dirs");
        (dir, layout)
    }

    fn applied(seq_byte: u8) -> WalEntry {
        WalEntry::Applied {
            state: Box::new(ContainerState::new(ContainerSpec::new(
                ContainerId::from_bytes([seq_byte; 16]),
                "web",
                ImageRef::parse("alpine:3").expect("parses"),
            ))),
        }
    }

    fn intent() -> WalEntry {
        WalEntry::Intent {
            command: Box::new(Command::StartContainer(ContainerId::from_bytes([1; 16]))),
            actor: "operator@pi".to_owned(),
        }
    }

    #[test]
    fn appends_survive_a_reopen() {
        let (_dir, layout) = layout();
        {
            let mut wal = Wal::open(&layout, CommitPolicy::default()).expect("open");
            wal.append(&intent()).expect("append 1");
            wal.append(&applied(1)).expect("append 2");
            wal.commit().expect("commit");
        }
        let scan = scan(&layout).expect("scan");
        assert!(
            !scan.torn_tail,
            "a clean write must not look torn: {scan:?}"
        );
        assert!(scan.corrupt.is_none());
        assert_eq!(scan.records.len(), 2);
        assert_eq!(scan.records[0].seq, 1);
        assert_eq!(scan.records[1].seq, 2);
        assert!(matches!(scan.records[0].entry, WalEntry::Intent { .. }));
        assert!(matches!(scan.records[1].entry, WalEntry::Applied { .. }));
    }

    #[test]
    fn uncommitted_records_are_reported_as_a_loss_window() {
        let (_dir, layout) = layout();
        let mut wal = Wal::open(&layout, CommitPolicy::default()).expect("open");
        wal.append(&intent()).expect("append");
        assert!(wal.loss_window_bytes() > 0);
        assert_eq!(wal.synced_len(), 0);
        wal.commit().expect("commit");
        assert_eq!(wal.loss_window_bytes(), 0);
    }

    #[test]
    fn a_torn_tail_is_found_and_truncated() {
        let (_dir, layout) = layout();
        {
            let mut wal = Wal::open(&layout, CommitPolicy::default()).expect("open");
            wal.append(&applied(1)).expect("append 1");
            wal.append(&applied(2)).expect("append 2");
            wal.commit().expect("commit");
        }
        let path = layout.wal_segment(1);
        let good_len = std::fs::metadata(&path).expect("metadata").len();

        // Simulate a crash halfway through a third record: garbage that has a
        // valid header but a short payload.
        {
            let mut file = OpenOptions::new().append(true).open(&path).expect("append");
            let payload = rkyv::to_bytes::<rkyv::rancor::Error>(&applied(3)).expect("archives");
            let mut framed = encode_header(3, payload.len(), &payload).to_vec();
            framed.extend_from_slice(&payload[..payload.len() / 2]);
            file.write_all(&framed).expect("write torn");
        }

        let found = scan(&layout).expect("scan");
        assert!(
            found.torn_tail,
            "a half-written record must be reported as torn"
        );
        assert_eq!(
            found.records.len(),
            2,
            "the two intact records must survive"
        );
        assert_eq!(found.valid_len, good_len);

        assert!(truncate_torn_tail(&layout, &found).expect("truncate"));
        let after = scan(&layout).expect("rescan");
        assert!(!after.torn_tail);
        assert_eq!(after.records.len(), 2);
    }

    #[test]
    fn a_flipped_payload_bit_is_corruption_not_a_torn_tail() {
        let (_dir, layout) = layout();
        {
            let mut wal = Wal::open(&layout, CommitPolicy::default()).expect("open");
            wal.append(&applied(1)).expect("append");
            wal.commit().expect("commit");
        }
        let path = layout.wal_segment(1);
        let mut bytes = std::fs::read(&path).expect("read");
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        std::fs::write(&path, &bytes).expect("write");

        let scan = scan(&layout).expect("scan");
        let corrupt = scan.corrupt.clone().expect("corruption must be reported");
        assert_eq!(corrupt.reason, CorruptionReason::PayloadCrc);
        assert_eq!(corrupt.seq, 1);
        // A damaged record is never silently truncated away: that is data loss
        // wearing a crash's clothes.
        assert!(!truncate_torn_tail(&layout, &scan).expect("truncate is a no-op"));
    }

    #[test]
    fn a_wild_length_field_is_rejected_before_allocating() {
        let (_dir, layout) = layout();
        let path = layout.wal_segment(1);
        let mut header = [0u8; HEADER_LEN];
        header[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        header[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        header[8..16].copy_from_slice(&1u64.to_le_bytes());
        header[16..20].copy_from_slice(&0u32.to_le_bytes());
        let crc = r3s_proto::crc32c(&header[0..20]);
        header[20..24].copy_from_slice(&crc.to_le_bytes());
        std::fs::write(&path, header).expect("write");

        let scan = scan(&layout).expect("scan");
        let corrupt = scan.corrupt.expect("must be reported");
        assert_eq!(corrupt.reason, CorruptionReason::LengthOutOfRange);
        assert!(scan.records.is_empty());
    }

    #[test]
    fn segments_roll_over_and_replay_in_order() {
        let (_dir, layout) = layout();
        let mut wal = Wal::open(&layout, CommitPolicy::default()).expect("open");
        for i in 0..200u8 {
            wal.append(&applied(i)).expect("append");
        }
        wal.commit().expect("commit");
        let segments = layout.wal_segments().expect("segments");
        assert!(
            segments.len() >= 2,
            "200 records must not fit in one {}-byte segment",
            layout.segment_max_bytes()
        );
        assert!(
            std::fs::metadata(&segments[0].1).expect("stat").len() <= layout.segment_max_bytes(),
            "a segment must never exceed the cap"
        );
        let result = scan(&layout).expect("scan");
        let seqs: Vec<u64> = result.records.iter().map(|r| r.seq).collect();
        let mut sorted = seqs.clone();
        sorted.sort_unstable();
        assert_eq!(seqs, sorted, "replay order must be sequence order");
    }

    #[test]
    fn group_commit_triggers_on_every_threshold() {
        let (_dir, layout) = layout();
        let policy = CommitPolicy {
            max_delay: Duration::from_secs(3600),
            max_bytes: 4096,
            max_records: 2,
        };
        let mut wal = Wal::open(&layout, policy).expect("open");
        assert!(!wal.should_commit(), "an empty log needs no commit");
        wal.append(&intent()).expect("append 1");
        assert!(
            !wal.should_commit(),
            "one record is under the record threshold"
        );
        wal.append(&intent()).expect("append 2");
        assert!(wal.should_commit(), "the record threshold was crossed");
        wal.commit().expect("commit");
        assert!(!wal.should_commit());
    }
}
