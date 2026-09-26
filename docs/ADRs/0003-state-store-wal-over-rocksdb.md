# ADR-0003: Purpose-built WAL + mmap snapshot over RocksDB or sled

- **Status**: Accepted
- **Date**: 2026-09-25
- **Applies to**: `r3s-store`

## Context

The engine needs three very different storage workloads:

1. **Durable transactional state** (container specs, phases, volume bindings, IP allocations): a few thousand records, read constantly, written rarely, must survive power loss exactly.
2. **A content-addressed blob store** (image layers): write-once, read-rarely, large, integrity-critical.
3. **Telemetry**: high-frequency, bounded, never read after a ring wrap, and it must be readable by the CLI with zero deserialization.

The target hardware is 512 MB–8 GB of RAM over an SD card, which is the environment these general-purpose databases are worst at.

| Engine | Version | RSS floor | Problem on this hardware |
|---|---|---|---|
| RocksDB | 0.25 | ~18 MB, C++ static | LTO/compaction is pathological on flash: background compactions rewrite the whole tree, producing multi-second write stalls and SD-card wear. It also links ~40 MB of C++ into a binary whose selling point is a 6 MB RSS. |
| sled | 1.0.0-alpha.124 | ~4 MB | Unmaintained (alpha since 2019), and it was never designed for a single-writer mmap workload with a fixed-size record model. |
| reddb (`redb`) | 4.3 | ~1 MB, pure Rust | Not a fit for workload 3 (telemetry) and a heavier abstraction than workload 1 needs, but small and correct. |
| Custom | — | ~200 KB code | We own correctness. |

The decisive point: **the requirements are narrow and completely known.** One writer, ~2 000 records, fixed-size reads, one struct layout. There is nothing an LSM tree gives us that a length-prefixed WAL plus a periodically rewritten mmap snapshot does not, and the WAL is ~300 lines of testable code.

## Decision

A purpose-built store with three files:

```
state/wal/000001.log     append-only, [len u32][crc32c u32][rkyv payload]
state/snap/000042.rkyv   mmap'd, double-buffered (current + previous)
state/LOCK               flock(LOCK_EX)
```

- **Group commit**: the single writer coalesces records for up to 5 ms or 64 KiB, then one `fdatasync`. Per-record `fsync` on a Pi SD card costs 3–40 ms and destroys throughput; the bounded window is documented as a ≤ 5 ms loss window.
- **WAL record = intent**, written *before* the side effect. Recovery replays intents; every apply path is idempotent, so replay converges rather than duplicating.
- **Snapshot** when `wal > 8 MiB` or `> 2000` records. Written to a temp file and `rename(2)`d; readers keep the old fd alive until the last `Arc` drops — there is no read pause.
- **Reads** use `rkyv::access()` with `bytecheck` on mmap'd bytes, always. No `access_unchecked` except on the engine-written telemetry ring ([UNSAFE.md J-10](../UNSAFE.md)).
- **Torn tail** is truncated on open: a record without a valid CRC was never acknowledged.
- **Damage that is not a torn tail is fatal, and nothing is written.** A bad frame CRC, bad magic, or an out-of-range length in the middle of the log means an *acknowledged* record is gone; `Store::open` returns `StoreError::StoreDamaged` and `Store::compact` refuses for the same reason. The damaged bytes stay exactly where they are. Silently replaying the prefix and carrying on was rejected: it makes the engine report success for state it does not have, and the next compaction would delete the evidence. A damaged *snapshot* is not fatal — the store falls back to the previous valid snapshot, or rebuilds from the WAL, and records what it rejected. Rationale and the operator procedure: RUNBOOK.md §6.6.
- `StoreBackend` is a trait with one production implementation, so `redb` can be dropped in as an escape hatch.

## Consequences

### Positive
- ~300 lines instead of a 40 MB dependency; the whole store is auditable against a spec.
- Read cost is zero-copy and allocation-free, which is what `r3s ps` needs to be fast at 16 containers.
- We control the on-disk format, so migration is a pure function chain (`v1→v2→v3`) tested against committed fixture bytes.
- Corruption handling is explicit and recoverable rather than whatever the library does.
- A damaged store cannot be started at all, which is the one behaviour operators will push back on. It is the point: an engine that cannot open the store is a five-minute restore, and one that opens on a prefix is a silent data-loss bug report three weeks later.

### Negative / costs accepted
- We own WAL compaction, snapshot consistency, and crash recovery. These are subtle and the tests must be thorough (power-cut injection via `dm-flakey`/loopback device in CI).
- Query capability is one-level key→value plus a full scan. If the CLI ever needs "all containers with label X", we build an index. This is a deliberate limit.
- No multi-process readers of the WAL. Only the daemon reads state; the CLI talks to the daemon.

### Follow-up work
- Power-cut test harness: run writes against a loopback device with periodic `dm-flakey` drops; assert the store always reopens to a valid declared state.
- Snapshot corruption → WAL replay test with truncated and bit-flipped fixtures.
- Ship `r3s system compact` for operators.

## Alternatives considered

- **RocksDB** — rejected: RSS floor, C++ dependency, and flash-hostile compaction.
- **sled** — rejected: unmaintained.
- **redb** — rejected for the primary role, **retained as the escape hatch**. It is the most likely substitute if the WAL's correctness cost ever exceeds its benefit, and the trait boundary exists solely for that.
- **Plain JSON/TOML rewritten on each change** — rejected: not crash-safe, O(n) write per change, unbounded rewrite.
- **A separate embedded DB crate with a C dependency (`lmdb` via `heed`)** — rejected for the same RSS/link reasons as RocksDB.

## Revisit when

- The declared state grows past ~50 000 records or requires a secondary index → re-evaluate `redb`.
- Power-cut testing reveals a recovery bug we cannot fix cleanly → re-evaluate `redb` under the same trait.
