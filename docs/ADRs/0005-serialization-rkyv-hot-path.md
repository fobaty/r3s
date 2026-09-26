# ADR-0005: rkyv on the hot path, bincode for cold payloads

- **Status**: Accepted
- **Date**: 2026-09-25
- **Applies to**: `r3s-proto`, `r3s-store`, `r3s-cli`, control plane

## Context

The engine has two very different serialization needs:

- **Hot**: the state store read on every CLI command and every reconcile tick. `r3s ps` answering "memory of container `web-1`" must not allocate or deserialize a 2 000-record snapshot. The store is already mmap'd, so the read should be a borrow.
- **Cold**: configuration, CLI API output, and control-plane messages. These cross a process or network boundary, are ≤ 64 KiB, and happen at human or control-plane frequency. Zero-copy buys nothing and self-describing formats are useful for tooling.

Version reality check: `rkyv` is on **0.8** (0.8.18 current); the long-promised 1.0 has not shipped, and 0.7.46 is the other widely-deployed line. `bincode` is at 3.0. The safe `rkyv::api` with `bytecheck` is the API we use; the older 0.7 `access_unchecked` ergonomics are not.

## Decision

- **Hot path (store, telemetry, `Snapshot`)**: `rkyv 0.8`, safe `rkyv::access::<T, rancor::Error>()` for all bytes that come from disk. `rkyv::access_unchecked` is permitted **only** for the engine-written telemetry ring ([UNSAFE.md J-10](../UNSAFE.md)), where records are fixed-size and engine-owned.
- **Cold path (config, HTTP/control-plane bodies)**: `bincode 3.0` with serde. Small, versioned, no reflection, no self-description needed on a private socket.
- **Edge (human/tooling)**: `serde_json` only at `--format json` and at the control-plane HTTP boundary.
- `r3s-proto` owns **both** the rkyv archived forms and the serde forms of every type, plus the conversions between them, so that a format change is a single-crate change and a single place to write a migration.
- Manifests and layer indexes use rkyv (they are read repeatedly during unpack and are integrity-checked). Layer blobs are raw zstd streams, never archived.

## Consequences

### Positive
- `r3s ps`/`stats` are allocation-free on the read path: the value is a borrow into the mmap.
- `bytecheck` validation is mandatory by default, which is the property that makes mmap of on-disk state safe against a corrupted or tampered file ([THREAT_MODEL §4.3](../THREAT_MODEL.md)).
- bincode for cold payloads removes rkyv's API-churn risk from the paths where it would hurt least.
- One crate owns wire types, so a format change has exactly one blast radius.

### Negative / costs accepted
- Two serialization stacks. Types need both derives and a conversion, which is more code than picking one.
- rkyv 0.8's API is still moving; we pin exactly and upgrade in a dedicated commit.
- rkyv archived types are not ergonomic to write business logic against. Business logic reads the serde form; the archived form is only for storage and zero-copy field access. This boundary must be respected or the code becomes unmaintainable.

### Follow-up work
- `r3s-proto` doc-comment stating, per type, which representation is the on-disk one and which is the API one.
- Proptest round-trips: `serde → rkyv → archived access → deserialize` equals the original for every type.

## Alternatives considered

- **`bincode` everywhere** — rejected: the hot path pays a deserialize and an allocation per CLI command, which is exactly what the design forbids.
- **`rkyv` everywhere** — rejected: no benefit on cold paths, higher risk of API churn affecting the control plane.
- **`serde_json` everywhere** — rejected: size and CPU on the store read path.
- **`postcard` / `borsh`** — considered; postcard is a fine bincode alternative but offers nothing this design needs, and borsh is tied to Solana-style layouts.
- **SQLite (`rusqlite`)** — rejected: another C dependency, and its page cache competes with the engine for the same RAM.

## Revisit when

- rkyv 1.0 ships → re-evaluate whether the serde form is still needed or can be derived from the archived form.
- The store exceeds 64 KiB records → revisit a chunked/streaming archive layout.
