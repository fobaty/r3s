# Architecture Decision Records

Every dependency, data format, and subsystem boundary decision gets one of these. "We could have used X" is the single most expensive conversation to have three stages late, so they are written *at the moment of the decision*, not at review.

## Index

| # | Title | Status | Date | Decides |
|---|---|---|---|---|
| [0001](0001-async-runtime-tokio.md) | Tokio multi-thread over Glommio/Monoio | Accepted | 2026-09-25 | Async runtime, worker model, io_uring |
| [0002](0002-embedded-ssh-russh.md) | Embedded russh server over system sshd / thruster | Accepted | 2026-09-25 | Management plane, crypto backend, channel policy |
| [0003](0003-state-store-wal-over-rocksdb.md) | Purpose-built WAL + mmap snapshot over RocksDB/sled | Accepted | 2026-09-25 | State store, telemetry buffer |
| [0004](0004-container-init-reexec.md) | Re-exec `r3s container-init` instead of forking the daemon | Accepted | 2026-09-25 | Process model, PID 1 semantics |
| [0005](0005-serialization-rkyv-hot-path.md) | rkyv on the hot path, bincode for cold payloads | Accepted | 2026-09-25 | Wire and on-disk serialization |
| [0006](0006-firewall-nftables-transactions.md) | nftables with batch transactions and named sets | Accepted | 2026-09-25 | Network policy model |
| [0007](0007-security-defaults.md) | Deny-by-default security posture, key-only auth, refused channels | Accepted | 2026-09-25 | Security baseline for v1.0 |

## Template

```markdown
# ADR-NNNN: Title

- **Status**: Proposed | Accepted | Superseded by ADR-NNNN | Rejected
- **Date**: YYYY-MM-DD
- **Deciders**: <who>
- **Applies to**: <crates / subsystems>

## Context
What forces are in play? Constraints, hardware, deadlines, threat model. Facts, not opinions.

## Decision
The choice, stated in the present tense, with the version numbers.

## Consequences
### Positive
### Negative / costs we are accepting
### Follow-up work

## Alternatives considered
Each with the specific reason it lost. "Less code" is not a reason.

## Revisit when
A concrete, checkable trigger — not "if performance is bad".
```

## Rules

1. An ADR is immutable once `Accepted`. To change a decision, write a new one that supersedes it and edit the index.
2. A dependency addition requires an ADR even if the crate is "tiny". Tree size on a device matters.
3. Version numbers in ADRs are the versions that were actually tested. A major bump of a dependency is a review event, not an automatic upgrade.
4. An ADR that only says "we picked the best one" is rejected in review. If the evaluation was close, write that it was close.
