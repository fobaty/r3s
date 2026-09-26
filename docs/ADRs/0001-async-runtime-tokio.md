# ADR-0001: Tokio multi-thread over Glommio and Monoio

- **Status**: Accepted
- **Date**: 2026-09-25
- **Applies to**: `r3s-engine`, `r3s-sshd`, `r3s-image`, all async code

## Context

The board is a 1–4 core ARM64 SoC with 512 MB–8 GB of RAM. The engine must host an SSH management plane, a network control plane, image downloads, and a 1 Hz telemetry sampler **in one process**.

Three runtimes were evaluated at the versions current today:

| Runtime | Version | Model | Constraint that matters here |
|---|---|---|---|
| Tokio | 1.53 | Work-stealing multi-thread pool + blocking pool | de-facto standard; every relevant crate targets it |
| Glommio | 0.1.x | Thread-per-core, io_uring, Linux only | No Tokio-compatible ecosystem; no timer integration |
| Monoio | 0.2.4 | Thread-per-core, io_uring | No russh compatibility; no timer without an extra thread |

The binding constraint is [ADR-0002](0002-embedded-ssh-russh.md): the SSH server is russh, which is Tokio-only. Any non-Tokio runtime therefore forces a second runtime on a second core plus a copy bridge between them — on a 4-core board that is ~25 % of the machine, and a second event loop to reason about under memory pressure.

Glommio was additionally disqualified because it cannot serve the management plane at all: there is no usable TLS+SSH stack for its reactor model, and its lack of a timer wheel forces a dedicated thread for the 1 Hz sampler and backoff timers.

## Decision

Tokio 1.53, multi-thread flavor, with explicit tuning:

```rust
let rt = tokio::runtime::Builder::new_multi_thread()
    .worker_threads(min(4, max(1, available_parallelism() - 1)))
    .max_blocking_threads(4)          // default 512 is a memory hazard here
    .enable_io()                      // epoll
    .enable_time()
    .thread_stack_size(128 * 1024)     // not 2 MiB × N threads
    .global_queue_interval(Some(31))   // reduce cross-thread latency
    .build()?;
```

- `io_uring` is **not** enabled by default. `tokio-uring 0.5` exists behind the `experimental-io-uring` feature and is A/B-tested per [BASELINE.md §7](../BASELINE.md) before any default change.
- Every blocking kernel operation (mount, cgroup write loop, netlink sync path, image extraction) is `spawn_blocking` **with a semaphore permit**, so a burst of pulls cannot exhaust the blocking pool.
- Timers: exactly one global `Interval` per cadence. Never one timer per container.

## Consequences

### Positive
- One runtime, one thread budget, one cancellation model, one profiling story.
- Every crate we depend on (russh, hyper/axum, reqwest, rtnetlink) works natively.
- Tuning is in one place and is measurable; the worker-count choice is a single knob per board class.

### Negative / costs accepted
- We forgo thread-per-core determinism. A busy telemetry tick can contend with SSH work on Pi 4. Accepted because the workload is I/O-bound and bursty, not latency-deterministic.
- `io_uring`'s benefits (fewer syscalls on the extract path) are not available by default. We treat that as an unproven claim and measure it before adopting.

### Follow-up work
- Benchmark `epoll` vs `io_uring` for image extraction on Pi 4/5; record in BASELINE §7.
- Revisit if a second, throughput-only data path (telemetry ingest from many peers) becomes I/O bound enough to justify a Monoio thread on a dedicated core.

## Alternatives considered

- **Glommio 0.1** — rejected: cannot host the SSH management plane; ecosystem too small to carry the project.
- **Monoio 0.2.4** — rejected for v1: a second runtime plus bridge copies costs more than it saves at 4 cores. Retained as a Stage-4 data-plane option.
- **Tokio current-thread on a single pinned thread** — rejected: any blocking syscall stalls the entire management plane, and `spawn_blocking` from a current-thread runtime still needs a driver.
- **Threads + `epoll` directly (no async runtime)** — rejected: the SSH protocol is inherently concurrent-async; hand-rolling it would consume the whole budget of the project.

## Revisit when

- Measured p99 CLI latency exceeds the §2 target in BASELINE while a worker is idle (contention problem), **or**
- a second runtime becomes justified by a Stage-4 throughput path with a benchmark attached.
