# r3s — Technical Specification, Architecture & Implementation Blueprint

> Bare-metal-grade container + data orchestration engine for ARM64 single-board computers.
> Rust `1.98+` (edition 2024), single static-ish binary, no Docker/Podman/K3s dependency.

| Parameter | Value |
|---|---|
| Target triple | `aarch64-unknown-linux-gnu` (glibc 2.36+ on Raspberry Pi OS 64-bit "Trixie") |
| Secondary triple | `aarch64-unknown-linux-musl` (static build, for rescue/initramfs use) |
| Min kernel | **6.1** (cgroup v2 delegation), **6.11+** recommended (unprivileged overlayfs in userns, `map_files`) |
| Reference HW | Pi 5 (4×Cortex-A76), Pi 4/CM4 (4×A72), Pi 3 / Zero 2 W (4×A53) |
| Toolchain | `rustc 1.98`, `edition = "2024"`, `resolver = "3"` |
| RSS budget (idle, 16 containers) | **≤ 24 MiB** |
| Cold start (`r3sd` → first CLI command) | **≤ 60 ms** |
| Container create latency (image pre-pulled) | **≤ 45 ms p50** |
| Unsafe surface | confined to `r3s-runtime`, `r3s-store`, `r3s-net`; all other crates `#![forbid(unsafe_code)]` |

**Non-goals (v1):** Windows/macOS support, VM isolation, GPU passthrough, multi-node consensus, rootless-on-Pi-Zero, Windows containers, replacing `dockerd` CLI compatibility beyond `r3s`-native grammar.

---

## 1. HIGH-LEVEL ARCHITECTURE & DESIGN PRINCIPLES

### 1.1 Zero-cost abstraction for resource-constrained ARM64

The engine is a **single process, single binary, three roles** multiplexed onto one Tokio runtime. There is no per-function daemon, no sidecar, no message broker.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              r3sd  (PID 1-ish)                               │
│                                                                              │
│  ┌────────────┐  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐   │
│  │ SSH mgmt   │  │ Reconciler  │  │ Image engine │  │  Telemetry sampler │   │
│  │ plane      │  │ (single-    │  │ (pull/unpack)│  │  (1 Hz, cgroupfs)  │   │
│  │ russh      │  │  writer)    │  │              │  │                    │   │
│  └─────┬──────┘  └──────┬──────┘  └──────┬───────┘  └─────────┬──────────┘   │
│        │  mpsc cmd       │  intent log   │  spawn req         │ ring buf     │
│  ┌─────▼────────────────▼───────────────▼──────────────────────▼──────────┐   │
│  │                    r3s-state  (mmap snapshot + WAL)                     │   │
│  └────────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌──────────────┐  ┌───────────────┐  ┌─────────────┐  ┌──────────────────┐  │
│  │ r3s-runtime  │  │  r3s-net      │  │ r3s-store   │  │ r3s-proto (rkyv) │  │
│  │ ns/cgroups/  │  │  veth/bridge/ │  │ CAS + txn   │  │ wire types       │  │
│  │ mount/oci    │  │  nftables     │  │             │  │                  │  │
│  └──────────────┘  └───────────────┘  └─────────────┘  └──────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────┘
                          │ spawn/reap via pidfd          │ netlink
                          ▼                                ▼
              ┌───────────────────────┐        ┌──────────────────────────┐
              │ r3s container-init    │        │  r3br0 / veth pairs /    │
              │ (re-exec, one per     │        │  nftables table inet r3s │
              │  container)           │        │                          │
              └───────────────────────┘        └──────────────────────────┘
```

**P1 — Hot paths are monomorphised, not dynamic.** The reconcile loop, the cgroup writer, the netlink mutation layer, and the CLI router are *generic over a marker*, not `dyn`. Boxing is restricted to: SSH session objects, the `Executor` trait used by tests, and error formatting. `criterion` harness must show **zero** allocation in `apply_limits()` and `enqueue()`.

**P2 — Data orientation beats code orientation.** Container state is a columnar, fixed-stride, `#[repr(C)]` record written into a memory-mapped ring. `r3s ps` reads the mmap directly and formats in place — the CLI never deserializes a full store snapshot to answer "how much RAM is container `web-1` using?".

**P3 — One writer, many lock-free readers.** The state store is single-writer (the reconciler task). Readers (SSH handlers, telemetry, future control-plane) use `rkyv` archived views over a read-only mmap plus an `arc_swap` pointer to the current snapshot. No `RwLock` on the hot path.

**P4 — Syscalls are batched.** Writing 11 cgroup control files for 11 containers = 11 write syscalls, not 121. The `CgroupWriter` coalesces into a single transaction buffer and issues one `writev`-equivalent per cgroup directory. Measured budget: ≤ 3 syscalls per container mutation.

**P5 — Kernel is the source of truth; the engine is a reconciler.** The engine never assumes its own bookkeeping is correct. Every 1 s tick it samples `cgroup.events`, `/proc/<pid>/stat`, and netlink, then drives *observed* state toward *declared* state (see §3.1.4). A `kill -9` of `r3sd` followed by a restart must converge to the declared state without manual cleanup.

**P6 — Boring, tuned, measured.** `opt-level = 3`, `lto = "fat"`, `codegen-units = 1`, `panic = "abort"` (in the container-init path only; the daemon uses unwind so a single bad container cannot take the node down), `strip = "symbols"`, `target-cpu = native` per-SKU build matrix. Every claim of "ultra-low memory" in this document is an exit-criterion in §5, not an aspiration.

**P7 — Error handling is split.** `thiserror` typed enums in library crates (matchable, no allocation on construction). `anyhow` only in `main`/CLI for context accumulation. Every fallible kernel boundary converts `Errno` → a typed variant carrying `(path, errno)` because `ENOSPC` on overlay upperdir and `EBUSY` on cgroup delete require *different* recovery.

**P8 — Security defaults are not optional.** Read-only rootfs, dropped capability bounding set, `no_new_privs`, seccomp filter, no-new-privileges on the SSH plane, and password auth disabled unless explicitly enabled with a warning. See §1.2.6.

### 1.2 Isolation mechanism

Everything below is implemented **in-process, in Rust, via direct syscalls**. No `runc`/`crun`/`containerd`/`shim` process tree.

| Layer | Kernel primitive | Rust implementation | Crate |
|---|---|---|---|
| Namespace isolation | `unshare(2)`, `setns(2)` | `nix::sched::{unshare, setns}` | `nix 0.31` |
| PID isolation | `CLONE_NEWPID` + re-exec + pidfd | `nix::sched::unshare`, `rustix::process::pidfd_open` | `nix`, `rustix 1.1` |
| Mount isolation | `CLONE_NEWNS` + `pivot_root(2)` | `nix::mount`, `nix::unistd::pivot_root` | `nix` |
| Filesystem view | OverlayFS, `MS_RDONLY` remount, idmapped mounts | `nix::mount::mount` + `mount_setattr(2)` | `nix` (feature `mount`) |
| Resource limits | cgroup v2 (`memory`, `cpu`, `pids`, `io`, `hugetlb`) | custom cgroupfs writer (see §1.2.2) | `std::fs` + `nix` |
| Capability model | `prctl(2)`, `capset(2)`, `PR_CAP_AMBIENT` | `capctl 0.2` + `nix::sys::prctl` | `capctl`, `nix` |
| Mandatory access control | seccomp-BPF (`SECCOMP_SET_MODE_FILTER`) | filter assembled from OCI `linux.seccomp` | `seccompiler 0.5` |
| Optional MAC | Landlock LSM (ABI v4) | `landlock 0.4` | `landlock` |
| Network isolation | netns + veth + bridge + nftables | `rtnetlink 0.23`, `nftables 0.6` | `rtnetlink`, `nftables` |
| Time | `CLONE_NEWTIME` + `time_namespaces(7)` | `nix::sched::unshare` + `timensat` | `nix` |

#### 1.2.1 Namespace matrix per container

| Namespace | Always | Conditional | Notes |
|---|---|---|---|
| `mnt` | ✔ | | `pivot_root` into the overlay merged dir |
| `pid` | ✔ | | init re-exec; container PID 1 is `r3s container-init` |
| `net` | ✔ | `--net=host` disables | veth end moved in, `lo` brought up |
| `uts` | ✔ | | hostname from `hostname` field |
| `ipc` | ✔ | | |
| `user` | ✔ (rootless mode) | disabled in `rootful` mode | uid/gid map written by parent, `setgroups=deny` |
| `cgroup` | ✔ | | namespaced view; the cgroup itself is created by the parent before spawn |
| `time` | | `--time-offset` | offsets only, never realtime |

`CLONE_NEWTIME` requires ≥ 5.6 and is opt-in because it silently affects `CLOCK_REALTIME` reads in the container; exposing it as a flag avoids surprising behaviour.

#### 1.2.2 cgroup v2 delegation protocol (critical ordering)

cgroup v2 has two rules that break naive implementations:

1. **The "no internal processes" rule** — a cgroup with children in `cgroup.subtree_control` must have no processes in its own `cgroup.procs`. Enabling controllers on a leaf that has processes returns `EBUSY`.
2. **Controllers must be enabled in the parent before the child is populated.**

Therefore the engine mounts a private hierarchy and creates a **three-level tree**, enabling controllers *before* moving any process:

```
/sys/fs/cgroup                              (mounted by engine: cgroup2, own ns)
└── r3s.slice                               engine.slice      ← controllers enabled here, no procs
    ├── r3s-system.slice                    engine overhead
    └── <slice>.slice                       one per QoS class (default: "default")
        └── r3s-<slice_id>-<ctr_id>.scope   one per container
```

Enablement sequence (idempotent, retried on `EBUSY` with 5 ms backoff, max 50 ms):

```text
root/cgroup.controllers            → read available (must contain cpu,memory,pids,io)
root/cgroup.subtree_control        → write "+cpu +memory +pids +io"     (once)
r3s.slice/cgroup.procs             → must be EMPTY (assert; engine puts nothing here)
r3s.slice/cgroup.subtree_control   → write "+cpu +memory +pids +io +cpuset"
r3s-system.slice/cgroup.procs      → write "<engine_pid>"   (so engine is accounted, not root)
```

Per-container limits are then written to `scope/` files *before* the child's PID is placed:

| Controller | File | Value written by `ResourceLimits` |
|---|---|---|
| memory | `memory.max` / `memory.high` | `limit_bytes` / `soft_bytes` |
| memory | `memory.swap.max` | `0` by default (SD-card swap is death) |
| memory | `memory.oom.group` | `1` (kill all, not just the offender) |
| cpu | `cpu.max` | `"<quota_us> <period_us>"`, e.g. `50000 100000` |
| cpu | `cpu.weight` / `cpuset.cpus` | `nice` class; cpuset from `cpuset` field |
| pids | `pids.max` | `max_pids` (default 512) |
| io | `io.max` | `"<dev> rbps=<r> wbps=<w> riops= wiops="` |
| hugetlb | `hugetlb.max` | `0` on ARM SBCs |

Reading is equally cheap: `memory.current`, `memory.events`, `cpu.stat`, `pids.current`, `io.stat` are single `read()` calls into a reused `Vec<u8>` — no `sysinfo` polling of `/proc` walking (which is O(processes) and dominates the telemetry budget on a Pi 3).

#### 1.2.3 Network isolation

- **Bridge**: `r3br0` (802.3, no IP) on the host, `r3br0` in the container netns with the container's IP. Default CIDR `10.42.0.0/16`, allocator = first-fit over a `Mutex<BTreeSet<u16>>`; deterministic and O(log n), no dependency.
- **veth**: `veth<ctr8>`(host) ↔ `eth0`(ns). `veth` names are ≤ 15 chars (IFNAMSIZ) → `v{ctr_index:04x}{suffix:04x}`.
- **Addressing**: static per container, written via netlink `RTM_NEWADDR` on the in-ns interface (not `ifconfig`/shell-out).
- **NAT/forwarding**: one nftables table `inet r3s`, with a `chain r3s-postrouting` containing a single `masquerade` rule for the CIDR — **not** per-container rules. Per-container filtering is expressed as `filter` chains with `ct state established,related accept` and named sets. This is the single most important performance decision in the net layer: a per-container chain set on a Pi's softirq budget is measurably worse than a named-set + chain-hybrid, and 200 containers should still be 6 nftables objects.
- **Atomicity**: all rule changes go through `NFT_MSG_BATCH_BEGIN`/`COMMIT` so a half-applied ruleset is impossible. The `nftables 0.6` crate exposes `Transaction::begin/commit` for this.
- **Cleanup invariant**: every netns object is recorded in the state store *before* creation, so a crash mid-`RTM_NEWLINK` is garbage-collected by the reconciler's `sweep_orphans()`.

#### 1.2.4 Read-only rootfs & bind mounts

- The container rootfs is an **overlay mount** at `containers/<id>/rootfs` (`lowerdir` = image layers colon-joined, `upperdir` = `.../upper`, `workdir` = `.../work`).
- `index=off`, `metacopy=off`, `xino=off` — indexed overlayfs costs an extra inode lookup per path component and buys nothing when lowerdirs are immutable. This is measurable on ext4 + SD card.
- The **writable layer is then remounted read-only for the process view** (`mount_setattr(2)` with `AT_RECURSIVE` on the container root, kernel ≥ 5.12) and a tmpfs or an explicit volume is mounted at each declared writable path. This is a stronger guarantee than `overlay` with `MS_RDONLY` on upperdir, which is advisory under some error paths.
- `/proc`, `/sys` (read-only, `ro` mount of the *container's* sysfs), `/dev` (`tmpfs` + bind of `null`, `zero`, `full`, `random`, `urandom`, `tty`), `/etc/resolv.conf`, `/etc/hostname`, `/etc/hosts` are bound per spec.
- `MS_NOSUID|MS_NODEV|MS_NOEXEC` on every bind that does not explicitly opt out (`--cap-drop`-style flags exist for this: `nosuid_bind`, `dev_bind`, `exec_bind`).

#### 1.2.5 Zero external-daemon guarantee

There is no `docker`, `podman`, `containerd`, `runc`, `crun`, `iptables`, `ip`, `nft`, `mount`, `tar`, or `rsync` process ever spawned. The only child processes r3s creates are (a) container payloads and (b) itself, re-executed as `r3s container-init`. This is enforced by a CI test that runs the daemon with a `PATH` containing only a directory of symlinks to `/bin/false` named after every one of those tools, then asserts full functionality.

#### 1.2.6 Defence in depth (defaults)

`pivot_root` + `no_new_privs` + seccomp + capability bounding set (`cap_set` only when the spec requests them) + optional Landlock. If the kernel lacks Landlock (`< 5.13`), the engine logs a capability line in `r3s info` and continues — degraded security is reported, never silently assumed.

### 1.3 Internal data engine

Three distinct stores, three distinct access patterns. Mixing them is the single most common design mistake in this class of system.

#### 1.3.1 Image store (immutable, content-addressed, append-mostly)

```
/var/lib/r3s/images/
├── blobs/sha256/<aa>/<full-64-hex>          # compressed layer blobs (zstd-19, or gzip from registries)
├── index.rkyv                              # rkyv-archived map: digest -> {size, media, parent}
└── refs/<repo>:<tag>                       # symlink to index entry, or tiny rkyv file

/var/lib/r3s/containers/<ctr_id>/
├── upper/  work/                            # overlayfs upper/work (same fs => required)
├── rootfs/                                 # the overlay mount point
├── config.rkyv                             # rkyv ContainerSpec (source of truth for re-create)
└── oci.json                                 # OCI runtime spec, exported for runc/ctr compatibility
```

- **Integrity**: sha256 over the *uncompressed* tar stream, verified streaming during unpack (never buffered to disk). Layer order is stored as an ordered `Box<[Digest]>`, resolved to a colon-joined `lowerdir` string, with a hard length check (Linux caps a single `lowerdir` at ~50 layers on some kernels; we detect `ENAMETOOLONG`/`EINVAL` and fall back to a "lowerdir-of-lowerdirs" single layer).
- **Compression**: `zstd 0.14` (C, but ~350 KB and orders of magnitude faster than gzip on Cortex-A53). Pure-Rust `ruzstd` is the fallback if the node must be fully static/musl.
- **Extraction hardening**: reject absolute paths, `..` traversal, symlinks escaping the root, hardlinks outside, device nodes unless whitelisted, and setuid bits unless explicitly requested. Path traversal on a shared SD card is a privilege-escalation primitive; this is enforced in `LayerUnpacker` with explicit error variants (`PathEscape`, `ForbiddenNodeType`, …) and is fuzz-tested (§5, Stage 3).

#### 1.3.2 Transactional state store (single-writer WAL + mmap snapshot)

```
/var/lib/r3s/state/
├── wal/000001.log        # append-only, length-prefixed, CRC32C per record
├── snap/000042.rkyv      # mmap'd zero-copy snapshot (double-buffered: current + previous)
└── LOCK                  # flock(LOCK_EX) — single engine instance per node
```

| Concern | Decision |
|---|---|
| Durability | Group commit: the writer coalesces records for up to 5 ms or 64 KiB, then one `fdatasync`. Per-commit `fsync` on a Pi SD card costs 3–40 ms and destroys throughput; the 5 ms window keeps the loss window bounded and is documented. |
| Ordering | All mutations are intents (`ApplySpec`, `StopContainer`, `AttachVolume`) written **before** the side effect, so a crash mid-apply is replayed idempotently. |
| Reads | Snapshot is `rkyv`-archived. `store.get::<ContainerSpec>(id)` returns `&ArchivedContainerSpec` with **no copy**; only CLI formatting allocates. |
| Compaction | Snapshot when `wal > 8 MiB` or `> 2000` records. Snapshot write is `write` + `rename` (atomic) and readers keep serving the old fd until refcount drops — no read pause. |
| Corruption | CRC32C per WAL record *and* per frame header. A torn tail is truncated on open (standard, safe: it was never acknowledged). A **corrupt snapshot** falls back to the previous one, or to WAL replay, and the rejection is reported. Damage **in the middle of the WAL** is fatal: `open` and `compact` both refuse with `StoreError::StoreDamaged`, writing nothing, so the damaged bytes survive for the operator (RUNBOOK §6.6, ADR-0003). |
| Schema migration | `store_version` in the snapshot header; migrations are pure functions `v1 -> v2 -> v3` executed on load, tested with fixture bytes committed to the repo. |

**Rejected**: RocksDB (C++ link, ~18 MB RSS floor, and its LSM compaction fights a 100 MB/s SD card), sled (unmaintained, `1.0.0-alpha.124`, known durability issues). `redb 4.3` is the designated fallback if Stage 3 slips — its pure-Rust, mmap-based, single-file ACID model is a good fit and swapping it in is gated behind the `StoreBackend` trait so the reconciler is unaffected.

#### 1.3.3 Telemetry (lock-free, mmap, fixed-stride)

```
/var/lib/r3s/telemetry/<ctr_id>.ring   # mmap, 4096 × MetricSample (32 B) = 128 KiB + 32 B header
```

One `MetricSample` (`#[repr(C)]`, 32 bytes: `sampled_at_mono_ns u64`, `memory_current u32`, `cpu_usage_us u32`, `pids u16`, `io_read_bytes u32`, `io_write_bytes u32`) per second per container, written by a single sampler task at a fixed tick (default 1 Hz, adaptive down to 0.2 Hz when 16+ containers run), read by the CLI with zero deserialization. Retention is a ring, not a GC policy: memory is bounded by construction. Prometheus exposition is generated on demand by walking the ring — no separate exporter process, no `/metrics` HTTP port unless explicitly enabled.

Widths are chosen for the hardware, not for elegance: 32-bit counters saturate at 4 GiB — a node-wide event on a Pi — and 32-bit fields keep a sample at 32 bytes so 4096 of them plus the header land inside three 128 KiB pages, which is what the CLI maps on a `stats` call. The stride is a `const _: () = assert!(STRIDE == 32)` in `r3s-store::ring`, so a field width change is a compile error rather than a silently different on-disk format. A missing `memory_max` is deliberate: it is read from `memory.max` at sampling time, not accumulated in the ring.

The two cursors in the ring header are *aliased* `AtomicU64`s in the mapping, not copies taken at open (`UNSAFE.md` J-11). A reader that snapshotted them would report an empty ring for a running container forever, which is exactly the bug the type exists to prevent; the release store after the record bytes and the acquire load before them are what make a torn cursor unobservable.

---

## 2. CORE RUST 1.98+ FRAMEWORK & CRATE RESEARCH

### 2.0 Verdict table (versions verified against crates.io, 2026-09)

| Module | Selected | Version | Rejected | Rationale (one line) |
|---|---|---|---|---|
| Async runtime | **tokio** | `1.53` | glommio, monoio | russh is tokio-only; io_uring via optional `tokio-uring`; tuned multi-thread beats thread-per-core at 4 cores. |
| SSH server | **russh** | `0.63.3` | thruster, thrussh | russh is a low-level SSH implementation (thruster is HTTP middleware — wrong layer entirely). |
| Syscall bindings | **nix** + **rustix** | `0.31.3` / `1.1.5` | raw `libc` everywhere | typed `Errno`; raw `libc` only in the `pre_exec`/init paths where async-signal-safety forbids anything else. |
| OCI spec types | **oci-spec** | `0.10` | hand-rolled | schema fidelity for `r3s run --oci` interop. |
| State store | **custom WAL+mmap** (redb fallback) | — | rocksdb `0.25`, sled alpha | RSS and SD-card compaction behaviour. |
| Serialization (hot) | **rkyv** | `0.8.18` | bincode for hot paths | true zero-copy archived reads from mmap. |
| Serialization (cold) | **bincode** | `3.0` | JSON | config/CLI/API payloads only. |
| HTTP (cluster) | **axum** / **hyper** | `0.8.9` / `1.11.1` | actix | smallest sane hyper 1.x surface; tower middleware for auth. |
| Netlink | **rtnetlink** + **rtnetlink-packet-route** | `0.23` / `0.33` | shelling out to `ip` | async, typed, scriptable. |
| Firewall | **nftables** | `0.6` | iptables crate (deprecated) | native nft, batch transactions. |
| Errors | **thiserror** (lib) + **anyhow** (bin) | `2.0` / `1.0` | anyhow in libraries | matchable errors, no context bloat. |
| Crypto (SSH) | **ring** | `0.17` | aws-lc-rs `1.18` | `ring` cross-compiles to aarch64-musl with no cmake/clang toolchain; aws-lc-rs needs both. |
| Seccomp | **seccompiler** | `0.5` | libseccomp | pure Rust, no libseccomp build dep. |
| LSM | **landlock** | `0.4` | — | cheap, kernel-optional hardening. |
| Term/CLI | **reedline** | `0.51` | rustyline, linefeed | async-friendly, history, hints, and no `libc`-heavy surprises. |

### 2.1 Async runtime: Tokio vs Glommio vs Monoio

**Decision: Tokio 1.53, multi-thread, worker count = `min(4, max(1, ncores - 1))`, with a dedicated blocking pool sized 4.**

Reasoning:

- **Glommio is disqualified by the requirements.** It is Linux-only (fine), io_uring-only (fine), and *thread-per-core cooperative* (fine) — but it has no TLS stack that russh can use, no `tokio`-compatible process/PTY integration, and its ecosystem (and its own maintenance cadence) is far too small to carry an SSH management plane. Its no-timer model also forces a dedicated timer thread.
- **Monoio is a data-plane option, not an engine option.** `monoio 0.2` is a genuinely excellent thread-per-core io_uring runtime and is the right answer for a *single-purpose* high-throughput workload. It conflicts with russh's Tokio dependency, so using it means running a second runtime on its own core with `async-channel` bridges between them. That costs a core and a copy. **Verdict: not in v1.** Revisit in Stage 4 only if the telemetry/ingest path is measured to be I/O bound, in which case it gets its own thread + a lock-free SPSC ring — not a second architecture.
- **Tokio tuning is the actual differentiator**, and the defaults are wrong for a Pi:
  - `worker_threads = ncores - 1` on a Pi 5 leaves one core for the SD-card I/O path; on a Pi 3 (1 core) it degrades to 1 worker.
  - `max_blocking_threads = 4`: mount, cgroup, netlink-sync, and image-extract all block; default 512 threads is a memory hazard.
  - **`io-uring` is opt-in, not default**: enable `tokio-uring 0.5` behind a `experimental-io-uring` cargo feature and A/B it. On Raspberry Pi OS the kernel is not io_uring-tuned, and `io_uring` on some ARM boards has regressed under the 5.10/6.6 backports. Default stays epoll.
  - All blocking kernel work goes through `tokio::task::spawn_blocking` *with a semaphore permit*, so a burst of 200 `image pull`s cannot exhaust the blocking pool.
  - `LruCache`/timer wheels: one global `Interval::tick` at 1 Hz, never one timer per container (200 timers on a Pi 3 is measurable jitter).

```toml
# Cargo.toml (root)
[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
panic = "unwind"          # daemon: one bad container must not kill the node
strip = "symbols"
debug = 1                 # keep line tables for the crash reporter
incremental = false

[profile.release.package."*"]
opt-level = 3             # deps included in LTO; no `debug-assertions`

[profile.dist]
inherits = "release"
panic = "abort"           # container-init + client CLI only
strip = true
```

### 2.2 SSH server & CLI: russh, not thruster

`russh 0.63.3` (Aug–Sep 2026) is the pragmatic choice:

- **RPITIT handler trait**: `fn data(&mut self, …) -> impl Future<Output = Result<(), Self::Error>> + Send` — no `#[async_trait]` boxing, no macro, and the future is a concrete type the compiler can inline. This is exactly the "precise capturing in `impl Trait`" the design brief asks for, and it is *already in the dependency*, not something we hand-roll.
- **Keys via `russh::keys`**: host key generation, `authorized_keys` parsing, and fingerprinting come from `russh-keys`; we do not implement ed25519/RSA/ECDSA verification.
- **Crypto backend**: enable the `ring` feature. `aws-lc-rs` is faster on A76 but requires a C toolchain *and* BoringSSL cross-compilation, which is a hard dependency on the operator's build machine. Behind a `crypto-aws-lc` cargo feature, verified in CI.
- **Algorithms**: negotiate modern-only (`sntrup761x25519-sha512@openssh.com`, `mlkem768x25519-sha256`, `curve25519-sha256`, `chacha20-poly1305@openssh.com`, `rsa-sha2-512`). Explicitly exclude `*@ssh-rsa` (SHA-1) and `diffie-hellman-group1-sha1` via `Preferred`, and drop `ssh-rsa` signature fallback.
- **PTY**: russh negotiates the PTY but the *daemon* must own the slave fd. Use `nix::pty::openpty` (feature `term`), apply `Winsize` from `pty_request` and update on `window_change_request` with `ioctl(TIOCSWINSZ)`.
- **Inactivity**: `inactivity_timeout = 900 s`, `max_auth_attempts = 3`, constant-time rejection via `Config::auth_rejection_time` (russh does not do this by default — a real timing-attack surface we must not skip).

**Why thruster is categorically wrong here**: `thruster 1.3` is an *HTTP* middleware framework (a Rustls-terminated HTTP server). Using it would mean implementing SSH transport, KEX, and userauth ourselves. It would add ~0% of the required functionality. Documented here only to close the question.

**Rejected alternative**: exposing an HTTP API + a separate `sshd` with a forced command. Rejected because (a) it requires OpenSSH on the node, breaking the "one binary" thesis, (b) forced-command wrappers are fragile (`$SSH_ORIGINAL_COMMAND` quoting, `~` expansion, TTY semantics), and (c) it forfeits the embedded, in-process auth + RBAC + audit story that is a core requirement.

### 2.3 Low-level runtime bindings

`nix 0.31.3` with features `["sched","fs","process","mount","user","signal","hostname","term","resource","net","socket"]` (nix has **no** default features and **no** cgroup bindings — an intentional omission upstream, and the reason §1.2.2 is hand-written).

API facts that materially shape the design (verified against the 0.31.3 source):

- `nix::sched::{unshare(CloneFlags) -> Result<()>`, `setns<Fd: AsFd>(fd, CloneFlags)`.
- `nix::sys::wait::waitpid(pid, Option<WaitPidFlag>) -> Result<WaitStatus>` — no more `siginfo` argument.
- `nix::unistd::fork` is **`pub unsafe fn`** and returns `ForkResult`; the safety contract is *async-signal-safe only until `execve`*, which is precisely why the container payload is started by **re-exec** (`r3s container-init`) rather than by doing container setup in the forked child. This is the same reason runc does it.
- `nix::mount::mount(source, target, fstype, flags, data)`, `umount2(target, MntFlags)`, `nix::unistd::pivot_root(new_root, put_old)`.
- `nix::sys::sysinfo::sysinfo()` is the only portable RAM query; for container RAM we read cgroup files instead (correct on v2, where host RAM is irrelevant to a limit).

**`rustix 1.1.5`** is added for the things nix does not expose: `pidfd_open`/`pidfd_send_signal` (process lifecycle without PID reuse races), `mount_setattr` (recursive read-only remount), `open_tree`/`move_mount` (detached mount trees, used for the `overlay` fast path and for `--volumes-from` clones), and `statmount` (detecting a leftover mount after a crash).

`caps 0.9`-style crates are not used; `capctl 0.2.4` gives `prctl`/`capset`/`ambient` with a type-safe bounding-set API, and seccomp is `seccompiler 0.5`.

### 2.4 State store

Covered in §1.3.2. The decision is a **purpose-built store** because none of the off-the-shelf embedded engines are right for a 512 MB–1 GB Pi with a slow, non-ideal SD card: RocksDB is heavy and its compaction is pathological on flash; sled is unmaintained. `redb 4.3` is the sanctioned escape hatch behind a `StoreBackend` trait.

### 2.5 Serialization & node networking

- **`rkyv 0.8.18` is the current stable line** (0.7.46 remains widely deployed; a 1.0 has been long-promised and is *not* released). Use the **safe** `rkyv::access::<T, rancor::Error>` API — `bytecheck` validation is on by default and is non-negotiable when parsing mmap that a compromised process might have written. Reserve `access_unchecked` for the telemetry ring, whose records are engine-written only, and gate it behind an audited `unsafe` block with a static invariant comment.
- **`bincode 3.0`** for anything crossing the CLI/HTTP boundary where a self-describing format is not needed. `serde_json` only at the human/tooling edge.
- **axum 0.8.9 / hyper 1.11.1** for the *optional* cluster control plane (`--enable-control-plane`, default off, binds `127.0.0.1` only unless TLS + mTLS is configured). axum is used rather than a bare hyper server because the tower middleware chain gives us request-size limits, timeouts, and structured access logs nearly free.
- For node-to-node streams (Stage 4), prefer a 8-byte length prefix + rkyv over QUIC initially: fewer moving parts, and reconnection logic is trivial. QUIC (`quinn 0.11`) is the documented upgrade path if mesh/handshake latency becomes measurable.

---

## 3. COMPLETE MODULE SPECIFICATION (ТЗ)

### 3.0 Workspace layout

```
r3s/
├── Cargo.toml                    # workspace, [workspace.dependencies] only
├── .cargo/config.toml            # cross targets + linker flags
├── crates/
│   ├── r3s-proto/       # rkyv wire + on-disk types, OCI mapping, digest. forbid(unsafe_code)
│   ├── r3s-store/       # WAL, snapshot, CAS, ring buffer.        [unsafe: mmap only]
│   ├── r3s-runtime/     # ns, cgroups, mounts, capabilities, seccomp, init. [unsafe]
│   ├── r3s-net/         # netlink, bridge/veth, address alloc, nftables.  [unsafe: netlink]
│   ├── r3s-image/       # registry client, manifest, unpack, verify.     forbid(unsafe_code)
│   ├── r3s-engine/      # reconciler, scheduler, health, config.        forbid(unsafe_code)
│   ├── r3s-cli/         # command grammar, renderers (table/json), RBAC. forbid(unsafe_code)
│   ├── r3s-sshd/        # russh server + handler + PTY + REPL.          forbid(unsafe_code)
│   └── r3s-bin/         # the single `r3s` binary (daemon|init|client subcommands)
├── tests/
│   ├── integration/     # nextest, requires root + real kernel namespaces
│   ├── fixtures/        # golden WAL/snapshot bytes for migration tests
│   └── ondevice/        # script run on a real Pi in CI (self-hosted runner)
└── docs/                # this document
```

Dependency rule: `r3s-proto` depends on nothing internal; `store → proto`; `runtime/net/image → proto`; `engine → all`; `cli/sshd → engine`; `bin → all`. No cycles, enforced by `cargo metadata` in CI.

### 3.1 `r3s-engine` — the orchestrator

#### 3.1.1 Public surface

```rust
pub struct Engine { /* … */ }

impl Engine {
    pub async fn bootstrap(cfg: EngineConfig) -> Result<Arc<Self>, EngineError>;
    pub async fn run(self: Arc<Self>) -> Result<(), EngineError>;   // until shutdown
    pub async fn shutdown(&self) -> Result<(), EngineError>;

    pub async fn submit(&self, req: Command) -> Result<CommandAck, EngineError>;
    pub fn snapshot(&self) -> Arc<StateSnapshot>;                   // rkyv, zero-copy
    pub fn health(&self) -> HealthReport;                           // borrowed, no alloc
}

#[non_exhaustive]
pub enum Command {
    CreateContainer(Box<ContainerSpec>),
    StartContainer(ContainerId),
    StopContainer { id: ContainerId, grace: Duration },
    KillContainer { id: ContainerId, signal: Signal },
    RemoveContainer(ContainerId),
    AttachVolume { container: ContainerId, volume: Box<VolumeSpec> },
    DetachVolume { container: ContainerId, target: PathBuf },
    UpdateLimits { id: ContainerId, limits: ResourceLimits },       // live, no restart
    PullImage(ImageRef),
    PruneImages(ImagePrunePolicy),
    SetRestartPolicy { id: ContainerId, policy: RestartPolicy },
}
```

`Command` is `rkyv`-serializable and is the *only* way to mutate state. Nothing else in the codebase writes the store. This is what makes the audit trail complete.

#### 3.1.2 Core structures

```rust
pub struct EngineConfig {
    pub root: PathBuf,                 // /var/lib/r3s
    pub ssh: SshConfig,                // bind addr, authorized_keys, allow_password
    pub limits: NodeLimits,            // global ceilings (see §3.1.3)
    pub network: NetworkConfig,        // bridge name, cidr, dns, mtu
    pub scheduler: SchedulerConfig,    // worker threads, tick interval
    pub storage: StorageConfig,        // driver (overlay), zstd level, wal limits
    pub telemetry: TelemetryConfig,    // sample interval, retention
}

pub struct ContainerState {
    pub id: ContainerId,               // [u8; 16] or short string; rkyv-friendly
    pub spec: ContainerSpec,
    pub phase: Phase,                  // enum, see §3.1.5
    pub pid: Option<u32>,
    pub exit: Option<ExitRecord>,      // code | signal, ts, oom_killed flag
    pub restart_count: u32,
    pub health: HealthReport,
}

pub enum Phase { Pending, Creating, Running, Paused, Stopping, Exited, Failed }
```

`HealthReport` is `#[repr(C)]`, fixed-size, `Copy` — it is the value type stored in the telemetry ring and returned by `r3s ps` without any formatting allocation.

#### 3.1.3 Scheduling & resource policy

- **Admission control**: `NodeLimits { max_containers, total_memory_bytes, total_pids, reserved_memory_bytes }`. A `CreateContainer` that would exceed any ceiling is rejected *before* any side effect and with a structured error naming the exhausted resource. Overcommit for CPU is allowed (quota), overcommit for memory is not (Pi boards OOM the whole SoC; `memory.swap.max=0` makes an overcommit fatal to the container, correct, and much better than taking the node down).
- **Reserved headroom**: the engine puts *itself* in `r3s-system.slice` with `memory.max = reserved_memory_bytes` (default 96 MiB) and `cpu.max` of 1 core-equivalent share, guaranteeing the management plane survives a hostile workload.
- **Slices**: containers are assigned to a slice (`default`, `realtime`, `batch`) — a two-level cgroup tree — so an entire class can be reprioritised atomically. This is what makes the `cpu.max` update path O(slices), not O(containers).
- **Placement**: single node, so placement is trivially local, but the *interface* is `PlacementConstraint` (memory/cpu/disk affinity) so Stage 4 multi-node does not require an API break.

#### 3.1.4 Reconciliation loop (the heart)

```
loop {
    sample_observed()            // cgroup.events, /proc/<pid>, netlink membership  (~1 ms/100 ct)
    let desired = snapshot.declared();      // rkyv, zero-copy
    let diff    = diff(observed, desired);
    for action in diff.actions().take(MAX_ACTIONS_PER_TICK /*32*/) {
        write_intent(action);   // WAL, group-committed  → crash-safe
        apply(action).await;    // idempotent; may fail, recorded as `retry_after`
    }
    persist_snapshot_if_needed();
    sleep_until(next_tick);     // interval, NOT sleep(1) — compensates for tick cost
}
```

- `apply` **must be idempotent**: "ensure cgroup exists with these limits", "ensure veth exists and is up", "ensure PID is alive". A crash between `write_intent` and `apply` is recovered by replay.
- `sweep_orphans()` removes netns/cgroup/mount objects under `/var/lib/r3s/**` with no corresponding entry in the declared state, and it is the *only* place that performs destructive cleanup — never the create path (which would race a concurrent create).
- Backoff: failed actions get `retry_after = min(30 s, 100 ms * 2^attempts)` with ±20 % jitter. No tight retry loops (a failing netlink call in a hot loop is how you melt a Pi).

#### 3.1.5 Lifecycle state machine

`Pending → Creating → Running ⇄ Paused → Stopping → Exited → (Removed | restart per policy)`

Legal transitions are a match in one place (`fn legal(a: Phase, b: Phase) -> bool`), unit-tested as a table. Any `submit` that would produce an illegal transition returns `EngineError::IllegalTransition` and writes nothing. Restart policy is `No | OnFailure | Always | UnlessStopped` with exponential backoff capped at 60 s and a 5-restarts-per-10-min rate limit per container (protects against crash-loop-storm on a 512 MB node).

#### 3.1.6 Process lifecycle

- `pidfd_open` on the payload PID after spawn; the reap loop waits on the pidfd via `tokio::signal::unix` + a `tokio::process::Child`, so **PID reuse cannot cause a signal to hit the wrong process**. SIGKILL escalation is driven by pidfd signalling, not by `kill(pid)`.
- `OOMKilled` is detected by reading `memory.events` (`oom_kill` counter) before reaping, so `r3s inspect` can report *why* a container died. This single feature removes the single most common support question in container runtimes.
- Stdin/stdout/stderr: for SSH `exec` with a PTY, the slave fd is wired to the SSH channel; without a PTY, stdout/stderr are separate pipes multiplexed into SSH extended-data (stderr, code 1). Attach/detach of a log follower is an optional subscription over a broadcast channel.

### 3.2 `r3s-sshd` / `r3s-cli` — the management plane

#### 3.2.1 Command grammar

Native r3s grammar, deliberately **not** a Docker-CLI compatibility shim (a shim would import every wart). The parser is hand-written over a `&str` with a cursor — no `clap` in the hot path, no allocation for tokenization, and no ambiguity. `clap` is used only for the standalone `r3s --help` client.

```
r3s <object> <verb> [flags]

image pull REF                    image list [--format table|json]
image prune [--filter ...]         image inspect REF
container run --name N IMAGE [args…]
container ls [--all] [--format …]  container inspect ID
container start|stop|restart ID    container kill ID --signal SIG
container rm ID [--force]          container logs ID [-f] [--tail N]
container stats [--no-stream]      container top ID
container exec [-it] ID CMD [args…]
volume create|ls|rm NAME          volume inspect NAME
network ls                        network inspect NAME
system info|version|status         system prune [--volumes]
limit set ID --memory 256m --cpu 500m --pids 128
cluster join|leave|ls             (Stage 4, gated)
```

- **Output**: default is a stable, aligned table; `--format json` emits JSON to stdout **and nothing else** (all diagnostics go to stderr, always). Machine-readability is a hard requirement, not a nicety.
- **Exit codes**: `0` ok, `1` runtime error, `2` usage, `3` not found, `4` conflict, `5` resource exhausted, `10` auth/RBAC denial. Documented and tested.

#### 3.2.2 Authentication & authorization

- Password auth **disabled by default**. Enabling it prints a loud warning to the SSH client's stderr on every connection and logs a `WARN` line.
- `authorized_keys` is re-read on each auth attempt (stat-cached, 1 s granularity) so `authorized_keys` can be updated without restarting the daemon — operationally important on headless Pi nodes.
- **RBAC** by key option: `authorized_keys` lines may carry `r3s-role=operator` / `r3s-role=viewer` / `r3s-role=admin`. Roles map to a capability set checked per command:

| Command group | viewer | operator | admin |
|---|---|---|---|
| `image list/inspect`, `container ls/inspect/logs/stats`, `system info/status` | ✔ | ✔ | ✔ |
| `container start/stop/kill/exec/attach`, `volume create/rm`, `limit set`, `image pull/prune` | | ✔ | ✔ |
| `system prune`, `engine restart`, `ssh role set`, `user add/rm` | | | ✔ |

- **Audit**: every mutating command logs `ts, principal (key fingerprint), role, argv, result, duration` to `audit.log` (append-only, `O_APPEND`, rotated at 4 MiB). `r3s system audit` is viewer-readable.
- **Brute-force**: `max_auth_attempts = 3` per connection, plus a per-source-IP exponential backoff held in an LRU of 256 entries.

#### 3.2.3 Interactive shell REPL

- A raw-mode, `reedline`-driven prompt: `r3s⟨hostname⟩ ⟨slice⟩ $` with completion (static command set + live container-id completion) and in-memory history persisted to `~/.r3s_history`.
- **Async-aware**: the REPL owns the terminal; long operations (pull, prune) print a spinner + progress derived from the engine's broadcast progress channel, and `Ctrl-C` cancels the in-flight command via a `CancellationToken` without killing the daemon.
- `exec -it` enters the container's namespace using `setns` on the stored namespace fds, allocates a PTY, sets the window size, and proxies bytes bidirectionally with backpressure (`Handle::data` is flow-controlled; the PTY read loop must apply the SSH window).

### 3.3 `r3s-runtime` / `r3s-net` — virtualization & network layer

#### 3.3.1 Contracts

```rust
#[async_trait::async_trait]            // only here: the engine may be sync in tests
pub trait IsolationBackend: Send + Sync {
    async fn create_scopes(&self, spec: &ContainerSpec) -> Result<ScopeSet>;
    async fn spawn_init(&self, spec: &ContainerSpec) -> Result<SpawnedPayload>;
    async fn teardown(&self, id: ContainerId) -> Result<()>;
    fn observe(&self, id: ContainerId) -> Result<Observed>;   // sync, allocation-free
}
```

`ScopeSet` is a *declared* record of every object created (cgroup path, veth names, mount points, netns path). It is written to the WAL **before** each object is created. Teardown is derived from the record, never from a guess — this is the design's single most important reliability property.

#### 3.3.2 Invariants (each has a test named `I<n>`)

| # | Invariant |
|---|---|
| I1 | After `create` returns Ok, exactly one cgroup exists under the container's slice, with all requested limits readable from cgroupfs. |
| I2 | A container cannot see or signal any host PID: its netns/mntns pid view contains only its own tree, and PID 1 is `r3s container-init`. |
| I3 | The container rootfs is read-only from the process's perspective; a write to `/etc/passwd` returns `EROFS`. |
| I4 | `kill -9 r3sd` + restart converges to the declared state with no manual cleanup and no leaked cgroup/veth/mount (verified by comparing `ip -o link`/`findmnt` snapshots before/after). |
| I5 | Deleting a container removes every object in its `ScopeSet`; a partial failure is retried and surfaced, never silently dropped. |
| I6 | Two containers on the same slice cannot exceed the slice's total `memory.max` (enforced by the hierarchy, not by admission logic). |
| I7 | `r3s image pull` of a 300-layer manifest does not exceed the configured `max_unpacked_bytes` and cannot escape the CAS root (fuzzed). |
| I8 | nftables ruleset is never observed in a partial state: every read of the `r3s` table either succeeds fully or the previous generation is still active (batch transactions). |
| I9 | A malicious tarball cannot create a path outside the extraction root (`PathEscape` variant asserted by proptest). |
| I10 | Every `Command` appears in the audit log within 50 ms of completion, including failures. |

#### 3.3.3 Error taxonomy (excerpt)

`EngineError::{ Config, Preflight, Unsupported{kernel_feature}, Store, Runtime, Network, Image, ResourceExhausted{resource,requested,available}, IllegalTransition, NotFound, Conflict, Cancelled, Internal }`

Each carries the operating errno and (where relevant) the path, because recovery differs: `ENOSPC` on `upper/` → `ResourceExhausted::Disk`; `EBUSY` on `rmdir` → retry with `MNT_DETACH`; `EINVAL` on `subtree_control` → a controller is missing from the kernel (a `Preflight` failure, surfaced at boot, not a runtime one).

---

## 4. PRODUCTION-GRADE CODE BLUEPRINTS (RUST 1.98, edition 2024)

> Shared context for the snippets:
>
> ```rust
> // crates/r3s-proto/src/types.rs
> #![forbid(unsafe_code)]
> use rkyv::Archive;
> use std::path::PathBuf;
> use std::time::Duration;
>
> pub type ContainerId = [u8; 16];
> pub type Digest = [u8; 32];
> pub use rkyv::rancor::{Error as RkyvError, Failure};
> pub use serde::{Deserialize, Serialize};
> pub use serde_json as json;
> pub use rkyv::Deserialize as _;
> pub use serde::Serialize as _;
> pub use rkyv::api::high::to_bytes_with_alloc as to_bytes;
> pub use rkyv::ser::allocator::Arena;
> ```

### Blueprint A — engine daemon bootstrap sequence

Order matters: fail fast on preflight, establish the cgroup hierarchy **before** accepting any work, open the store before the SSH listener (a store failure must not leave an exposed management port), and only then serve.

```rust
// crates/r3s-engine/src/boot.rs
use std::{path::PathBuf, sync::Arc, time::Instant};

use tokio::{signal, sync::broadcast};
use tracing::{error, info, warn};

use crate::{
    config::EngineConfig,
    error::{EngineError, Result},
    net::NetworkPlane,
    preflight::{self, Preflight},
    runtime::RuntimePlane,
    scheduler::Scheduler,
    sshd::SshPlane,
    store::Store,
    telemetry::TelemetrySampler,
    types::{Command, CommandAck, ContainerId, Phase},
};

pub struct Engine {
    cfg: EngineConfig,
    store: Arc<Store>,
    runtime: Arc<RuntimePlane>,
    network: Arc<NetworkPlane>,
    sampler: Arc<TelemetrySampler>,
    scheduler: Arc<Scheduler>,
    events: broadcast::Sender<EngineEvent>,
    shutting_down: tokio_util::sync::CancellationToken,
}

impl Engine {
    /// Ordered, failure-atomic boot. Every step is idempotent so a crash
    /// between steps is recovered by simply re-running bootstrap.
    pub async fn bootstrap(cfg: EngineConfig) -> Result<Arc<Self>> {
        let t0 = Instant::now();

        // 1. Preflight: kernel, cgroup v2 delegation, overlayfs, netfilter, root.
        //    Fails here must be *startup* failures, never degraded-runtime surprises.
        let facts = preflight::run(&cfg).await?;
        if !facts.netfilter_nft {
            warn!(target: "r3s::preflight", "nftables unavailable; network policy disabled");
        }
        if facts.landlock_abi < 1 {
            warn!(target: "r3s::preflight", abi = facts.landlock_abi, "Landlock unavailable");
        }

        // 2. Mount a private cgroup2 view so a host `systemd` hierarchy change
        //    can never remove the controllers we depend on.
        preflight::mount_cgroup2(&cfg.root).await?;

        // 3. Open state before opening any socket: a corrupt store must not
        //    leave an authenticated management port exposed.
        let store = Arc::new(Store::open(&cfg.root, cfg.storage.clone()).await?);
        store.recover().await?; // truncate torn WAL tail, replay intents, migrate schema

        // 4. Kernel planes. The engine process itself is accounted first so a
        //    memory-hungry container can never OOM-kill the control plane.
        let runtime = Arc::new(RuntimePlane::new(&cfg, &store).await?);
        runtime.claim_engine_scope().await?;

        // 5. Network plane: bridge, address pool, nftables table (idempotent).
        let network = Arc::new(NetworkPlane::new(&cfg, &facts).await?);
        network.reconcile_existing().await?;

        // 6. Telemetry before the scheduler: the first tick must be able to
        //    observe containers created by the very first reconcile pass.
        let sampler = Arc::new(TelemetrySampler::new(&cfg, &store).await?);
        sampler.spawn();

        // 7. Replayer/reconciler. Runs before SSH is bound so an operator who
        //    connects immediately never sees a half-reconciled node.
        let scheduler = Arc::new(Scheduler::new(
            cfg.scheduler.clone(),
            runtime.clone(),
            network.clone(),
            store.clone(),
        ));
        scheduler.spawn();

        // 8. Management plane last.
        let (events, _) = broadcast::channel(cfg.scheduler.event_buffer);
        let engine = Arc::new(Self {
            cfg,
            store,
            runtime,
            network,
            sampler,
            scheduler,
            events,
            shutting_down: tokio_util::sync::CancellationToken::new(),
        });

        let ssh = SshPlane::bind(engine.clone(), &engine.cfg.ssh).await?;
        engine.spawn_signal_watcher();
        engine.spawn_reporter(t0);

        info!(target: "r3s", elapsed_ms = t0.elapsed().as_millis(), "engine ready");
        Ok(engine)
    }

    pub async fn run(self: Arc<Self>) -> Result<()> {
        loop {
            tokio::select! {
                biased;
                _ = self.shutting_down.cancelled() => break,
                sig = signal::ctrl_c() => { info!("SIGINT received"); break }
                _ = signal::unix::signal(signal::unix::SignalKind::terminate()) => {
                    info!("SIGTERM received"); break
                }
                else => tokio::time::sleep(Duration::from_secs(3600)).await,
            }
            #[allow(unreachable_code)]
            {
                // unreachable; kept for exhaustiveness of the select above
            }
        }
        self.shutdown().await
    }

    /// Ordered teardown: stop accepting work, drain, stop containers in
    /// dependency order, then release kernel objects. Never panics.
    pub async fn shutdown(&self) -> Result<()> {
        self.shutting_down.cancel();
        self.sampler.stop().await;
        self.scheduler.stop().await;
        self.network.teardown_orphans().await?;
        self.runtime.teardown_engine_scope().await?;
        info!(target: "r3s", "engine stopped");
        Ok(())
    }

    pub async fn submit(&self, req: Command) -> Result<CommandAck> {
        self.scheduler.submit(req).await
    }

    pub fn snapshot(&self) -> Arc<crate::types::StateSnapshot> {
        self.store.snapshot()
    }

    pub fn health(&self) -> crate::types::HealthReport {
        self.scheduler.health()
    }

    fn spawn_signal_watcher(self: &Arc<Self>) {
        let me = self.clone();
        tokio::spawn(async move {
            let mut sigterm = match signal::unix::signal(signal::unix::SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => { error!(error = %e, "cannot install SIGTERM handler"); return }
            };
            tokio::select! {
                _ = sigterm.recv() => info!("SIGTERM"),
                _ = me.shutting_down.cancelled() => {}
            }
            let _ = me.shutdown().await;
        });
    }

    fn spawn_reporter(&self, t0: Instant) {
        let stats = self.store.stats_handle();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_secs(300));
            iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                iv.tick().await;
                tracing::info!(
                    target: "r3s::stats",
                    boot_ms = t0.elapsed().as_millis(),
                    rss_kib = stats.rss_kib(),
                    wal_records = stats.wal_records(),
                    containers = stats.live_containers(),
                    "engine stats"
                );
            }
        });
    }
}
```

`Preflight` result type (carries the kernel facts the rest of the engine branches on, so those branches are `match`es on data rather than re-`stat`ing):

```rust
// crates/r3s-engine/src/preflight.rs
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Preflight {
    pub kernel: KernelVersion,     // (major, minor, patch)
    pub cgroup_v2_unified: bool,
    pub cgroup_controllers: CpuSet,// cpu, memory, pids, io, cpuset, hugetlb
    pub overlayfs: bool,
    pub unpriv_overlayfs: bool,
    pub userns: bool,
    pub netfilter_nft: bool,
    pub landlock_abi: u32,
    pub euid: nix::unistd::Uid,
    pub page_size: usize,
}
```

Every one of these is asserted at boot and printed by `r3s system info`, because "works on my kernel" is the most common failure report for a runtime like this.

### Blueprint B — embedded SSH server, routing, and REPL wiring (russh 0.63.3)

The handler implements russh's RPITIT trait (no `#[async_trait]`, no boxing of futures), keeps per-channel session state in a sharded map, and separates three concerns: **authn/RBAC** (`r3s-sshd::authn`), **transport/PTY** (`r3s-sshd::term`), and **command routing** (`r3s-cli::Router`).

```rust
// crates/r3s-sshd/src/handler.rs
#![forbid(unsafe_code)]

use std::{collections::HashMap, future::Future, io, path::PathBuf, sync::Arc, time::Duration};

use russh::{
    Channel, ChannelId, ChannelMsg,
    server::{self, Auth, ChannelOpenHandle, Handle, Msg, Session},
    keys::PublicKey,
};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, sync::Mutex};
use tracing::{debug, info, warn};

use r3s_cli::{Role, Router};

#[derive(Clone)]
pub struct SshHandler {
    router: Arc<Router>,
    /// Per-*connection* state. `server::Server::new_client` hands us a fresh
    /// clone per connection, so this Arc is the natural session scope.
    conn: Arc<Mutex<ConnState>>,
    /// Per-*channel* state. Mutex is `tokio::sync::Mutex` because the trait's
    /// methods are sync fns returning futures; we only lock for O(1) map work.
    sessions: Arc<Mutex<HashMap<ChannelId, SessionCtx>>>,
    max_sessions: usize,
}

#[derive(Default)]
struct ConnState {
    role: Option<Role>,
    principal: Option<String>, // key fingerprint
    peer: Option<std::net::SocketAddr>,
}

#[derive(Default)]
struct SessionCtx {
    role: Option<Role>,
    pty: Option<PtyLease>,
    /// Cancel token for the in-flight command (Ctrl-C support).
    exec: Option<tokio_util::sync::CancellationToken>,
    last_activity: Option<std::time::Instant>,
}

impl SshHandler {
    pub fn new(router: Arc<Router>, max_sessions: usize) -> Self {
        Self {
            router,
            conn: Arc::new(Mutex::new(ConnState::default())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            max_sessions,
        }
    }
}

impl server::Server for SshHandler {
    type Handler = Self;

    fn new_client(&mut self, peer_addr: Option<std::net::SocketAddr>) -> Self {
        // A per-connection clone: this is how russh scopes handler state.
        let mut me = self.clone();
        me.conn = Arc::new(Mutex::new(ConnState { peer: peer_addr, ..Default::default() }));
        me.sessions = Arc::new(Mutex::new(HashMap::new()));
        debug!(?peer_addr, "ssh: client connected");
        me
    }

    fn handle_session_error(&mut self, error: <Self::Handler as server::Handler>::Error) {
        warn!(%error, "ssh: session error");
    }
}

impl server::Handler for SshHandler {
    type Error = io::Error;

    // ---- Authentication -------------------------------------------------
    fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
        let this = self.clone();
        let user = user.to_owned();
        let key = public_key.clone();
        async move {
            match this.router.authn().authenticate(&user, &key).await {
                Ok(grant) => {
                    {
                        let mut sessions = this.sessions.lock().await;
                        if sessions.len() >= this.max_sessions {
                            return Ok(Auth::reject());
                        }
                    }
                    let mut conn = this.conn.lock().await;
                    conn.role = Some(grant.role);
                    conn.principal = Some(grant.fingerprint.clone());
                    drop(conn);
                    info!(user, fingerprint = %grant.fingerprint, role = %grant.role, "ssh: auth ok");
                    Ok(Auth::Accept)
                }
                Err(e) => {
                    // Never leak *why* auth failed to the client; log it, reject uniformly.
                    warn!(user, error = %e, "ssh: auth denied");
                    Ok(Auth::reject())
                }
            }
        }
    }

    // Password auth is opt-in and rate-limited by the authn service.
    fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
        let this = self.clone();
        let (user, password) = (user.to_owned(), password.to_owned());
        async move {
            match this.router.authn().authenticate_password(&user, &password).await {
                Ok(grant) => Ok(Auth::Accept).inspect(|_| {
                    warn!(user, "ssh: PASSWORD AUTH used");
                }),
                Err(_) => Ok(Auth::reject()),
            }
        }
    }

    // ---- Channels --------------------------------------------------------
    fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        mut reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let this = self.clone();
        async move {
            let id = channel.id();
            this.sessions.lock().await.insert(id, SessionCtx::default());
            reply.accept().await;
            let _ = session;
            Ok(())
        }
    }

    fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let this = self.clone();
        let term = term.to_owned();
        let modes: Vec<(russh::Pty, u32)> = modes.to_vec();
        async move {
            // The SSH client *negotiates* the PTY; we must own the slave fd.
            let lease = PtyLease::open(term.as_str(), col_width, row_height, pix_width, pix_height, &modes)
                .map_err(io::Error::other)?;
            this.sessions.lock().await.get_mut(&channel).map(|c| c.pty = Some(lease));
            session.channel_success(channel);
            Ok(())
        }
    }

    fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let this = self.clone();
        async move {
            if let Some(ctx) = this.sessions.lock().await.get(&channel) {
                if let Some(pty) = &ctx.pty {
                    pty::resize(pty, col_width, row_height, pix_width, pix_height);
                }
            }
            session.channel_success(channel);
            Ok(())
        }
    }

    fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let this = self.clone();
        let argv = String::from_utf8_lossy(data).into_owned();
        async move {
            session.channel_success(channel);
            let code = this
                .router
                .execute(channel, &argv, this.sessions.clone(), session.handle().clone())
                .await;
            let _ = session.handle().exit_status_request(channel, code as u32).await;
            let _ = session.handle().close(channel).await;
            let _ = this.sessions.lock().await.remove(&channel);
            Ok(())
        }
    }

    // `r3s sftp` is explicitly NOT offered in v1: it is the largest attack
    // surface in any SSH daemon and is not required by the brief.
    fn subsystem_request(
        &mut self, _channel: ChannelId, _name: &str, session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async move { session.channel_failure(_channel); Ok(()) }
    }

    fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let this = self.clone();
        let buf = data.to_vec(); // russh's slice is only valid for this call
        async move {
            match this.on_input(channel, &buf).await {
                Ok(()) => {}
                Err(e) => return Err(e),
            }
            // Ctrl-C is a *client* convention: cancel the command, keep the session.
            if buf == [3] {
                let token = this.sessions.lock().await.get(&channel).and_then(|c| c.exec.clone());
                if let Some(t) = token { t.cancel(); }
            }
            let _ = session;
            Ok(())
        }
    }

    fn disconnect(
        &mut self, _address: std::net::SocketAddr, _error: russh::Error, _msg: &str,
        _session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async move { Ok(()) }
    }
}

impl SshHandler {
    async fn on_input(&self, channel: ChannelId, data: &[u8]) -> Result<(), io::Error> {
        let pty = {
            let mut sessions = self.sessions.lock().await;
            let ctx = sessions.get_mut(&channel).ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;
            ctx.last_activity = Some(std::time::Instant::now());
            ctx.pty.as_ref().map(|p| p.slave.clone())
        };
        match pty {
            Some(mut fd) => { fd.write_all(data).await?; Ok(()) }
            None => Ok(()), // non-PTY exec: input is forwarded by the command runner
        }
    }
}

/// Bound to `Handle` by the router; owns the bidirectional proxy between an
/// SSH channel and a PTY master, with backpressure in both directions.
pub struct PtyProxy { pub handle: Handle, pub channel: ChannelId }

impl PtyProxy {
    pub async fn pump(mut self, master: std::fs::File, token: tokio_util::sync::CancellationToken) {
        let (mut rd, mut wr) = tokio::io::split(master);
        let up = tokio::spawn({
            let (h, c, t) = (self.handle.clone(), self.channel, token.clone());
            async move {
                let mut buf = vec![0u8; 32 * 1024];
                loop {
                    tokio::select! {
                        biased;
                        _ = t.cancelled() => break,
                        n = wr.read(&mut buf) => match n {
                            Ok(0) | Err(_) => break,
                            Ok(n) => if h.data(c, buf[..n].to_vec()).await.is_err() { break }
                        }
                    }
                }
            }
        });
        let _ = up.await;
        let _ = self.handle.eof(self.channel).await;
    }
}
```

Server bind + hard limits (the `Config` is where the DoS controls live):

```rust
// crates/r3s-sshd/src/server.rs
use std::sync::Arc;
use russh::{server::{self, Config, Server as _}, Preferred};
use tokio::net::TcpListener;

pub async fn bind(router: Arc<Router>, cfg: &SshConfig) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let keys = load_or_generate_host_keys(&cfg.host_key_paths).await?;
    let config = Config {
        server_id: "SSH-2.0-r3s".into(),
        methods: russh::auth::MethodSet::PUBLICKEY | russh::auth::MethodSet::PASSWORD,
        auth_rejection_time: Duration::from_millis(300),      // constant-time-ish
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        keys,
        limits: russh::Limits { kex_time: Some(Duration::from_secs(20)), ..Default::default() },
        window_size: 2 * 1024 * 1024,
        maximum_packet_size: 32 * 1024,
        channel_buffer_size: 64,
        event_buffer_size: 256,
        max_auth_attempts: 3,
        inactivity_timeout: Some(Duration::from_secs(900)),
        preferred: Preferred {
            kex: std::borrow::Cow::Owned(vec![
                "mlkem768x25519-sha256".into(), "curve25519-sha256".into(),
            ]),
            ..Preferred::default()
        },
        ..Default::default()
    };

    // Bind before serving so a port clash fails at boot, not on first client.
    let listener = TcpListener::bind(cfg.bind).await?;
    let sh = SshHandler::new(router, cfg.max_sessions);

    Ok(tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else { continue };
            let config = config.clone();
            // One task per connection with a hard handshake budget: a slow
            // client must not be able to pin a worker thread indefinitely.
            tokio::spawn(async move {
                let _ = stream.set_nodelay(true);
                let outcome = tokio::time::timeout(cfg.handshake_timeout, async move {
                    russh::server::run_stream(config, stream, sh).await.map(|_| ())
                })
                .await;
                if outcome.is_err() { warn!(%peer, "ssh: handshake timeout"); }
            });
        }
    }))
}
```

`russh::server::run_stream(config, stream, handler) -> Result<RunningSession<H>, H::Error>` is a free function (not a method) in 0.63, and it returns the `RunningSession`; the accept loop above is intentionally minimal — the heavy part (per-connection state) lives in the `SshHandler` clone produced by `new_client`.

### Blueprint C — low-level namespace + cgroup creation

Two halves: the **parent** (daemon side, async, writes intent + creates kernel objects) and the **child** (`r3s container-init`, re-executed, sync, async-signal-safe until `execve`).

```rust
// crates/r3s-runtime/src/cgroup.rs
//! cgroup v2 writer. nix has no cgroup bindings, so this is intentionally
//! hand-written: it is ~150 lines, fully typed, and testable without a
//! namespace by pointing CGROUP_ROOT at a tmpfs mount in tests.
#![cfg_attr(test, allow(unsafe_code))]

use std::{io, path::{Path, PathBuf}};

use tracing::debug;

#[derive(Debug, thiserror::Error)]
pub enum CgroupError {
    #[error("cgroup path escape: {0}")]
    PathEscape(PathBuf),
    #[error("no-internal-processes rule violated for {path}")]
    Busy { path: PathBuf },
    #[error("controller {0} not available on this kernel")]
    MissingController(String),
    #[error("io error on {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
}

pub struct Cgroup {
    root: PathBuf,   // e.g. /sys/fs/cgroup
    rel: PathBuf,    // e.g. r3s.slice/default.slice/r3s-x.scope
}

impl Cgroup {
    pub fn new(root: &Path, rel: impl AsRef<Path>) -> Result<Self, CgroupError> {
        let rel = rel.as_ref();
        if rel.is_absolute() || rel.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
            return Err(CgroupError::PathEscape(rel.to_path_buf()));
        }
        Ok(Self { root: root.to_path_buf(), rel: rel.to_path_buf() })
    }

    pub fn path(&self) -> PathBuf { self.root.join(&self.rel) }

    fn io<P: AsRef<Path>>(&self, what: &Path, r: io::Result<()>) -> Result<(), CgroupError> {
        r.map_err(|source| CgroupError::Io { path: what.to_path_buf(), source })
    }

    /// cgroupfs has no "create" syscall: a cgroup is a directory. mkdir is
    /// idempotent (EEXIST is success) which is exactly the semantic we want.
    pub fn ensure(&self) -> Result<(), CgroupError> {
        let p = self.path();
        match std::fs::create_dir_all(&p) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            Err(source) => Err(CgroupError::Io { path: p, source }),
        }
    }

    pub fn read_to_string(&self, rel: &str) -> io::Result<String> {
        std::fs::read_to_string(self.path().join(rel))
    }

    pub fn write_ctl(&self, rel: &str, value: &str) -> Result<(), CgroupError> {
        let p = self.path().join(rel);
        debug!(path = %p.display(), value, "cgroup write");
        // O_WRONLY without O_TRUNC: the kernel parses the whole buffer.
        self.io(&p, std::fs::OpenOptions::new().write(true).open(&p).and_then(|mut f| {
            use io::Write;
            f.write_all(value.as_bytes())
        }))
    }

    /// Controllers MUST be enabled in the parent *before* children are
    /// populated, and a cgroup with enabled subtree controllers must have an
    /// empty cgroup.procs (the "no internal processes" rule).
    pub fn enable_controllers(&self, ctrls: &[&str]) -> Result<(), CgroupError> {
        let available = self.read_to_string("cgroup.controllers").unwrap_or_default();
        for c in ctrls {
            if !available.split_whitespace().any(|a| a == *c) {
                return Err(CgroupError::MissingController((*c).to_owned()));
            }
        }
        let want = ctrls.iter().map(|c| format!("+{c}")).collect::<Vec<_>>().join(" ");
        self.write_ctl("cgroup.subtree_control", &want)
    }

    pub fn assert_no_internal_processes(&self) -> Result<(), CgroupError> {
        if !self.read_to_string("cgroup.procs").unwrap_or_default().trim().is_empty() {
            return Err(CgroupError::Busy { path: self.path() });
        }
        Ok(())
    }

    pub fn attach_pid(&self, pid: nix::unistd::Pid) -> Result<(), CgroupError> {
        self.write_ctl("cgroup.procs", &pid.as_raw().to_string())
    }

    pub fn set_limits(&self, limits: &ResourceLimits) -> Result<(), CgroupError> {
        // memory
        self.write_ctl("memory.max", &limits.memory_bytes.to_string())?;
        self.write_ctl("memory.swap.max", &limits.swap_bytes.to_string())?;
        self.write_ctl("memory.oom.group", "1")?;
        // cpu: "<quota_us> <period_us>"
        let period = 100_000u64;
        let quota = (limits.cpu_shares * period / 100).min(i64::MAX as u64);
        self.write_ctl("cpu.max", &format!("{quota} {period}"))?;
        // pids
        self.write_ctl("pids.max", &limits.max_pids.to_string())?;
        Ok(())
    }

    /// Teardown: move stragglers out, then rmdir. EAGAIN/EBUSY mean someone
    /// is still in the cgroup; the caller retries with the standard backoff.
    pub fn remove(&self) -> Result<(), CgroupError> {
        let p = self.path();
        if !p.exists() { return Ok(()); }
        let _ = self.write_ctl("cgroup.kill", "1");           // kernel ≥ 5.14
        let _ = std::fs::remove_dir_all(&p);
        std::fs::remove_dir(&p).or_else(|e| match e.kind() {
            io::ErrorKind::NotFound => Ok(()),
            _ => Err(CgroupError::Io { path: p, source: e }),
        })
    }
}
```

```rust
// crates/r3s-runtime/src/isolation.rs
//! Namespace + mount + execve path. Everything in `child_main` runs between
//! fork/exec and execve: async-signal-safe only, no allocation, no logging.
#![allow(unsafe_code)] // justified: this module *is* the unsafe boundary

use std::{ffi::CString, os::unix::ffi::OsStrExt, path::{Path, PathBuf}};

use nix::{
    mount::{MntFlags, MsFlags, mount, umount2},
    sched::{CloneFlags, setns, unshare},
    sys::{resource::{Resource, RLIM_INFINITY, setrlimit}, stat::umask},
    unistd::{chdir, close, dup2, execve, getpid, pivot_root, setresgid, setresuid, setsid},
};
use tracing::error;

use crate::{cgroup::Cgroup, config::ContainerSpec};

/// Opens the namespace FDs the parent needs for `exec` and for `setns` joins.
pub struct NamespaceFds {
    pub pid: OwnedFd,
    pub mnt: OwnedFd,
    pub net: OwnedFd,
    pub userns: OwnedFd,
}

pub fn open_namespace_fds(pid: nix::unistd::Pid) -> std::io::Result<NamespaceFds> {
    let open = |name: &str| {
        let p = format!("/proc/{}/ns/{}", pid.as_raw(), name);
        std::fs::OpenOptions::new().read(true).open(p)
            .map_err(std::io::Error::other)
            .map(|f| f.into())
    };
    Ok(NamespaceFds { pid: open("pid")?, mnt: open("mnt")?, net: open("net")?, userns: open("user")? })
}

pub fn ns_flags(spec: &ContainerSpec) -> CloneFlags {
    let mut f = CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWPID
        | CloneFlags::CLONE_NEWUTS | CloneFlags::CLONE_NEWIPC
        | CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWCGROUP;
    if spec.rootless { f |= CloneFlags::CLONE_NEWUSER; }
    f
}

/// The child's setup, executed after re-exec of `r3s container-init` and
/// before `execve` of the payload. No panics, no allocations, no threads.
pub fn child_main(spec: &ChildSetup) -> std::io::Result<std::convert::Infallible> {
    // 1. Join the user namespace FIRST and become uid 0 inside it, otherwise
    //    every subsequent mount/unshare below fails with EPERM.
    if spec.userns_fd.is_some() {
        setns(spec.userns_fd.as_ref().unwrap(), CloneFlags::CLONE_NEWUSER)
            .map_err(fatal("setns(user)"))?;
    }
    if let Some(uid) = spec.inside_uid {
        setresgid(uid, uid, uid).map_err(fatal("setresgid"))?;
        setresuid(uid, uid, uid).map_err(fatal("setresuid"))?;
    }

    // 2. Unshare the rest. CLONE_NEWPID only takes effect for *children*, so we
    //    fork immediately after this call (see step 6).
    unshare(spec.ns_flags).map_err(fatal("unshare"))?;

    // 3. New session + controlling terminal, so signals and TTY semantics match
    //    what a container runtime is expected to provide.
    let _ = setsid();

    // 4. Mount namespace: make every mount private so nothing propagates back
    //    to the host (this is why we unshared CLONE_NEWNS at all).
    mount(
        None::<&Path>, Path::new("/"), None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE, None::<&str>,
    ).map_err(fatal("make-rprivate"))?;

    // 5. Mount the rootfs and pivot into it. pivot_root requires the new root
    //    to be a *mount point*, hence the self-bind.
    let rootfs = &spec.rootfs;
    mount(
        Some(rootfs.as_path()), rootfs.as_path(), None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC, None::<&str>,
    ).map_err(fatal("bind rootfs"))?;

    // Recursively read-only: stronger than relying on an MS_RDONLY overlay upper.
    rustix::mount::mount_setattr(
        std::fs::File::open(rootfs)?,
        "", rustix::mount::SetAttrFlags::MOUNT_ATTR_RDONLY
            | rustix::mount::SetAttrFlags::AT_RECURSIVE,
    ).map_err(fatal("mount_setattr(ro)"))?;

    let (parent, base) = rootfs.parent().ok_or_else(|| fatal_io("rootfs has no parent"))
        .and_then(|p| Ok((p.to_path_buf(), base_name(rootfs)?)))?;
    let put_old = parent.join("r3s-oldroot");
    let _ = std::fs::create_dir(&put_old);
    pivot_root(rootfs, &put_old).map_err(fatal("pivot_root"))?;

    // Detach the host root so it cannot be reached via the old root fd.
    umount2(Path::new("/"), MntFlags::MNT_DETACH).map_err(fatal("umount oldroot"))?;
    let _ = std::fs::remove_dir("/r3s-oldroot");

    chdir("/").map_err(fatal("chdir /"))?;
    umask(0o022);

    // 6. Pseudo-filesystems, AFTER pivot_root (they must live in the new root).
    mount(Some("proc"), Path::new("/proc"), Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV, None::<&str>)
        .map_err(fatal("mount /proc"))?;
    mount(Some("tmpfs"), Path::new("/dev"), Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_STRICTATIME, Some("mode=755,size=65536k"))
        .map_err(fatal("mount /dev"))?;
    for dev in ["null", "zero", "full", "random", "urandom", "tty"] {
        let p = PathBuf::from("/dev").join(dev);
        let _ = mount(Some(Path::new("/dev").as_path()), &p, None::<&str>,
            MsFlags::MS_BIND, None::<&str>);
    }
    if spec.readonly_sys {
        mount(None::<&Path>, Path::new("/sys"), None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            None::<&str>).map_err(fatal("bind /sys ro"))?;
    }

    // 7. Write mounts (declared volumes) then rlimits, then seccomp LAST —
    //    after it is installed, only open/read/write/exit_group remain available.
    for m in &spec.mounts {
        apply_mount(m).map_err(fatal("apply_mount"))?;
    }
    for (res, soft, hard) in spec.rlimits {
        let _ = setrlimit(res, &nix::sys::resource::RLimit { rlim_cur: soft, rlim_max: hard });
    }
    if let Some(profile) = &spec.seccomp {
        if let Err(e) = crate::seccomp::install(profile) {
            error!(error = %e, "seccomp install failed; refusing to exec");
        }
    }

    // 8. The double fork. The process that called unshare(CLONE_NEWPID) is NOT
    //    in the new PID namespace; only its children are. Forking here makes
    //    *this* process PID 1 of the container.
    let pid = match unsafe { nix::unistd::fork() } {
        Ok(nix::unistd::ForkResult::Parent { child }) => child,
        Ok(nix::unistd::ForkResult::Child) => {
            // In the new PID ns: re-apply limits that were reset by fork, reap
            // orphans so PID 1 semantics are correct, then exec the payload.
            reap_orphans();
            let prog = CString::new(spec.argv[0].as_bytes()).map_err(|_| fatal_io("argv0"))?;
            let argv: Vec<CString> = spec.argv.iter()
                .map(|a| CString::new(a.as_bytes())).collect::<std::result::Result<_, _>>()
                .map_err(|_| fatal_io("argv"))?;
            let envp: Vec<CString> = spec.env.iter()
                .map(|a| CString::new(a.as_bytes())).collect::<std::result::Result<_, _>>()
                .map_err(|_| fatal_io("env"))?;
            execve(&prog, &[prog.as_ptr()], argv.as_ptr().cast(), envp.as_ptr().cast())
                .map_err(fatal("execve"))
        }
        Err(e) => fatal_errno("fork")(e),
    };
    // Parent of PID 1: report the ns-init pid back to the daemon and wait forever.
    // The daemon tracks this pid via pidfd; SIGKILL from the daemon orphans the
    // container, which the kernel re-parents to init — the correct semantics.
    crate::init::report_pid(pid);
    loop { nix::unistd::pause().map_err(fatal("pause")); }
}

fn reap_orphans() {
    // PID 1 of a PID namespace is responsible for reaping; without this a
    // container leaks zombies for the lifetime of the pod.
    let mut action = nix::sys::signal::SigAction::new(nix::sys::signal::SigHandler::SigIgn, nix::sys::signal::SigSet::empty(), nix::sys::signal::SockFlags::empty());
    let _ = nix::sys::signal::sigaction(nix::sys::signal::Signal::SIGCHLD, &mut action);
    loop {
        match nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(-1), None) {
            Ok(_) => continue,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(nix::errno::Errno::ECHILD) => break,
            Err(_) => break,
        }
    }
}

fn base_name(p: &Path) -> std::io::Result<CString> {
    p.file_name()
        .ok_or_else(|| fatal_io("no file_name"))
        .and_then(|n| CString::new(n.as_bytes()).map_err(|_| fatal_io("nul in name")))
}

fn apply_mount(m: &MountSpec) -> std::io::Result<()> {
    use nix::mount::{MntFlags as MF, MsFlags as MS};
    let target = Path::new(&m.target);
    std::fs::create_dir_all(target)?;
    let mut flags = MS::MS_BIND | MS::MS_REC;
    flags |= if m.readonly { MS::MS_RDONLY } else { MS::MS_BIND };
    if m.nosuid { flags |= MS::MS_NOSUID }
    if m.nodev { flags |= MS::MS_NODEV }
    if m.noexec { flags |= MS::MS_NOEXEC }
    mount(Some(Path::new(&m.source)), target, None::<&str>, flags, None::<&str>)?;
    if m.readonly { umount2(target, MF::MNT_REMOUNT | MF::MNT_RDONLY)?; }
    Ok(())
}

fn fatal<E: std::fmt::Display>(what: &'static str) -> impl Fn(E) -> std::io::Error { move |e| std::io::Error::other(format!("{what}: {e}")) }
fn fatal_io(what: &'static str) -> std::io::Error { std::io::Error::other(what) }
fn fatal_errno(what: &'static str) -> impl Fn(nix::errno::Errno) -> std::io::Error { move |e| std::io::Error::from_raw_os_error(e as i32) }
```

Parent side — the async, retryable half that owns kernel object lifetime:

```rust
// crates/r3s-runtime/src/spawn.rs
use std::{path::Path, sync::Arc};

use nix::unistd::Pid;
use tokio::{process::Command, sync::Semaphore};
use tracing::{debug, info};

use crate::{cgroup::Cgroup, isolation::open_namespace_fds, manifest::ScopeSet, spec::ContainerSpec, Error};

pub struct Spawner {
    bin: PathBuf,
    slice: String,
    cgroup_root: PathBuf,
    /// One permit per concurrent create: image extraction + mount + fork are
    /// all blocking and must not saturate the blocking pool.
    permits: Semaphore,
}

impl Spawner {
    pub async fn spawn(&self, spec: &ContainerSpec, scope: &ScopeSet) -> Result<Spawned, Error> {
        let _permit = self.permits.acquire().await.map_err(Error::ShuttingDown)?;

        // (a) cgroup object + limits, BEFORE the process exists.
        let cg = Cgroup::new(&self.cgroup_root, scope.cgroup_rel())?;
        cg.ensure()?;
        cg.set_limits(&spec.limits)?;

        // (b) Re-exec ourselves as the container init. Never fork the daemon's
        //     threads: pre_exec in a multithreaded process is a footgun and
        //     nix::unistd::fork is `unsafe` for exactly this reason.
        let mut cmd = Command::new(&self.bin);
        cmd.arg("container-init")
           .arg("--bundle").arg(&scope.bundle_dir())
           .stdin(std::process::Stdio::null())
           .stdout(std::process::Stdio::null())
           .stderr(std::process::Stdio::null());
        // If the payload's stdio is wired to an SSH PTY, hand over the fds here
        // instead of null:
        //   cmd.stdout(unsafe { Stdio::from_raw_fd(pty_slave) });

        let child = cmd.spawn().map_err(Error::Spawn)?;
        let pid = Pid::from_raw(child.id() as i32);

        // (c) Attach to the cgroup: limits are enforced from the first
        //     instruction of the payload, including its dynamic linker.
        cg.attach_pid(pid).map_err(Error::Cgroup)?;

        // (d) Namespace fds are opened from the *child's* /proc entry and used
        //     by `r3s exec` later. Held open by the daemon on purpose: if the
        //     payload dies they still let us setns for post-mortem inspection.
        let fds = open_namespace_fds(pid).map_err(Error::Namespace)?;
        let pidfd = rustix::process::pidfd_open(pid).map_err(|e| Error::Namespace(std::io::Error::from_raw_os_error(e.raw_os_error())))?;

        debug!(id = %spec.id, pid = pid.as_raw(), "spawned");
        Ok(Spawned { pid, pidfd, ns_fds: fds, cgroup: cg, child })
    }
}
```

Unsafe-surface rule, enforced by a CI lint (`cargo geiger` diff against a committed baseline; the total unsafe byte count may not grow without a written justification in `docs/UNSAFE.md`):

| Crate | `unsafe` permitted for |
|---|---|
| `r3s-store` | `mmap`/`munmap`, `flock` |
| `r3s-runtime` | syscalls, `fork`, `execve`, fd handling, seccomp BPF |
| `r3s-net` | netlink socket buffers |
| everything else | **nothing** (`#![forbid(unsafe_code)]`) |

---

## 5. SYSTEM ROADMAP & IMPLEMENTATION STEPS

### 5.0 Stage 0 — Baseline & instrumentation (2 weeks, runs concurrently with Stage 1)

Not optional. Without measured baselines every later claim is unverified.

- `docs/BASELINE.md`: RSS, boot time, syscall counts, container start latency for a 1-container workload on Pi 5 / Pi 4 / Pi 3, with `perf stat`, `/proc/self/smaps_rollup`, and `bpftrace` syscall counts.
- `tests/ondevice/runner.sh` — a self-hosted GitHub Actions runner on a physical Pi, with a USB-serial console so a kernel-panic from a bad mount namespace is recoverable. Without this, Stage 1 tests that create namespaces will hard-lock the node and lose the runner.
- `criterion` benches for: WAL append, snapshot archive, cgroup write batch, netlink round-trip, SSH handshake, CLI table render.

### 5.1 Stage 1 — Core engine & isolation foundations (5 weeks)

**Goal:** a container with real isolation, managed by a daemon, with no images beyond a rootfs tarball.

| Week | Deliverable |
|---|---|
| 1 | Workspace skeleton, `r3s-proto` types, CI (fmt/clippy `-D warnings`/miri-less `cargo deny`/deny-licenses), cross-compile to `aarch64` + musl, `r3s init`/`version` |
| 2 | `r3s-store`: WAL (CRC32C, group commit), mmap snapshot, rkyv access, recovery/truncation, migrations |
| 3 | `r3s-runtime`: cgroup v2 tree, scope create/limits/remove, preflight, engine scope, OOM detection |
| 4 | `r3s-runtime`: namespaces, re-exec init, `pivot_root`, mounts/rbind, rlimits, capabilities, seccomp |
| 5 | `r3s-engine`: `Command` enum, reconciler, lifecycle state machine, restart policy, `sweep_orphans`, signal handling |

**DoD (integration requirements):**
- `I1..I6`, `I10` implemented and green.
- `kill -9 r3sd` during 200 container creations → restart converges, `0` leaked cgroups/veths/mounts (asserted by snapshotting `findmnt` and `/sys/fs/cgroup/*/cgroup.procs`).
- 500 × `create+start+stop+rm` soak: RSS growth ≤ 2 MiB over the run (checked with `smaps_rollup`, not `ps`).
- Namespace escape attempt suite: setuid binary in container cannot regain host capabilities; `/proc/1/root` does not resolve to the host root; `ptrace` of a host pid fails.
- `pids.max` exhaustion kills only the offending container (verified with `pids.events`).
- 72-hour soak on a Pi 3 (the worst target) with no OOM, no fd leak (`/proc/self/fd` count stable ±2).

**Exit criteria:** the engine is a working runtime *without* networking or images. If a 1-container cluster cannot survive `kill -9` cleanly, later stages will not save it.

### 5.2 Stage 2 — Embedded SSH server & custom shell (4 weeks)

**Goal:** the full management plane; no external SSH tooling on the node.

| Week | Deliverable |
|---|---|
| 1 | `r3s-sshd`: bind, host keys, `authorized_keys` (stat-cached), constant-time reject, brute-force LRU, session/connection caps |
| 2 | Channel lifecycle: PTY (`openpty` + `TIOCSWINSZ`), `exec`, extended-data (stderr), `exit-status`, refusal of `sftp`/`x11`/`direct-tcpip`/`agent` |
| 3 | `r3s-cli`: hand-written parser, router, RBAC, table/JSON renderers, exit codes, audit log |
| 4 | REPL: `reedline`, completion (commands + live container ids), history, progress + `Ctrl-C` cancellation, `exec -it` into a container's namespaces |

**DoD (integration requirements):**
- `ssh -T` and `ssh -t` both work against Pi 3/4/5; 200 concurrent sessions hold with RSS ≤ +6 MiB over baseline.
- 8 192-bit RSA + ed25519 + ecdsa keys; **all** SHA-1 (`ssh-rsa`, `diffie-hellman-group1-sha1`) negotiations are rejected.
- Auth brute force: 1000 bad attempts from one IP → locked out with exponential backoff; a legitimate key still works.
- RBAC matrix test: every (role × command) pair asserts allow/deny; denial is logged with principal fingerprint.
- `r3s exec -it` into a running container: TTY echo, `SIGWINCH` on resize, `SIGINT` propagation to PID 1, exit status propagated to the SSH client.
- `cargo-fuzz` (10 min/night) over the CLI parser and the tar unpacker: zero panics, zero OOM.
- Compatibility matrix with OpenSSH 8.x, 9.x, 10.x and `ssh2`/`libssh2` clients (some clients are the source of most interop bugs).

**Exit criteria:** a fresh operator can install the binary, `ssh root@pi`, and drive everything without any other tool on the box.

### 5.3 Stage 3 — Image & storage layer (4 weeks)

**Goal:** OCI images end to end: pull, verify, unpack, run, prune.

| Week | Deliverable |
|---|---|
| 1 | Registry client: HTTP/1.1 + HTTP/2 upgrade, auth (bearer + basic), resumable chunked download, retry/backoff, per-registry rate-limit backoff; `rustls` with a small root store |
| 2 | Manifest handling (Docker v2 + OCI + indexes), `rkyv` CAS, content-addressed blobs, zstd streaming verify (sha256 over the *uncompressed* stream) |
| 3 | `LayerUnpacker`: whiteouts (`.wh.`), opaque dirs, uid/gid/xattr restore, hardlink/symlink validation, path-escape prevention, disk-quota enforcement, progress reporting |
| 4 | Overlay integration: multi-layer `lowerdir`, `index=off` tuning, `containers/<id>/upper|work|rootfs`, volume management, `r3s image prune` with LRU, `oci.json` export, read-only remount via `mount_setattr` |

**DoD (integration requirements):**
- Pull 50 real images (Debian slim, Alpine, `nginx`, `redis`, a 1.2 GB `python` image, a multi-arch manifest list) with digest pinning verified byte-for-byte.
- `I7`, `I9` green; proptest over malicious tarballs (`../../etc/shadow`, absolute symlink, hardlink escape, `/dev/kmem` node, setuid on a bindable file) — all rejected with the right error variant.
- Disk-full simulation (`tmpfs` at 64 MiB): clean `ENOSPC` error, no partial container, no leaked upperdir.
- Kill -9 during unpack of a 1.2 GB image → restart resumes or rolls back cleanly; CAS is never left with a blob whose digest does not match its content.
- `r3s image prune` never removes a blob referenced by a live container; proven by a randomized reference-graph test (10 000 iterations).
- Overlay mount options A/B tested: `index=off` must be ≥ 20 % faster on Pi 3 for a 5 k-file start, or the assumption is dropped and documented.

**Exit criteria:** `r3s run --rm alpine:3 sh` works end to end over SSH on a Pi with a cold SD card, in < 90 s including image pull.

### 5.4 Stage 4 — Hardening, telemetry & cluster-ready networking (4 weeks)

**Goal:** production readiness for unattended nodes.

| Week | Deliverable |
|---|---|
| 1 | Telemetry: mmap ring, 1 Hz sampler, `r3s stats`/`top`, Prometheus `/metrics` (opt-in), per-cgroup `memory.events` OOM attribution, export over SSH (`--format json`) |
| 2 | Self-healing: health checks (exec/http/tcp), auto-restart with backoff + rate limit, crash-loop detection, stuck-detector, `system prune`, disk-pressure guard, graceful reboot drain |
| 3 | Networking hardening: per-container egress policy, port publishing (DNAT via nftables), bandwidth limits via `tc`, `I8` batch-transaction guarantees, netns leak sweeper |
| 4 | Cluster primitives: node identity (Ed25519), mTLS control plane (axum, bound to `127.0.0.1` by default), heartbeat/health gossip over length-prefixed rkyv streams, image cache sharing protocol, `cluster join/leave/ls`, multi-node image pull failover |

**DoD (integration requirements):**
- 72-hour mixed-load soak on Pi 4 (32 containers, 1 Hz telemetry): RSS drift ≤ 1 MiB/h, no fd/mount/cgroup leaks, p99 CLI latency ≤ 40 ms.
- 2-node cluster on two Pis: node failure → workloads rescheduled or cleanly marked failed within 30 s; no split-brain (a single leader lease in the store, fenced).
- Chaos suite: SIGKILL the daemon every 60 s for 1 h; SIGKILL the host mid-write; fill the SD card to 98 %; `nft flush ruleset` externally. The node must recover to declared state in all four.
- Security review: no `unsafe` without a justification entry, no network-listening port without auth, default-deny egress, secrets never in the store plaintext, host keys generated with correct permissions, audit log tamper-evident (hash chain).
- Supply chain: `cargo deny` + `cargo auditable` (reproducible builds), SBOM per release, signed release artifacts and a documented manual upgrade path (binary replace + `r3s system migrate`).
- Load test: 2 000 `r3s ps` invocations/hour via SSH with no leak of sessions or file descriptors.

**Exit criteria:** a node can sit unattended on a remote Pi for a month, with an operator who has never touched the device.

### 5.5 Risk register

| Risk | Impact | Mitigation |
|---|---|---|
| SD-card wear / random-write latency | State corruption, latency spikes | Group commit, bounded WAL, no RocksDB-style compaction, `EXT4` mount options documented (`noatime`, `data=writeback`), optional tmpfs for `state/wal` |
| Kernel variance across Pi OS versions | Preflight failures in the field | Preflight is a first-class feature; explicit min-kernel matrix; `nix` feature-gated so unsupported calls do not compile |
| Running out of RAM on 512 MB boards | OOM kill of the node | Admission control on memory, engine self-limit, `memory.oom.group`, swap disabled, telemetry-based alerting |
| `overlayfs` semantics (whiteouts, metacopy, index) | Subtle data bugs | `index=off`/`metacopy=off`; fuzzer against a reference `tar`+`diff` extraction; property tests for whiteout round-trips |
| SSH hand-rolled attack surface | RCE on the node | russh (not a hand-rolled transport), modern-only algorithms, constant-time reject, brute-force limits, connection caps, SFTP/X11/forwarding refused, external security review before v1.0 |
| Unsafe code in a runtime | Privilege escalation | Unsafe confined to 3 crates, `cargo geiger` budget, `UNSAFE.md` justifications, `forbid(unsafe_code)` everywhere else |
| Scope creep into a Docker clone | Never ships | Explicit non-goals (§ preamble); native grammar; OCI only as an *input* format |
| Single-writer design bottleneck | Latency under burst load | 5 ms group commit; burst of 200 creates is bounded by the create semaphore; measured before assuming a problem |

### 5.6 Definition of done (applies to every stage)

1. `cargo clippy --all-targets --all-features -- -D warnings` clean; `cargo fmt --check` clean; `cargo doc -D warnings` clean.
2. `cargo nextest run` green (unit + integration) on both x86_64 CI and the on-device runner.
3. `cargo geiger` unsafe-byte count ≤ committed baseline.
4. No new dependency without an entry in `docs/ADRs/` explaining why the existing set is insufficient, plus `cargo deny` justification if the license is not permissive.
5. Every new failure mode has a typed error variant and a documented recovery in `docs/RUNBOOK.md`.
6. A performance-sensitive change ships with a `criterion` before/after.

---

## Appendix A — Cross-compilation

```toml
# .cargo/config.toml
[target.aarch64-unknown-linux-gnu]
linker = "aarch64-linux-gnu-gcc"
runner = "r3s-deploy"            # scp + run on the Pi, for integration tests
rustflags = ["-C", "target-cpu=cortex-a76", "-C", "link-arg=-Wl,-z,now"]

[target.aarch64-unknown-linux-musl]
linker = "aarch64-linux-musl-gcc"
rustflags = ["-C", "target-feature=+crt-static", "-C", "target-cpu=generic"]
```

- Build matrix: `cortex-a76` (Pi 5), `cortex-a72` (Pi 4/CM4), `cortex-a53` (Pi 3/Zero 2), `generic` (musl, max compatibility). Publish all four; default to `generic` in the installer.
- `ring` builds for `aarch64-unknown-linux-musl` with a musl toolchain only; document `apt install musl-tools` in the build README. `aws-lc-rs` is feature-gated and out of the musl path.

## Appendix B — Systemd unit

```ini
[Unit]
Description=r3s container engine
After=network-online.target local-fs.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/local/bin/r3s daemon --config /etc/r3s/config.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=2
LimitNOFILE=1048576
LimitNPROC=infinity
TasksMax=infinity
Delegate=yes
# The engine manages its own cgroup subtree; this is mandatory.
Slice=system.slice
OOMPolicy=continue
StateDirectory=r3s

[Install]
WantedBy=multi-user.target
```

`Delegate=yes` and `Delegate=cpu cpuset io memory pids` on cgroup controllers are what allow `r3sd` to create its own subtree under systemd without systemd reclaiming it.

## Appendix C — Documented deviations from the brief

The brief's assumptions were checked against the current ecosystem; these are the places where the honest answer differs from the request, and the reason for each:

1. **`rkyv` is on `0.8`, not `1.0`** — there is no stable 1.0 release. `0.8.18` is used, which has the safe `access()` + `bytecheck` API. The `rancor` error type replaces the old `rancor::Error`/`Failure` re-exports used in older examples.
2. **Tokio over Glommio/Monoio** — the SSH management plane is the hard constraint (russh is Tokio-only), and at 4 cores a tuned multi-thread Tokio beats a thread-per-core runtime once you account for the second runtime plus bridge copies. Monoio is documented as a data-plane option for a future revision, not used in v1.
3. **`russh`, not thruster** — thruster is an HTTP server framework and provides none of the SSH transport/KEX/userauth required. The 0.63 `Handler` trait uses RPITIT (`fn … -> impl Future + Send`), so precise `impl Trait` capturing is available without `#[async_trait]`.
4. **`bincode` is not the hot path** — `rkyv` is, because the design goal is zero-copy reads from a memory-mapped snapshot. `bincode 3.0` handles config and API payloads.
5. **No `rocksdb`/`sled`** — RSS and flash-compaction behaviour are wrong for the target hardware. The store is purpose-built, with `redb` as the drop-in fallback behind a `StoreBackend` trait.
6. **A container "init" is required** — forking a payload that must be PID 1 of a new PID namespace means re-execing ourselves. This is not optional indirection: `unshare(CLONE_NEWPID)` does not move the *caller* into the new namespace, and `nix::unistd::fork` is `unsafe` precisely because calling it from a multithreaded daemon is dangerous. Hence `r3s container-init`.
7. **Password authentication is off by default** and SFTP/X11/forwarding channels are refused. Both are deliberate attack-surface reductions, documented, and configurable.
