# UNSAFE.md — Unsafe-code policy and justification register

The engine runs as root and manages kernel primitives on behalf of tenants. A memory-safety bug here is a host compromise. `unsafe` is therefore not banned — it is **rationed, located, justified, and budgeted**.

## 1. Policy

1. `unsafe` is permitted in **three crates only**: `r3s-store`, `r3s-runtime`, `r3s-net`.
2. Every other crate carries `#![forbid(unsafe_code)]` at the crate root. Not `deny` — `forbid` cannot be locally overridden.
3. Every `unsafe` block or `unsafe fn` must reference a **J-row** in the register below (a `// SAFETY: J-04` comment in the block is the accepted form).
4. The total unsafe byte count, measured with `cargo geiger`, is committed in `ci/unsafe-baseline.txt`. CI fails if it grows without a matching register update **and** an ADR.
5. New unsafe code is merged separately from the feature that uses it.

## 2. Register

| ID | Crate | What | Why it cannot be safe Rust | Blast radius | Verified by |
|---|---|---|---|---|---|
| J-01 | `r3s-store` | `mmap`/`munmap` of the snapshot and telemetry ring | Zero-copy reads from the store are a core performance requirement; copying defeats the design | Corrupt store (detected by `bytecheck`/CRC, not by memory corruption) | `snapshot.rs` unit tests (every header field is validated before a byte is read as data) + `cargo +nightly miri test -p r3s-store` |
| J-02 | `r3s-store` | `flock(LOCK_EX)` on `state/LOCK` | Single-writer guarantee against a second daemon instance | Two daemons on one node → store corruption | `crates/r3s-store/tests/integration/single_writer.rs`; the cross-process case is `#[ignore]`d until `r3s-bin` exists |
| J-03 | `r3s-runtime` | `fork` (via `nix::unistd::fork`, `unsafe fn`) | Rejected, re-exec is used instead — kept only for the PID-namespace init in `isolation.rs` | See J-04 | `ondevice/init_pidns.rs` |
| J-04 | `r3s-runtime` | `execve` of the container payload, `dup2` of stdio/PTY, `_exit` | `nix` exposes these; they are the container boundary itself | **Host compromise if arguments are wrong** | `ondevice/isolation_escape.rs` |
| J-05 | `r3s-runtime` | `unshare`/`setns`/`pivot_root`/`mount`/`umount2` | The entire isolation mechanism; `nix` wraps raw syscalls | Full host isolation loss if flags are wrong | `ondevice/isolation_escape.rs` (assert I2, I3) |
| J-06 | `r3s-runtime` | `prctl`/`capset`/`ambient` via `capctl` | Capability model | Privilege retention in container | `ondevice/caps.rs` |
| J-07 | `r3s-runtime` | `seccomp` BPF install (`seccompiler`) | Kernel API is a byte-code array; `seccompiler` generates it | Container running a syscall we forbade, or daemon unable to `execve` | `ondevice/seccomp.rs` (allowed-syscall probe binary) |
| J-08 | `r3s-net` | `rtnetlink` socket buffer construction | netlink has no safe high-level API for link/addr creation | Broken networking, or a malformed netlink message | `ondevice/network.rs` + nftables `I8` batch assertions |
| J-09 | `r3s-net` | `sendmsg`/`recvmsg` with `CMSG` (port-ID discovery) | Required to learn the assigned veth ifindex | Stale/wrong interface targeted | `ondevice/network.rs` |
| J-10 | `r3s-engine` (telemetry only) | `rkyv::access_unchecked` on the telemetry ring | Ring records are engine-written, fixed-size, engine-owned; `bytecheck` is measurable overhead at 1 Hz × N containers | Malformed record read → panic (not memory unsafety) | `fuzz/telemetry.rs` (arbitrary bytes must not cause UB) |
| J-11 | `r3s-store` | Raw `*const AtomicU64` cursors into the ring mapping, plus `unsafe impl Send`/`Sync` for `RingWriter`/`RingReader` | The cursors must *alias* the shared mapping: a struct that owns the `Mmap` and a cursor borrowing from it cannot be self-referential, and a cursor that copies the words would make every reader blind to later samples | A stale or freed cursor → data race or use-after-free on the ring header | `crates/r3s-store/src/ring.rs` (`a_reader_follows_the_writer_live`, `a_reader_across_threads_sees_the_writers_samples`) |

## 3. Rules for the code itself

**Async-signal safety.** Anything reachable between `fork`/`unshare` and `execve` in `r3s-runtime::isolation::child_main` must be async-signal-safe: no allocation, no logging, no `std::sync`, no panics. That function is the reason the design re-execs instead of forking the multithreaded daemon.

**No raw pointer crosses an `.await`.** Store fds as `OwnedFd`, never `*mut`/`*const` in a future. J-11 is the one place a raw pointer exists, and it is confined to the synchronous `push`/`head`/`tail` accessors of a struct that owns its own mapping.

**Parse before you trust.** mmap'd bytes from disk are untrusted input. `rkyv` safe `access()` with `bytecheck` is mandatory everywhere except J-10. `unsafe` accessors are forbidden in `r3s-proto` entirely.

**`unsafe trait`** is forbidden. If a trait needs `unsafe`, model it as a plain trait plus a documented precondition check in the constructor.

**Panics.** The daemon uses `panic = "unwind"`; a panic in a reconciler task is caught and turned into a failed action with backoff. `container-init` is built with `panic = "abort"` — a container init that panics must die loudly, not half-initialise.

**Leaks beat corruption.** On a failed `mount`/`pivot_root` in `child_main`, the process `_exit(127)`s; the reconciler reaps the scope. We never unwind a half-configured namespace.

## 4. Reducing the surface over time

- J-08/J-09: if `rtnetlink` gains typed constructors, migrate and delete the unsafe.
- J-03: removable entirely if we accept a static `r3s container-init` that only ever does `setns` + `execve` with no `fork` (we need the double-fork for PID-1 semantics, so this stays for now).
- J-10: removable by writing an explicit `#[repr(C)]` decoder for the ring instead of relying on rkyv's layout assumptions.
- J-02: removable by using `flock` from a crate (none adequate) or by moving the lock into the kernel (`O_TMPFILE` + `linkat`).
- J-11: removable by owning the cursors as real `&AtomicU64` in a self-referential struct (`ouroboros`, or by moving the header into a separate mapping handed out as `&'static`), at the cost of either another dependency or a leak per ring. Not worth it while the accessors are four lines each.

## 5. Verification commands

```bash
cargo geiger --invert > /tmp/unsafe.txt
diff -u ci/unsafe-baseline.txt /tmp/unsafe.txt   # must be empty

cargo +nightly miri test -p r3s-store            # mmap/byte-swap paths
cargo +nightly miri test -p r3s-proto            # rkyv archived round-trips

# isolation suite on real hardware (creates namespaces; needs root + a USB console)
./scripts/ondevice.sh pi.local isolation
```

Any diff in the geiger baseline without a new J-row is a **hard CI failure**, not a warning.
