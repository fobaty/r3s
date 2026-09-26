# ADR-0004: Re-exec `r3s container-init` instead of forking the daemon

- **Status**: Accepted
- **Date**: 2026-09-25
- **Applies to**: `r3s-runtime`, `r3s-engine`

## Context

A container needs new PID, mount, network, UTS, IPC, user and cgroup namespaces, a new root via `pivot_root`, dropped capabilities, rlimits, and a seccomp filter — applied to the payload *before* `execve`.

The obvious implementation is `Command::pre_exec` on the daemon, or `fork` in the daemon. Both are wrong here, for reasons that are not stylistic:

1. **Between `fork` and `execve`, only async-signal-safe calls are legal.** That means no allocation, no logging, no `std::sync`, no panics. The daemon's container setup path wants all of those (it needs error reporting with a path and errno). Getting this wrong produces intermittent, unreproducible hangs in the child — the classic `fork` in a multithreaded program failure.
2. **`nix::unistd::fork` is `pub unsafe fn`** in 0.31 precisely because of this contract. A safe wrapper cannot exist; the compiler cannot verify it.
3. **Rust's own guidance** is that `Command::spawn` + `pre_exec` is a footgun: the closure runs in a forked child of a multithreaded process, and std cannot make it safe.
4. **`unshare(CLONE_NEWPID)` does not move the caller.** The calling process stays in the old PID namespace; only *its children* are in the new one. Something must fork after the `unshare`, or PID 1 of the container is not the process we configured.
5. Re-entering our own binary as the container init means the setup code is a **fresh process at `main`**, with the whole program available for `#[global_allocator]`, error handling, and logging — none of which is available in the `pre_exec` window.

This is exactly why runc, crun, and containerd all ship a separate init process.

## Decision

The daemon spawns **itself** with a distinct argv:

```
r3s container-init --bundle /var/lib/r3s/containers/<id> --config <path>
```

`r3s-runtime::isolation::child_main` is that entry point. It:

1. `setns` into the user namespace (if rootless) and becomes uid 0 inside it — first, because every later mount would otherwise fail with `EPERM`.
2. `unshare` the remaining namespace flags.
3. Makes all mounts `MS_REC|MS_PRIVATE` so nothing propagates back to the host.
4. Self-binds the rootfs, marks it recursively read-only via `mount_setattr`, `pivot_root`, then `umount2(MNT_DETACH)` the old root and `rmdir` the put_old dir.
5. Mounts `/proc`, `/dev` (tmpfs + bind of the six standard devices), read-only `/sys`.
6. Applies declared bind mounts, then rlimits, then **seccomp last** (after it, only `open/read/write/exit_group` remain).
7. `fork()`s: the child is PID 1 in the new namespace, reaps orphans, and `execve`s the payload. The parent reports the ns-init PID to the daemon and pauses forever.
8. The daemon tracks the ns-init PID with `pidfd_open` so PID reuse can never make a signal hit the wrong process.

The parent records every kernel object in a `ScopeSet` **written to the WAL before the object is created**, so a crash mid-setup is recoverable rather than a leak.

## Consequences

### Positive
- The container boundary runs in a clean, single-threaded process at `main`. Normal Rust error handling applies; panics are contained.
- `nix::unistd::fork` appears exactly once, in a function whose contract is documented in the code ([UNSAFE.md J-03/J-04](../UNSAFE.md)).
- Reuse of the existing binary: no second artifact, no version skew between daemon and runtime.
- `r3s exec` is symmetric: the daemon `setns`es into the same namespaces using the fds it already holds open.

### Negative / costs accepted
- One extra `execve` of ourselves per container (~1–2 ms). Measured in BASELINE; accepted as the price of correctness.
- The init path must be `async`-free and allocation-light enough to be signal-safe, which constrains how it may be written.
- The binary must be present on the node for containers to start. It already is, by definition.

### Follow-up work
- Consider a `r3s-init` static/musl helper binary if a node ever runs a different `r3sd` from a different root.

## Alternatives considered

- **`Command::pre_exec`** — rejected: async-signal-safety contract, and the closure cannot report a useful error.
- **Raw `fork()` in the daemon** — rejected: same contract problem, plus forking a Tokio runtime's process is a class of bug we do not want in a runtime.
- **A separate `r3s-init` binary** — rejected for now: doubles the release artifacts and the version-skew surface for no benefit while the daemon and init are the same file. Kept as an option if the init must run in a different mount/PID context than the daemon.
- **A persistent per-container shim that reaps and proxies** (containerd's model) — rejected: an extra long-lived process per container costs ~1 MB RSS × N on a 512 MB board for behaviour we do not need yet. Revisit if we need log multiplexing or zombie reaping outside the container.

## Revisit when

- A per-container shim is needed for log fan-out to multiple attach points (then the execve cost is irrelevant and the shim is justified on its own merits).
