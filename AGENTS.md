# AGENTS.md — Engineering rules for `r3s`

**Read this before touching code.** The full design lives in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md); this file is the *short* version that must be obeyed without exceptions.

## What this project is

A bare-metal-grade container + data orchestration engine for ARM64 single-board computers. One Rust binary, no `docker`/`podman`/`containerd`/`runc`/`ip`/`nft`/`tar` process is ever spawned. Management happens over an embedded SSH server.

## Non-negotiables

| Rule | Enforcement |
|---|---|
| Rust **1.98+**, `edition = "2024"`, workspace `resolver = "3"` | CI `cargo +1.98.0 check` |
| `unsafe` **only** in `r3s-store`, `r3s-runtime`, `r3s-net`; every other crate has `#![forbid(unsafe_code)]` | `cargo geiger` vs. committed baseline |
| Every `unsafe` block links a justification entry in [`docs/UNSAFE.md`](docs/UNSAFE.md) | reviewer + geiger diff |
| No new dependency without an ADR in [`docs/ADRs/`](docs/ADRs/) | review |
| Single writer to the state store, ever | `Store` API has no `&mut self` outside the reconciler |
| No shelling out to system tools for kernel work (netlink/cgroupfs/mount only) | review + `PATH=/nonexistent` integration test |
| Errors: `thiserror` in libraries, `anyhow` only in `bin` | clippy + review |
| Every new failure mode has a typed error variant **and** a `docs/RUNBOOK.md` row | review |
| Namespace/mount/cgroup changes require an **on-device** test on real hardware | CI job `ondevice` |

## Commands

```bash
# host (aarch64 or x86_64 dev box)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run                      # unit + host-safe integration
cargo doc --no-deps --workspace        # warnings are errors in CI
cargo deny check                       # licenses + bans
cargo geiger --invert                  # unsafe surface must not grow

# device
./scripts/build.sh --board pi5 --target aarch64-unknown-linux-gnu --release
./scripts/deploy.sh pi.local           # build aarch64 + scp + restart systemd unit
./scripts/ondevice.sh pi.local         # on-device integration suite (needs root)
./scripts/bench-ondevice.sh           # numbers for docs/BASELINE.md (needs root)
./scripts/soak.sh --duration 6h       # leak hunt: RSS, fds, cgroup dirs
```

Release profile is fixed in the root `Cargo.toml` (`lto = "fat"`, `codegen-units = 1`). Do not change it per-crate.

## Style

- Match the surrounding code. No new abstraction layers without a reason in a comment explaining **why**.
- Comments explain *why*, never *what*. English only.
- Prefer a `match` over `if` chains for state machines; transitions live in exactly one function (`Phase` legality) and are table-tested.
- `unsafe` code must be `async-signal-safe` if it can run between `fork` and `execve` (see `r3s-runtime::isolation::child_main`).
- Never fabricate a measurement. Performance claims go in [`docs/BASELINE.md`](docs/BASELINE.md) with a reproduction command or they do not go in the docs.

## Definition of done

1. `fmt` + `clippy -D warnings` + `doc` + `nextest` green on host.
2. On-device suite green if the change touches namespaces, cgroups, mounts, netlink, or nftables.
3. ADR added or updated if a dependency, a data format, or a subsystem boundary changed.
4. `docs/RUNBOOK.md` updated for any new operator-visible failure.
5. `unsafe` surface did not grow, or `docs/UNSAFE.md` was updated with a justification and the reviewer agreed.

## Where to look

| Question | File |
|---|---|
| How does it work? | `docs/ARCHITECTURE.md` |
| Why this crate and not the other one? | `docs/ADRs/` |
| Is this `unsafe` allowed? | `docs/UNSAFE.md` |
| What can go wrong and who can attack it? | `docs/THREAT_MODEL.md` |
| It is 3 a.m. and the node is broken. | `docs/RUNBOOK.md` |
| Is it fast enough? | `docs/BASELINE.md` |
