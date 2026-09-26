# ADR-0002: Embedded russh server over system sshd

- **Status**: Accepted
- **Date**: 2026-09-25
- **Applies to**: `r3s-sshd`, `r3s-cli`

## Context

Requirement: management over SSH from a single Rust binary, with no external dependency on a system SSH daemon. This rules out "install OpenSSH and add a forced command", which was evaluated seriously because it is the least code.

The option space:

| Option | Provides | Cost / problem |
|---|---|---|
| System `sshd` + forced command | Transport, auth, PTY, forwarding for free | Requires OpenSSH on the node (breaks the single-binary thesis), forced-command wrappers are fragile (`$SSH_ORIGINAL_COMMAND` quoting, `~` expansion, TTY semantics differ between `-t` and `-T`), and per-command RBAC + audit must be reconstructed in a shell script |
| `thruster 1.3` + hand-written SSH | HTTP only | It is an HTTP middleware framework. It provides none of the SSH transport, KEX, or userauth. It is not a competitor here; it is a different protocol |
| `russh 0.63.3` | Complete SSH implementation, async, Tokio-native | We own the userauth policy and the channel surface |

## Decision

Embed `russh 0.63.3` in the daemon, on port 2222 by default.

- **Crypto backend: `ring 0.17`.** `aws-lc-rs 1.18` is faster on A76 but requires a C toolchain *and* BoringSSL cross-compilation for the `aarch64-unknown-linux-musl` build. That is an operator-host dependency for a marginal handshake gain on a 1–4 core board where the handshake is dominated by network RTT. `aws-lc-rs` remains available behind a feature flag and is re-evaluated if BASELINE §7 shows a real difference.
- **Handler trait**: the 0.63 `Handler` uses RPITIT (`fn … -> impl Future<Output = …> + Send`), so precise `impl Trait` capturing and inlining are available without `#[async_trait]` boxing.
- **Algorithms pinned** via `Preferred`: KEX `mlkem768x25519-sha256`, `curve25519-sha256`; host key ed25519; cipher `chacha20-poly1305@openssh.com`. `ssh-rsa` (SHA-1) and `diffie-hellman-group1-sha1` are **not offered**.
- **Channel policy**: `pty-req`, `exec`, `shell`, `env`, `window-change` are implemented. `subsystem_request` (SFTP), `x11_request`, `channel_open_x11`, `direct-tcpip`, `forwarded-tcpip`, and agent forwarding are **refused** — see [ADR-0007](0007-security-defaults.md).
- **DoS controls are in `Config`, not in handler code**: `max_auth_attempts = 3`, `auth_rejection_time = 300 ms` (russh does not do this by default — it is a real timing-attack surface), `inactivity_timeout = 900 s`, `window_size = 2 MiB`, `maximum_packet_size = 32 KiB`, plus a per-connection handshake budget in the accept loop and per-connection session caps.
- `authorized_keys` is read fresh on each auth attempt with a 1 s stat cache, so key rotation does not require a daemon restart.

## Consequences

### Positive
- One binary; nothing to install or keep patched on the node.
- RBAC, audit, and command routing are in-process and typed, not reconstructed in a shell wrapper.
- The management plane shares the engine's cancellation, metrics, and error model.

### Negative / costs accepted
- We own userauth correctness. Constant-time rejection and brute-force backoff are our responsibility, and they are tested ([THREAT_MODEL §4.1](../THREAT_MODEL.md)).
- russh is pre-1.0 and breaks its API between minor versions. This is a real maintenance cost; it is managed by pinning exactly and by a compile-fail-free upgrade being a dedicated, reviewed commit.
- SFTP is unavailable. An operator who expects it must use `r3s container cp`/tar-over-exec, which we have to provide ourselves.

### Follow-up work
- Interop matrix in CI against OpenSSH 8.x/9.x/10.x and libssh2 clients.
- `r3s container cp` to replace the SFTP workflow explicitly removed here.

## Alternatives considered

- **systemd `sshd` + `ForceCommand`** — rejected: breaks the single-binary requirement, forces a shell-based CLI, and makes RBAC/audit a bash problem.
- **Writing SSH from scratch** — rejected: KEX, curve25519, chacha20-poly1305, agent handling, and rekeying are not the interesting part of this project and are the classic place to ship a backdoor.
- **`thruster`** — rejected as categorically inapplicable (HTTP framework).
- **gRPC over SSH stdio-forwarding** — rejected: adds a protocol layer, an extra daemon process, and an operational failure mode, for no benefit on a single-node device.

## Revisit when

- russh reaches 1.0 (or is unmaintained for 6 months), **or**
- handshake measurement in BASELINE §7 shows `ring` costs > 20 % of handshake time on Pi 5, **or**
- `authorized_keys` re-read latency (1 s) is operationally too slow at fleet scale.
