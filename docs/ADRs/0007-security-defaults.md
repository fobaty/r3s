# ADR-0007: Deny-by-default security posture

- **Status**: Accepted
- **Date**: 2026-09-25
- **Applies to**: `r3s-sshd`, `r3s-runtime`, `r3s-net`, `r3s-image`, `r3s-cli`

## Context

The engine runs as root, accepts remote input over SSH, unpacks archives from the network, and grants network access to code it did not write. Every one of those is a privilege-escalation surface, and the project has no security team — it has one engineer and a threat model.

There is a real tension in scope: the obvious convenience features (password auth, SFTP, X11 forwarding, per-container netfilter rules) are each individually defensible and collectively the majority of the attack surface of any SSH daemon.

## Decision

**Everything is off unless explicitly requested, and requesting it is loud.**

**Management plane**
- Password authentication **disabled by default**; enabling it prints a warning to every connecting client and logs a `WARN` per use.
- `authorized_keys` only. `r3s-role=` key option maps a key to `viewer`/`operator`/`admin`; every command is checked against the role's capability set before parsing side effects.
- SFTP, X11, agent forwarding, and TCP/stream-local forwarding channels are **refused**, not restricted. They are not required by the brief.
- `MaxAuthTries = 3`, constant-time rejection (`auth_rejection_time = 300 ms`), per-source-IP exponential backoff, session caps, handshake timeout.
- Legacy algorithms (`ssh-rsa`/SHA-1, `dh-group1-sha1`) are not offered.
- Every mutating command is audit-logged with principal fingerprint, argv, result and duration, into a hash-chained append-only log.

**Container**
- Read-only rootfs via `pivot_root` + `mount_setattr(AT_RECURSIVE, RDONLY)`; `no_new_privs` before `execve`; capability set is exactly what the spec requests, bounding set dropped; `PR_SET_NO_NEW_PRIVS` on every bind that does not opt out; seccomp filter installed last.
- Default network policy is **deny between containers and deny to LAN/loopback/link-local**, with published ports and egress as explicit grants.
- Image layers: digest verified over the uncompressed stream; traversal, symlink/hardlink escape, device nodes and setuid rejected; decompression capped by `max_unpacked_bytes`.

**Degradation is reported, never assumed.** If Landlock is unavailable (< 5.13) or nftables is missing, `r3s system info` says so explicitly. We never report a security posture we are not actually enforcing.

## Consequences

### Positive
- The management-plane attack surface is one protocol, three algorithms, one auth method, and zero channel types.
- Operators cannot accidentally expose `admin` to a colleague who only needs `r3s container ls`; keys are cheap to issue per role.
- Every operator-visible security state is queryable, so "is this node actually enforcing what you think" is a command, not an audit.
- Each removed feature is a class of bug we do not have (no SFTP path traversal surface, no X11 MITM surface, no forward-tunnel pivot surface).

### Negative / costs accepted
- **No SFTP.** `r3s container cp` / tar-over-exec must be written to cover the workflow, and it is our own code to maintain — arguably the same risk, differently shaped. Accepted because it also removes the dependency, not adds one.
- Password auth being off-by-default is friction for the "quick test on my Pi" case. The mitigation is a one-line config flag, and the friction is intentional.
- RBAC adds a capability check to every command and a role column in `authorized_keys` that operators will get wrong. Mitigated by `r3s ssh key ls` printing the effective role per fingerprint.
- Per-container network policy is coarse: a container that needs a custom egress path gets a named chain. Rich policy is deferred until there is a demonstrated need.

### Follow-up work
- `r3s container cp` before v1.0.
- Rate-limited "suspicious activity" alerting to the audit log (N failed auths, N image failures).

## Alternatives considered

- **Password auth on by default** — rejected: any SSH service with passwords on a network-exposed port is a scanning target; key-only costs operators 5 minutes and costs us nothing.
- **Implement SFTP** — rejected: it is the largest single attack surface in any SSH daemon (path traversal, symlinks, ACLs, quota) and is not required.
- **Fine-grained capability sets (a real capability system)** — rejected for v1: role × command-group is enough for a single-node device, and a capability system is a large design in itself.
- **AppArmor/SELinux profiles instead of seccomp** — rejected: profile management on Pi OS is manual, out-of-band, and unverifiable from the engine. seccomp is defined by the container spec, so it is enforceable and testable. Landlock is added as an opportunistic extra.
- **Per-container iptables chains for isolation** — superseded by [ADR-0006](0006-firewall-nftables-transactions.md) on scalability grounds.

## Revisit when

- A second operator class needs programmatic access (CI, GitOps) → revisit fine-grained capabilities and a non-interactive API.
- A concrete use for SFTP/X11/forwarding appears → add it as an explicit, off-by-default feature with its own threat-model section and fuzz target.
