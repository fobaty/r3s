# THREAT_MODEL.md

Scope: `r3sd` (engine daemon) and `r3s` (embedded SSH management plane) on a single ARM64 node. Written before the code, reviewed whenever a subsystem boundary changes.

## 1. Assets

| # | Asset | Why it matters |
|---|---|---|
| A1 | **Host root** | Full control of the physical device (camera, GPIO, network position). The engine runs as root. |
| A2 | **Container isolation boundary** | A container must never observe or influence the host or its neighbours. |
| A3 | **Node network position** | Egress IP, mDNS/LLMDP presence, ARP, local services. A compromised container must not reach them. |
| A4 | **SSH host keys and `authorized_keys`** | Management-plane access. |
| A5 | **State store + image CAS** | Integrity (a poisoned store is code execution at next boot) and confidentiality (specs may contain env vars, tokens). |
| A6 | **Audit log** | Non-repudiation of administrative actions. |
| A7 | **Peers in a cluster** | Node identity, mTLS keys, image cache trust. |

## 2. Adversaries

| Class | Capability | Realistic? |
|---|---|---|
| **AN1 Untrusted container workload** | Runs arbitrary code as `root` *inside* its namespace, with a network connection out. | Yes — this is the normal case. Assume the workload is hostile. |
| **AN2 Remote network attacker** | Reaches the SSH port from anywhere it is exposed. | Yes, on any node with port forwarding. |
| **AN3 Local unprivileged user** | A shell on the node without the management key. | Possible (default Pi images have a `pi` user). |
| **AN4 Compromised registry / MITM** | Serves a malicious or substituted image, or a crafted manifest/tar. | Yes, via typosquats and public mirrors. |
| **AN5 Malicious image author** | Crafts tar entries: traversal, symlink escapes, device nodes, setuid, decompression bombs. | Yes. |
| **AN6 Byzantine peer node** | Joins a cluster with a valid-enough identity, serves poisoned images. | Only in Stage 4+. |
| **AN7 Physical attacker** | Access to the SD card / UART. | Out of scope for in-scope mitigations; documented as residual risk. |

## 3. Trust boundaries

```
  AN2 ──SSH──▶ [ r3s-sshd :2222 ]  ← authn, RBAC, constant-time reject, brute-force backoff
                    │
                    ▼
              [ r3s-engine ]  ── declared vs observed state, single writer
                 │        │
        root     │        │  rkyv WAL + mmap snapshot (A5)
                 ▼        ▼
            [ r3s-runtime ] ── namespaces, cgroups, mounts, seccomp  ══ BOUNDARY ══▶ AN1
                 │
            [ r3s-net ]  ── netns, veth, nftables (A3)
```

Boundary rules:
1. **`r3s-sshd` → `r3s-engine`** is the only externally reachable path. No other listener exists unless `--enable-control-plane` is set (then `127.0.0.1` + mTLS only).
2. **`r3s-engine` → kernel** is the second boundary: every kernel object is created from a `ScopeSet` record written to the WAL *before* creation, so a crash is recoverable, never a silent leak.
3. **`r3s-engine` → container** is the third: spec validation happens in the engine, never in the container-init, and the container-init trusts only already-validated data.

## 4. Attack surfaces and mitigations

### 4.1 SSH management plane (AN2, AN3) — highest risk

| Threat | Mitigation | Residual risk |
|---|---|---|
| Brute force / credential stuffing | `max_auth_attempts = 3`; per-source-IP exponential backoff in a 256-entry LRU; constant-time rejection (`Config::auth_rejection_time`); password auth **off** by default with a per-connection warning | Distributed brute force is not rate-limited by IP — mitigated by key-only auth and network-level controls |
| Weak/legacy algorithms | `Preferred` pinned to `mlkem768x25519-sha256` / `curve25519-sha256` KEX, `chacha20-poly1305`; SHA-1 `ssh-rsa` and `diffie-hellman-group1-sha1` **not offered**; interop tested against OpenSSH 8/9/10 | A client that only speaks SHA-1 cannot connect — intended |
| Channel-based escalation (SFTP, X11, agent forwarding, TCP forwarding) | All refused in `channel_open_*`/`subsystem_request` — not "restricted", **refused** | None; these are not required by the brief |
| Slow-loris handshake | Per-connection 30 s budget in the accept loop; `inactivity_timeout = 900 s`; connection cap | Many slow connections can still occupy task slots; cap is the control |
| Resource exhaustion via many sessions | `max_sessions` per connection and a global cap; each session is a bounded task | — |
| Over-privileged key | `authorized_keys` `r3s-role=` option → per-command RBAC; `viewer` cannot mutate | A stolen `admin` key is game over — key hygiene is the operator's job (see RUNBOOK §5) |
| Privilege escalation via the CLI | The CLI is not a shell: no `;`, `|`, `&&`, globbing, or env expansion. A command maps to exactly one `Command` variant with a typed parser | Parsing bugs → fuzzed nightly |
| Audit tampering | Append-only log with a hash chain (`prev_hash` field); rotation keeps the chain | Root on the host can rewrite the file — residual, documented |
| Host key theft | Keys at `/etc/r3s/ssh/host_ed25519`, mode `0600`, generated on first boot with `0600` before write | Physical/AN7 |

### 4.2 Image ingestion (AN4, AN5)

| Threat | Mitigation |
|---|---|
| MITM / substituted layer | TLS with certificate validation; **content digest is authoritative** — sha256 is computed over the uncompressed stream and compared to the manifest digest; a digest mismatch aborts the pull |
| Registry credential leakage | Bearer tokens are held in memory only, never written to the store or the log; log filters redact `Authorization` headers |
| Path traversal (`../../etc/shadow`) | `LayerUnpacker` resolves every entry and rejects any path escaping the root → `PathEscape`; proptest + nightly fuzz |
| Symlink/hardlink escape | Symlink targets resolved against the extraction root; hardlink targets must already exist **inside** the root |
| Device nodes, setuid, setgid | Rejected by default (`ForbiddenNodeType`); only whitelisted with an explicit opt-in flag; capabilities are dropped in the container regardless |
| Decompression bomb | `max_unpacked_bytes` enforced *while* streaming; aborts the pull, no partial container |
| Manifest confusion (index vs image vs artifact) | Media-type is checked explicitly; unknown types are rejected, not guessed |
| Registry redirect to internal address (SSRF) | Redirects are limited to the same registry host, and private/loopback/link-local addresses are refused for the *initial* registry |
| Resource exhaustion during pull | Global pull semaphore (2 concurrent), per-image byte cap, resumable chunks |

### 4.3 State store (A5)

| Threat | Mitigation |
|---|---|
| Corrupted/hostile mmap read | `rkyv` safe `access()` with `bytecheck` on **every** untrusted read; `rkyv::access_unchecked` is used only on the engine-written telemetry ring (J-10) |
| Torn write on power loss | CRC32C per WAL record; a torn tail record is truncated on open (it was never acknowledged); snapshots are written to a temp file and `rename(2)`d |
| Snapshot corruption | CRC + `bytecheck` on load; fall back to WAL replay; if that also fails, quarantine (`state.quarantine.<ts>/`) and refuse to start with a clear message rather than booting with empty state |
| Two daemons on one node | `flock(LOCK_EX)` (J-02); second instance exits with a distinct error code |
| Secrets in the store | `ContainerSpec.env` values marked `Secret(bool)` are stored redacted; the real value lives in an in-memory map for the container's lifetime only, and is not persisted |
| Schema downgrade attack | `store_version` is checked and migrations are one-way; an unknown *newer* version is a refusal, never a downgrade |

### 4.4 Isolation boundary (A2) — against AN1

| Threat | Mitigation | Verified by |
|---|---|---|
| Mount escape | `pivot_root` into the overlay + `MNT_DETACH` of the old root + `MS_REC|MS_PRIVATE` at setup | `I2`, `I3` |
| Read-only rootfs bypass | `mount_setattr(AT_RECURSIVE, MOUNT_ATTR_RDONLY)` on the container root | `I3` (`EROFS` on write) |
| Capability retention | `cap_set` to the requested set only, `PR_CAPBSET_DROP` for everything else, `no_new_privs` set before `execve` | `ondevice/caps.rs` |
| Syscall abuse | seccomp filter from the OCI profile installed **last**; default-deny for the workload's own binaries, explicit allowlist for the shim | `ondevice/seccomp.rs` |
| `/proc` leaks host state | container's own pid namespace + `hidepid`-equivalent (unreachable by default), `/sys` mounted read-only | `I2` |
| Zombie / PID leak as a DoS | init reaps orphans (`SIGCHLD` → `SIG_IGN` + `waitpid(-1)`); `pids.max` bounds the blast radius | `ondevice/pids.rs` |
| cgroup escape | No cgroup file paths are writable by the container; the container's cgroup has no `cgroup.procs` write access from inside (the cgroup is owned by the parent hierarchy and the container is not privileged in it) | `I6` |
| Filesystem resource DoS | `memory.max`, `io.max`, `pids.max`, disk quota per container's `upper/` checked before pull | `I6` |

### 4.5 Network (A3)

| Threat | Mitigation |
|---|---|
| Container-to-container traffic by default | nftables `filter` chain, default **deny** between container subnets; the CLI must opt in (`network connect`) |
| Container-to-host/LAN (SSRF from inside) | Egress policy per container; the default policy denies access to RFC1918/loopback/link-local except explicitly published services |
| DNS exfiltration / resolution hijack | Per-container `resolv.conf` view; DNS queries are DNAT'd to the configured resolver and logged as audit events |
| Rule-set corruption by a partial write | All mutations in one `NFT_MSG_BATCH_BEGIN`/`COMMIT` transaction (`I8`) |
| Port collisions / squatting | Publishing a port is a store transaction; a collision is a `Conflict` error, never an override |
| nftables flushed externally (host compromise or misconfiguration) | Reconciler detects the missing table and re-installs it within one tick; the window is bounded and logged |

### 4.6 Cluster (AN6, Stage 4)

Node identity = Ed25519 keypair generated at first boot; the public half is the node's only cluster identity. Control plane is mTLS-only, binds `127.0.0.1` by default. Leader election uses a single fenced lease in the store (no two leaders can write). Peer-supplied images are always re-verified by digest **on the receiving node** — a peer cannot make us accept content by asserting its digest.

## 5. Explicitly out of scope

- Physical attacks (AN7), including SD-card tampering. Residual risk: an attacker with the card can replace the binary. Mitigation is filesystem integrity + signed artifacts, documented, not implemented.
- Side-channel attacks on crypto (constant-time is delegated to `ring`).
- Kernel exploits in overlayfs/netfilter — we reduce exposure, we do not fix upstream.
- Denial of service by an authorized `admin` key. The RBAC system is a safety rail against accidents, not against a hostile administrator.

## 6. Abuse cases to keep tested

These are regression tests, not prose. Each has a named test in the suite:

1. Container writes to `/proc/1/root/etc/shadow` → `ENOENT`/`EPERM`, never host write.
2. Container sends crafted `SSH_MSG_CHANNEL_OPEN` for `x11` → refused.
3. Container symlinks `/data -> /etc/shadow` in an image layer → `PathEscape` on pull.
4. Attacker replaces a layer blob after the digest is recorded → digest mismatch, pull aborts, blob quarantined.
5. Attacker writes a 40 GiB expansion from a 4 KiB gzip bomb → `max_unpacked_bytes` trips, disk does not fill.
6. `authorized_keys` is edited while 20 sessions are live → new key works, old sessions unaffected.
7. A user-supplied `PATH` of `false` binaries → full engine functionality unaffected.
8. A container sends `SIGKILL` to a host PID it guessed → `ESRCH` (it is in a different pid namespace).
