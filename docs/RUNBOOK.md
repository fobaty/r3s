# RUNBOOK.md

Operator procedures. Written to be followed at 3 a.m. on a headless Pi with no display.

Every error string quoted here is a real variant of a typed error in the codebase. `r3s errors` lists the full catalogue with the same strings.

## 0. Emergency index

| Symptom | Go to |
|---|---|
| Engine will not start, node is unreachable over SSH | §7 |
| Node is wedged / cannot create containers | §8 |
| All containers gone after a power cut | §9 (state recovery) |
| Suspected compromise | §10 |
| Disk full | §6.1 |
| Container OOM-killed unexpectedly | §6.2 |
| SSH auth failing after a key change | §5 |

## 1. Install and first boot

```bash
scp r3s-aarch64 pi.local:/tmp/
ssh pi.local 'sudo install -m 0755 /tmp/r3s-aarch64 /usr/local/bin/r3s'
ssh pi.local 'sudo systemctl enable --now r3s'
ssh pi.local 'r3s system info'      # preflight + kernel facts
```

**Preflight is not optional.** `r3s system info` must print, without errors:

```
kernel            6.12.x  (>= 6.1 required)
cgroup v2         unified, controllers: cpuset cpu io memory pids
overlayfs         yes (unprivileged: yes)
netfilter         nftables
landlock          ABI 4
engine scope      r3s-system.slice active
```

If `cgroup v2` says `hybrid`, the host is on cgroup v1 → **r3s will not run**. Fix the host (Pi OS 64-bit bookworm+ only), do not attempt a workaround.

Config lives at `/etc/r3s/config.toml` (`r3s config show` prints the effective, resolved config including defaults).

## 2. Day-2 operations

```bash
r3s image pull ghcr.io/org/app:1.4.2
r3s container run --name api --cpus 500m --memory 256M -p 8080:8080 ghcr.io/org/app:1.4.2
r3s container ls
r3s container inspect api            # includes OOM attribution, restart history
r3s container stats --no-stream
r3s container logs api -f
r3s limit set api --memory 384M      # live, no restart
r3s volume create data --size 2G
r3s container run --volume data:/var/lib/app --name api --rm alpine:3 du -sh /var/lib/app
```

Machine output: append `--format json`. **stdout is data, stderr is diagnostics** — safe to pipe.

Exit codes: `0` ok · `1` runtime error · `2` usage · `3` not found · `4` conflict · `5` resource exhausted · `10` auth/RBAC denied.

## 3. Logging

| Stream | Destination | Rotation |
|---|---|---|
| Structured logs | journald (`journalctl -u r3s -f`) | `logrotate`, 8 MiB × 5 |
| Audit | `/var/log/r3s/audit.log` (append-only, hash-chained) | 4 MiB, chain carried in the header |
| Container logs | `/var/lib/r3s/containers/<id>/logs/` (bounded, 10 MiB default) | ring |

```bash
r3s system audit --since 24h --role admin
journalctl -u r3s -p warning --since -1h
```

## 4. Backups

Back up **state** (small) and **volumes** (potentially large). The image CAS is reconstructible from the registry and does not need backing up, only the *pins* in state do.

```bash
r3s system backup --to /mnt/usb/backup-$(date +%F)   # consistent, engine-quiesced
r3s system restore --from /mnt/usb/backup-2026-09-25
```

A backup taken while pulls are in flight is still consistent: the engine quiesces the writer (no new commands for the duration, ≤ 5 ms stall).

## 5. SSH key rotation

```bash
# 1. Add the new key (no restart; stat-cached, ≤1 s to take effect)
sudo sh -c 'echo "ssh-ed25519 AAAA...new-key-comment r3s-role=admin" >> /etc/r3s/authorized_keys'

# 2. Verify it works BEFORE removing the old one
ssh -i new_key root@pi.local 'r3s system status'

# 3. Remove the old key
sudo r3s ssh key rm <fingerprint>          # fingerprint is printed by `r3s ssh key ls`

# 4. Rotate the host key (new connections only; existing sessions drop)
sudo r3s ssh hostkey rotate
```

Never remove the last working key over an SSH session you are currently using — that is how a node becomes unmanageable. Use a second session to verify.

## 6. Failure catalogue

### 6.1 `ResourceExhausted{resource:"disk"}` / `Io { path: ".../upper", source: ENOSPC }`

```bash
r3s system status                      # disk usage breakdown
r3s image prune --filter unused=true   # images not referenced by any container
r3s system prune --volumes             # DESTRUCTIVE: unreferenced volumes only
du -sh /var/lib/r3s/images /var/lib/r3s/containers /var/lib/r3s/state
```

If state is large, the WAL is not compacting:

```bash
r3s system stats --wal                # wal_records, wal_bytes, last_snapshot_age
```

High `wal_records` with a recent snapshot means a failing action is looping. Check `journalctl -u r3s | grep -i retry`.

### 6.2 Container exited with `oom_killed: true`

```bash
r3s container inspect <id>             # memory.current at exit, memory.events counters
r3s limit set <id> --memory 512M
r3s container logs <id> --tail 200
```

`memory.oom.group=1` means the kernel killed the whole cgroup. If the container is repeatedly OOM-killed with a stable memory usage, the limit is simply too low for the workload; if usage climbs, it is a leak in the workload.

### 6.3 `CgroupError::Busy { path: "...slice" }`

The no-internal-processes rule was violated — a process is in a cgroup whose `subtree_control` has controllers enabled. This is a bug, not a condition. Capture and report it:

```bash
cat /sys/fs/cgroup/r3s.slice/cgroup.procs
cat /sys/fs/cgroup/r3s.slice/cgroup.subtree_control
journalctl -u r3s | grep -i "cgroup write" -A2
```

Workaround while investigating: `r3s daemon --slice-mode=flat` places the engine in a leaf of its own so slices never inherit engine processes. Do not use as a permanent fix.

### 6.4 `CgroupError::MissingController("io")` at boot

`io` is not in the kernel's `cgroup.controllers`. Either the controller is not bound, or the host is a cgroup v1 hybrid. This is a **startup** failure by design — the engine refuses rather than silently losing the I/O limit. Fix the host.

### 6.5 `nftables: transaction commit failed: EBUSY` / rules keep disappearing

Something outside r3s is flushing netfilter. The reconciler re-installs within a tick; if it is failing continuously, another agent (docker, ufw, firewalld) owns the ruleset. **Pick one owner.** On Pi OS, disable `ufw`/`firewalld` and let r3s own `inet r3s`:

```bash
nft list ruleset | head -40          # see who else is writing
systemctl stop firewalld ufw
r3s network reload                   # re-apply the whole table atomically
```

### 6.6 `store: snapshot failed bytecheck` / `store: WAL CRC mismatch` / `store is damaged: WAL segment …`

The store detected damage it cannot explain as a crash and **refuses to open**. Nothing is written and nothing is deleted on that path — not the snapshot, not the segment, not a byte — because the damaged frame is the evidence. A damaged *snapshot* is different and is not fatal: the store falls back to the previous snapshot, or rebuilds from the WAL if none survives, and reports what it rejected (`store open` log line, `r3s system status --store-only`).

```bash
sudo systemctl stop r3s
cp -a /var/lib/r3s/state /var/lib/r3s/state.bad.$(date -u +%Y%m%dT%H%M%SZ)   # keep the evidence
ls -la /var/lib/r3s/state/wal/       # which segment, how large
sudo r3s system recover --from-wal   # replay the intact prefix into a fresh snapshot
```

The error names the segment and byte offset, and `CorruptionReason` distinguishes the four causes — frame header CRC, payload CRC, bad magic, length out of range. Bad magic or an out-of-range length usually means something else wrote to that file; a payload CRC usually means the SD card. Read the reason before restoring: a payload CRC that repeats on the same sector every run is a card, not an r3s bug.

If recovery fails, start with a clean store (containers are re-created from `config.rkyv` in the container dirs if those survived, otherwise from `backup/`).

### 6.7 `auth: too many authentication attempts`

Expected after 3 failures. If the legitimate key is rejected, see §5. Rate limit is per source IP with exponential backoff; it clears on its own (max 15 min) or:

```bash
sudo r3s ssh ratelimit clear --all
```

### 6.8 SSH connects but the shell hangs at the prompt

Almost always a `pkg`/channel-buffer issue on the client, not the server. Verify with a non-interactive command:

```bash
ssh -T root@pi.local 'r3s system status'     # must return text and exit 0
```

If `-T` works and interactive hangs, the PTY allocation path is at fault: `journalctl -u r3s | grep -i pty`. Collect and report; the fallback is `r3s exec -it` from a `-T` session.

## 7. Engine will not start

```bash
systemctl status r3s
journalctl -u r3s -b -p err --no-pager | tail -50
r3s system doctor          # runs preflight read-only, safe to run anywhere
```

Order of diagnosis:
1. Preflight failure (`cgroup`, `overlayfs`, `netfilter`) → host kernel/config problem, §1.
2. `flock` on `state/LOCK` held → another daemon is running, or a stale PID file. `sudo fuser /var/lib/r3s/state/LOCK`.
3. Port `:2222` in use → `sudo ss -ltnp | grep 2222`. Change `ssh.bind` in the config, do not fight it.
4. Store failure → §6.6.
5. `Delegate=yes` missing from the systemd unit → the engine cannot create its cgroup subtree. Reinstall the unit (Appendix B of ARCHITECTURE.md).

Last resort, keeping the node reachable:

```bash
sudo systemctl stop r3s
sudo r3s daemon --foreground --no-ssh --no-network --no-reconcile
# then inspect the store with `r3s system status --store-only`
```

## 8. Node wedged

Symptoms: containers start but immediately die, or `container run` hangs.

```bash
# Is it the engine or the kernel?
top -b -n1 | head -20                 # load, steal time
cat /proc/pressure/{cpu,memory,io}    # PSI — the fastest way to find the stall
dmesg -T | tail -50                  # OOM kills, overlay errors, netlink errors
r3s system stats --rss               # engine memory
```

- `memory` pressure high + container OOMs → lower limits (§6.2).
- `io` pressure high + everything slow → SD card. Move `state/` to an SSD/USB via a bind, or set `state.wal_tmpfs = true` for the WAL only.
- Load average ≈ ncores with no container accounting → the engine is spinning: `strace -p $(pidof r3s) -c -f -w` for 5 s, then report.
- Load from a container → `r3s container stats --no-stream`, then stop it.

## 9. State recovery after power loss

The engine is designed for this: declared state is in the store, observed state is re-sampled at boot, and the reconciler converges. The only manual step is quarantining any partial object.

```bash
r3s system status                     # declared vs observed diff
r3s system reconcile --dry-run         # prints the actions it *would* take
r3s system reconcile
```

Common partial objects after power loss:

| Leftover | Detection | Fix |
|---|---|---|
| Stale veth | `ip -o link show \| grep veth` vs declared | `r3s system sweep` (automatic on boot) |
| Stale mount | `findmnt -t overlay` | `r3s system sweep` unmounts with `MNT_DETACH` |
| Stale cgroup | `find /sys/fs/cgroup -name 'r3s-*.scope'` | `r3s system sweep` |
| Stale netns | `ip netns list` | `r3s system sweep` |

If `r3s system status` shows a diff that persists after 3 reconcile cycles, capture `r3s system doctor --json` and open an issue with the output. Do not hand-`rmdir` cgroups: it hides the bug that produced them.

## 10. Suspected compromise

```bash
# Freeze evidence first, then act.
sudo cp -a /var/log/r3s /tmp/r3s-audit-$(date +%s)
sudo cp -a /var/lib/r3s/state /tmp/r3s-state-$(date +%s)
r3s system audit --since 7d --json > /tmp/r3s-audit.json

# Revoke management access
sudo r3s ssh key rm <fingerprint>
sudo r3s ssh hostkey rotate

# Isolate the workload
r3s network isolate <container>        # deny-all egress for one container
r3s network set-policy <container> --default deny

# Then, in this order:
#   1. rotate SSH keys and cluster identity
#   2. re-pull and re-deploy every image from a trusted registry (digests change)
#   3. wipe the store:  sudo mv /var/lib/r3s/state /var/lib/r3s/state.bad
#   4. treat the host as compromised if root-level persistence is suspected
```

A container with root-equivalent access inside its namespace is a much smaller problem than one that escaped. `docs/THREAT_MODEL.md` §6 lists the regression tests that prove the escape paths stay closed.

## 11. Upgrade

```bash
r3s version                            # current
sudo r3s system backup --to /mnt/usb/pre-upgrade
scp r3s-<arch> pi.local:/tmp/
ssh pi.local 'sudo install -m 0755 /tmp/r3s-<arch> /usr/local/bin/r3s.new \
  && sudo mv /usr/local/bin/r3s.new /usr/local/bin/r3s \
  && sudo systemctl restart r3s && r3s system status'
```

Schema migrations run automatically on open and are logged (`store: migrated v3 -> v4`). Downgrade is not supported: the store records the version it was written with. To roll back, restore the pre-upgrade backup.

## 12. Running the tests

```bash
# host: compiles, lints, unit tests, and host microbenchmarks
cargo nextest run --workspace
./scripts/bench.sh

# device: capability matrix, then benchmarks, then a leak-hunting soak
./scripts/ondevice.sh              # here, on the device
./scripts/ondevice.sh pi.local     # over ssh, as root
./scripts/bench-ondevice.sh pi.local
sudo R3S_REPEAT=1 ./scripts/soak.sh --duration 30m
```

The `host` form runs a checkout **on the device**, not this one: it looks for
`$R3S_REMOTE_ROOT` (`~/r3s` by default) with `scripts/lib.sh` in it, and the
report is pulled back into `target/reports/` here. Clone the repo on the node
once (`ssh pi.local 'git clone <url> ~/r3s'`) or pass
`R3S_REMOTE_ROOT=/srv/r3s`.

Every device run writes a JSON report to `target/reports/` (uploaded as a CI artifact by the `ondevice` workflow). A report entry with `"status": "skip"` is not a pass: it means the check could not run, and the report must not be read as full coverage.

The on-device suite creates namespaces, mounts overlays, and writes cgroups. It will hard-lock a node without a serial console if the kernel panics. Do not run it on a node you cannot physically reach.

## 13. Script and CI failures

These are operator-visible failures of the tooling, not of the engine. Each one names the file to fix rather than the subsystem.

| Symptom | Cause | What to do |
|---|---|---|
| `error: ssh not found; install openssh-client` | running `deploy.sh` / remote `ondevice.sh` from a minimal host image | install `openssh-client`, or run the script on the device instead |
| `error: cannot reach root@pi.local` | wrong host, no key, or the node is down | `ssh -v root@pi.local`; the script never retries, because a deploy that hangs hides a dead node |
| `error: no r3s checkout on root@pi.local at '/root/r3s'` | remote run, but the repo is not cloned there (or is somewhere else) | `ssh pi.local 'git clone <url> ~/r3s'`, or `R3S_REMOTE_ROOT=/path/to/r3s ./scripts/ondevice.sh pi.local` |
| `warn: the report stayed on the device … and was not pulled back` | the remote run finished but `sudo cat` over ssh failed (key without passwordless sudo, or the report was never written) | read it on the node: `sudo cat /root/r3s/target/reports/*.json`; a missing report means the suite died before its first line of output |
| `error: …/r3s not built; crates/r3s-bin is not implemented yet` | the engine binary does not exist yet in this tree | expected while the runtime is unimplemented; not a regression |
| `error: run as root: cgroup and namespace work needs it` | benchmark or soak without privileges | `sudo`; the number would be meaningless otherwise |
| `error: 3 check(s) failed on this device` | a capability assertion in `ondevice.sh` failed | read the named check in `target/reports/ondevice-*.json`; §6.3/§6.4 cover the cgroup cases |
| `error: only 2 samples; shorten the sample interval` | soak ended before the leak detector had enough points | raise `--duration` or lower `--sample`; a trend cannot be decided from two points |
| `warn: RSS grew 61% (limit 25%)` | the engine leaks across container lifecycles | this is a real bug, not a threshold problem: bisect by crate and file a report with the report path |
| `warn: cgroup directories leaked: 4` | cgroups are not being removed on teardown | same as above; check `cgroup.kill` and the `cgroup.events` pop handler |
| `the unsafe surface changed` (CI) | a new `unsafe` block appeared or an old one moved | add a justification row in `docs/UNSAFE.md` first, then update `ci/unsafe-baseline.json` in the same commit |
| `error: unknown codegen option: ' target-cpu'` | `RUSTFLAGS` was set with a stray leading space | `unset RUSTFLAGS`; `scripts/build.sh` sets it correctly per board |

## 14. Measurement protocol

`docs/BASELINE.md` is only ever edited by a human, and only from a report in `target/reports/` produced on the board in question. Every number carries the command that produced it. A host number, a number copied from a datasheet, or a number estimated from a previous release does not go in. Unmeasured fields stay `TBD` in the document and `null` in the report.
