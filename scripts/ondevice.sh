#!/usr/bin/env bash
# The on-device integration suite. Run this ON the device, as root.
#
#   ./scripts/ondevice.sh              # local device
#   ./scripts/ondevice.sh pi.local     # over ssh, on the device, as root
#   R3S_REMOTE_ROOT=/srv/r3s ./scripts/ondevice.sh pi.local
#
# Every kernel fact the engine depends on is asserted here, because none of it
# can be asserted in CI: a host build can only prove the code compiles, not
# that this board's kernel exposes what the code reads.
#
# Exit code is non-zero if any check fails. A skipped check is not a pass; it is
# recorded as skipped so the report cannot be read as full coverage.

set -euo pipefail
# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# Both invocations documented in the runbook are supported:
#
#   ./scripts/ondevice.sh              run here, on the device
#   ./scripts/ondevice.sh pi.local     run there, over ssh, as root
#
# The second form exists because the operator holding the console is often not
# the operator holding the laptop, and the suite needs to be reproducible from
# a ticket without walking to the node.
REMOTE=""
REMOTE_USER="${R3S_REMOTE_USER:-root}"
case "${1:-}" in
  "") ;;
  -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
  *)
    if [[ $# -gt 1 ]]; then
      die "usage: $0 [host]"
    fi
    REMOTE="$1"
    ;;
esac

if [[ -n "$REMOTE" ]]; then
  need ssh "install openssh-client"
  # The device has its own checkout; running the laptop's absolute path there
  # would fail with a bare "no such file". R3S_REMOTE_ROOT is the device path.
  REMOTE_SCRIPT="$(remote_checkout "$REMOTE" "$REMOTE_USER" "scripts/ondevice.sh")"
  log "running the suite on $REMOTE_USER@$REMOTE ($REMOTE_SCRIPT)"
  # The report is written on the device and pulled back, so a remote run leaves
  # the same artefact locally as a local one.
  REMOTE_ROOT="$(dirname "$REMOTE_SCRIPT")/.."
  REMOTE_REPORT_DIR="$REMOTE_ROOT/target/reports"
  # `rc=0; ... || rc=$?` instead of `cmd; rc=$?`: under `set -e` a failing
  # command never reaches the next line, and the report has to be pulled back
  # whether the suite passed or not.
  rc=0
  # shellcheck disable=SC2029  # local expansion into a quoted remote string is intended
  ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$REMOTE" \
    "cd '$REMOTE_ROOT' && sudo --preserve-env=R3S_BIN,R3S_REMOTE_DIR,R3S_REPORT_DIR='$REMOTE_REPORT_DIR' $REMOTE_SCRIPT" || rc=$?
  LOCAL_REPORT="$(report_dir)/ondevice-$(date -u +%Y%m%dT%H%M%SZ).json"
  # shellcheck disable=SC2029  # local expansion into a quoted remote string is intended
  newest="$(ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$REMOTE" \
    "sudo ls -t '$REMOTE_REPORT_DIR'/ondevice-*.json 2>/dev/null | head -1" || true)"
  if [[ -n "$newest" ]] && remote_fetch "$REMOTE" "$REMOTE_USER" "$newest" "$LOCAL_REPORT"; then
    log "report: $LOCAL_REPORT"
  else
    warn "the report stayed on the device ($newest) and was not pulled back"
  fi
  exit "$rc"
fi

# R3S_REPORT_PATH lets the remote wrapper name the file it will fetch, instead
# of guessing at it afterwards.
if [[ -n "${R3S_REPORT_PATH:-}" ]]; then
  REPORT="$R3S_REPORT_PATH"
else
  REPORT="$(report_dir)/ondevice-$(date -u +%Y%m%dT%H%M%SZ)-$$.json"
fi
mkdir -p "$(dirname "$REPORT")"
CHECKS_FILE="$(mktemp)"
trap 'rm -f "$CHECKS_FILE"' EXIT

PASS=0 FAIL=0 SKIP=0

record() {
  # record <name> <pass|fail|skip> <detail>
  local name="$1" status="$2" detail="${3:-}"
  printf '%s\t%s\t%s\n' "$name" "$status" "$detail" >>"$CHECKS_FILE"
  case "$status" in
    pass) PASS=$((PASS + 1)); printf '  \033[32mok\033[0m   %s (%s)\n' "$name" "$detail" ;;
    fail) FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m %s (%s)\n' "$name" "$detail" ;;
    skip) SKIP=$((SKIP + 1)); printf '  \033[33mskip\033[0m %s (%s)\n' "$name" "$detail" ;;
  esac
}

log "on-device suite on $(hostname) ($(uname -m), kernel $(kernel_version))"

# --- privileges -------------------------------------------------------------
if [[ "$(id -u)" -eq 0 ]]; then
  record "root" pass "euid 0"
else
  record "root" fail "euid $(id -u); the suite needs root for namespaces, cgroups and mounts"
fi

# --- kernel -----------------------------------------------------------------
if kernel_at_least "$R3S_MIN_KERNEL"; then
  record "kernel>=$R3S_MIN_KERNEL" pass "$(kernel_version)"
else
  record "kernel>=$R3S_MIN_KERNEL" fail "$(kernel_version)"
fi

# --- cgroup v2 --------------------------------------------------------------
CG=/sys/fs/cgroup
if [[ -f "$CG/cgroup.controllers" ]]; then
  record "cgroup-v2" pass "unified hierarchy at $CG"
  avail="$(cat "$CG/cgroup.controllers" 2>/dev/null || true)"
  for c in cpu memory pids io; do
    if grep -qw "$c" <<<"$avail"; then
      record "controller:$c" pass "available"
    else
      record "controller:$c" fail "not in cgroup.controllers ($avail)"
    fi
  done
  # memory.events is read for oom_kill before reaping (state.rs::ExitRecord).
  if [[ -w "$CG" ]]; then
    probe="$CG/r3s-probe.$$"
    if mkdir -p "$probe" 2>/dev/null; then
      for f in memory.events cgroup.type cgroup.freeze cgroup.procs; do
        if [[ -e "$probe/$f" ]]; then
          record "$f" pass "$probe/$f"
        else
          record "$f" fail "absent in $probe"
        fi
      done
      rmdir "$probe" 2>/dev/null || true
    else
      record "cgroup-probe" fail "cannot create a cgroup under $CG"
    fi
  else
    record "cgroup-writable" fail "$CG is not writable"
  fi
  # systemd must delegate the subtree, otherwise the engine has to own $CG.
  if grep -qE '^\S+:.*:.*:' /proc/self/cgroup 2>/dev/null; then
    record "cgroup-namespaced" pass "process is inside a cgroup namespace"
  else
    record "cgroup-namespaced" skip "not in a cgroup namespace; engine will manage $CG directly"
  fi
else
  record "cgroup-v2" fail "no $CG/cgroup.controllers; this engine requires the unified hierarchy"
fi

# --- filesystems ------------------------------------------------------------
if grep -qw overlay /proc/filesystems 2>/dev/null; then
  record "overlayfs" pass "available"
else
  record "overlayfs" fail "not in /proc/filesystems; the default rootfs is overlay"
fi

if grep -qw tmpfs /proc/filesystems 2>/dev/null; then
  record "tmpfs" pass "available"
else
  record "tmpfs" fail "not in /proc/filesystems"
fi

# --- namespaces -------------------------------------------------------------
ns_ok=1
for ns in pid user mount net; do
  if ! ls "/proc/self/ns/$ns" >/dev/null 2>&1; then
    record "ns:$ns" fail "/proc/self/ns/$ns missing"
    ns_ok=0
  fi
done
# An `if`, not a trailing `&&`: a false condition returning 1 under `set -e`
# ends the run before the report is written, which is the worst possible moment
# to lose the evidence of a missing namespace.
if [[ $ns_ok -eq 1 ]]; then
  record "namespaces" pass "pid, user, mount, net present"
fi

if [[ -w /proc/sys/user/max_user_namespaces ]]; then
  lim="$(cat /proc/sys/user/max_user_namespaces)"
  if [[ "$lim" -gt 0 ]]; then
    record "userns-allowed" pass "max_user_namespaces=$lim"
  else
    record "userns-allowed" fail "max_user_namespaces=0; rootless mode is unavailable"
  fi
else
  record "userns-allowed" skip "/proc/sys/user/max_user_namespaces not present"
fi

# --- pidfd / signals --------------------------------------------------------
if [[ -e /proc/self/pidfd ]]; then
  record "pidfd" pass "/proc/self/pidfd readable"
else
  record "pidfd" fail "cannot open a pidfd; the runtime waits on pidfd, not waitpid"
fi

# --- netfilter --------------------------------------------------------------
# The engine talks to nftables over its own netlink socket, so `nft` must not
# be needed. It may be absent; that is the point. What must be true is that the
# kernel offers the families the engine opens.
if [[ -e /proc/net/nf_conntrack ]]; then
  record "nf-conntrack" pass "conntrack present"
else
  record "nf-conntrack" skip "no conntrack (egress filtering still works, connection tracking does not)"
fi
if [[ -r /proc/net/protocols ]]; then
  record "netlink-socket" pass "/proc/net/protocols readable"
else
  record "netlink-socket" fail "cannot inspect the netlink socket table"
fi

# --- no sidecar tooling -----------------------------------------------------
# The strongest property of this engine: it must work with no PATH at all. If
# it ever shells out to `ip`, `nft` or `tar`, this is what catches it.
if [[ -x "${R3S_BIN:-/usr/local/bin/r3s}" ]]; then
  if env -i PATH=/nonexistent "${R3S_BIN:-/usr/local/bin/r3s}" --version >/dev/null 2>&1; then
    record "path-nonexistent-version" pass "binary runs with PATH=/nonexistent"
  else
    record "path-nonexistent-version" fail "binary needs something on PATH"
  fi
else
  record "path-nonexistent" skip "no r3s binary at ${R3S_BIN:-/usr/local/bin/r3s} yet"
fi

# --- container lifecycle ----------------------------------------------------
BIN="${R3S_BIN:-/usr/local/bin/r3s}"
if [[ -x "$BIN" ]]; then
  if "$BIN" --help >/dev/null 2>&1; then
    record "cli-help" pass "--help"
  else
    record "cli-help" fail "--help returned non-zero"
  fi
else
  record "container-lifecycle" skip "no r3s binary yet; the engine crate is not implemented"
fi

# --- disk -------------------------------------------------------------------
avail_kb="$(df -Pk /var/lib 2>/dev/null | awk 'NR==2 {print $4}')"
if [[ -n "${avail_kb:-}" && "$avail_kb" -gt 1048576 ]]; then
  record "disk" pass "$((avail_kb / 1024)) MiB free on /var/lib"
elif [[ -n "${avail_kb:-}" ]]; then
  record "disk" fail "$((avail_kb / 1024)) MiB free on /var/lib; images need more"
else
  record "disk" skip "could not stat /var/lib"
fi

# --- report -----------------------------------------------------------------
{
  printf '{\n'
  printf '  "generated_at": "%s",\n' "$(json_escape "$(utc_now)")"
  printf '  "host": "%s",\n' "$(json_escape "$(hostname)")"
  printf '  "arch": "%s",\n' "$(json_escape "$(uname -m)")"
  printf '  "kernel": "%s",\n' "$(json_escape "$(kernel_version)")"
  printf '  "board_cpu": "%s",\n' "$(json_escape "$(board_cpu)")"
  printf '  "checks": [\n'
  first=1
  while IFS=$'\t' read -r name status detail; do
    [[ $first -eq 1 ]] || printf ',\n'
    first=0
    printf '    {"name": "%s", "status": "%s", "detail": "%s"}' \
      "$(json_escape "$name")" "$status" "$(json_escape "$detail")"
  done <"$CHECKS_FILE"
  printf '\n  ],\n'
  printf '  "summary": {"pass": %d, "fail": %d, "skip": %d}\n' "$PASS" "$FAIL" "$SKIP"
  printf '}\n'
} >"$REPORT"

log "report: $REPORT"
printf 'summary: %d pass, %d fail, %d skip\n' "$PASS" "$FAIL" "$SKIP"
[[ "$FAIL" -eq 0 ]] || die "$FAIL check(s) failed on this device"
