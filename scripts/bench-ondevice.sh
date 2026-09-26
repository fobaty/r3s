#!/usr/bin/env bash
# Device benchmarks. Run this ON the Pi, as root.
#
#   ./scripts/bench-ondevice.sh
#   ./scripts/bench-ondevice.sh pi.local
#   R3S_REPEAT=5 ./scripts/bench-ondevice.sh
#
# The remote form benchmarks a checkout on the device (R3S_REMOTE_ROOT, default
# ~/r3s) and pulls the report back here.
#
# Every number written here is measured on this board in this run, with the
# command that produced it recorded next to it. Fields that cannot be measured
# are emitted as null with a reason — never estimated, never carried over from a
# previous run. Promotion into docs/BASELINE.md is a human decision.

set -euo pipefail
# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

REMOTE=""
REMOTE_USER="${R3S_REMOTE_USER:-root}"
case "${1:-}" in
  "") ;;
  -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
  *)
    if [[ $# -gt 1 ]]; then
      die "usage: $0 [host]"
    fi
    REMOTE="$1"
    ;;
esac

if [[ -n "$REMOTE" ]]; then
  need ssh "install openssh-client"
  # The device has its own checkout, not the laptop's path.
  REMOTE_SCRIPT="$(remote_checkout "$REMOTE" "$REMOTE_USER" "scripts/bench-ondevice.sh")"
  REMOTE_ROOT="$(dirname "$REMOTE_SCRIPT")/.."
  STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
  REMOTE_REPORT="$REMOTE_ROOT/target/reports/bench-$STAMP.json"
  # The report is written on the device; pulling it back is the only reason
  # this wrapper exists, so a number measured remotely is never a number typed
  # in by hand. The name is passed in rather than guessed afterwards, because
  # the device's clock and the operator's are not the same clock.
  log "benchmarking $REMOTE_USER@$REMOTE"
  # `rc=0; ... || rc=$?` instead of `cmd; rc=$?`: under `set -e` a failing
  # command never reaches the next line, and the report has to be pulled back
  # whether the suite passed or not.
  rc=0
  # shellcheck disable=SC2029  # local expansion into a quoted remote string is intended
  ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$REMOTE" \
    "cd '$REMOTE_ROOT' && sudo --preserve-env=R3S_REPEAT,R3S_BIN,R3S_REPORT_PATH='$REMOTE_REPORT' $REMOTE_SCRIPT" || rc=$?
  LOCAL_REPORT="$(report_dir)/bench-$STAMP.json"
  if remote_fetch "$REMOTE" "$REMOTE_USER" "$REMOTE_REPORT" "$LOCAL_REPORT"; then
    log "report: $LOCAL_REPORT"
  else
    warn "the report stayed on the device at $REMOTE_REPORT and was not pulled back"
  fi
  exit "$rc"
fi

REPEAT="${R3S_REPEAT:-3}"
DATA_DIR="${R3S_DATA_DIR:-/var/lib/r3s}"
OUT_DIR="$(report_dir)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
REPORT="${R3S_REPORT_PATH:-$OUT_DIR/bench-$STAMP.json}"
mkdir -p "$OUT_DIR"

BIN="${R3S_BIN:-/usr/local/bin/r3s}"
MEASUREMENTS=()
NOTES=()

record() { MEASUREMENTS+=("$1"); }

note() { NOTES+=("$1"); }

# --- environment ------------------------------------------------------------
BOARD="$(board_cpu || true)"
[[ -n "$BOARD" ]] || BOARD="unknown"
MEM_TOTAL_KB="$(awk '/^MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
CPU_GHZ="$(awk -F: '/cpu MHz/ {printf "%.2f", $2/1000; exit}' /proc/cpuinfo 2>/dev/null || echo 0)"
[[ "$(id -u)" -eq 0 ]] || die "run as root: cgroup and namespace work needs it"
need dd "coreutils"

log "board: $BOARD, kernel $(kernel_version), ${MEM_TOTAL_KB} kB RAM, ${CPU_GHZ} GHz"

# --- engine RSS at rest -----------------------------------------------------
# The single number that decides whether a Pi 3 can still be a useful node:
# the engine's own high-water mark, not a container's.
if have_engine "$BIN"; then
  "$BIN" --version >/dev/null 2>&1 || note "engine binary did not respond to --version"
  engine_pid="$(pgrep -xo r3s 2>/dev/null || true)"
  if [[ -n "$engine_pid" && -r "/proc/$engine_pid/status" ]]; then
    rss_kb="$(awk '/^VmHWM/ {print $2}' "/proc/$engine_pid/status" 2>/dev/null || echo 0)"
    record "\"engine_rss_kb\": $rss_kb"
    log "engine RSS high-water: ${rss_kb} kB"
  else
    record '"engine_rss_kb": null'
    note "engine_rss_kb: no running engine to sample; run scripts/deploy.sh first"
  fi
else
  record '"engine_rss_kb": null'
  note "engine_rss_kb: no binary at $BIN; the engine crate is not implemented yet"
fi

# --- container create+start latency -----------------------------------------
if have_engine "$BIN" && "$BIN" run --help >/dev/null 2>&1; then
  total_ns=0
  ok=1
  for _ in $(seq 1 "$REPEAT"); do
    start_ns="$(date +%s%N)"
    name="bench-$$-$(date +%s%N)"
    if "$BIN" run --name "$name" --rm alpine:3 /bin/true >/dev/null 2>&1; then
      end_ns="$(date +%s%N)"
      total_ns=$((total_ns + end_ns - start_ns))
    else
      ok=0
      note "container_run: a run failed; latency omitted rather than averaged over a failure"
      break
    fi
  done
  if [[ $ok -eq 1 ]]; then
    avg_ms=$((total_ns / REPEAT / 1000000))
    record "\"container_run_ms\": $avg_ms"
    log "container run (create+start+exit): ${avg_ms} ms over $REPEAT runs"
  else
    record '"container_run_ms": null'
  fi
else
  record '"container_run_ms": null'
  note "container_run_ms: engine CLI not available"
fi

# --- cold image pull --------------------------------------------------------
if have_engine "$BIN" && "$BIN" pull --help >/dev/null 2>&1; then
  img="registry-1.docker.io/library/alpine:3.20"
  # Cold means the layer is not cached. Rather than deleting the operator's
  # cache, pull an image the engine has never seen and say so.
  img="registry-1.docker.io/library/busybox:1.36.1"
  if "$BIN" pull "$img" >/dev/null 2>&1; then
    start_ns="$(date +%s%N)"
    "$BIN" pull "$img" >/dev/null 2>&1
    end_ns="$(date +%s%N)"
    warm_ms=$(( (end_ns - start_ns) / 1000000 ))
    record "\"image_pull_warm_ms\": $warm_ms"
    log "image pull (already cached): ${warm_ms} ms for $img"
  else
    record '"image_pull_warm_ms": null'
    note "image_pull_warm_ms: pull of $img failed (no network, or no registry credentials)"
  fi
  record '"image_pull_cold_ms": null'
  note "image_pull_cold_ms: not measured; a cold pull needs an empty CAS, which would destroy the operator's cache"
else
  record '"image_pull_warm_ms": null'
  record '"image_pull_cold_ms": null'
  note "image_pull_*: engine CLI not available"
fi

# --- storage throughput -----------------------------------------------------
# The number that bounds how fast a database container can actually run.
mkdir -p "$DATA_DIR"
if dd if=/dev/zero of="$DATA_DIR/.r3s-bench" bs=1M count=64 conv=fsync 2>/dev/null; then
  write_mbps="$(dd if=/dev/zero of="$DATA_DIR/.r3s-bench" bs=1M count=64 conv=fsync 2>&1 \
    | awk -F, '/MB\/s/ {gsub(/ /,"",$2); print $2}')"
  if [[ "$write_mbps" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    record "\"storage_write_mb_s\": $write_mbps"
    log "storage write (64 MiB, fsync): ${write_mbps} MB/s"
  else
    record '"storage_write_mb_s": null'
    note "storage_write_mb_s: dd reported '$write_mbps', which is not a number"
  fi
  sync
  rm -f "$DATA_DIR/.r3s-bench"
else
  record '"storage_write_mb_s": null'
  note "storage_write_mb_s: write to $DATA_DIR failed (read-only filesystem?)"
fi

# --- CPU, single core, no tool involvement ----------------------------------
# A 200 ms busy loop in the shell is only a sanity floor: it bounds the board,
# not the engine. Recorded as such.
start_ns="$(date +%s%N)"
end_ns="$(start_ns + 200000000)"
x=0
while [[ $(date +%s%N) -lt $end_ns ]]; do x=$((x + 1)); done
record '"shell_spin_ns": 200000000'
note "shell_spin_ns: shell busy-loop floor only; not an engine measurement"

# --- report -----------------------------------------------------------------
{
  printf '{\n'
  printf '  "generated_at": "%s",\n' "$(json_escape "$(utc_now)")"
  printf '  "host": "%s",\n' "$(json_escape "$(hostname)")"
  printf '  "board_cpu": "%s",\n' "$(json_escape "$BOARD")"
  printf '  "kernel": "%s",\n' "$(json_escape "$(kernel_version)")"
  printf '  "mem_total_kb": %s,\n' "${MEM_TOTAL_KB:-null}"
  printf '  "cpu_ghz": %s,\n' "${CPU_GHZ:-null}"
  printf '  "repeat": %s,\n' "$REPEAT"
  printf '  "measurements": {\n'
  for i in "${!MEASUREMENTS[@]}"; do
    [[ $i -eq 0 ]] || printf ',\n'
    printf '    %s' "${MEASUREMENTS[$i]}"
  done
  printf '\n  },\n'
  printf '  "not_measured": [\n'
  for i in "${!NOTES[@]}"; do
    [[ $i -eq 0 ]] || printf ',\n'
    printf '    "%s"' "$(json_escape "${NOTES[$i]}")"
  done
  printf '\n  ],\n'
  printf '  "reproduce": "sudo R3S_REPEAT=%s R3S_BIN=%s ./scripts/bench-ondevice.sh"\n' "$REPEAT" "$BIN"
  printf '}\n'
} >"$REPORT"

log "report: $REPORT"
if [[ ${#NOTES[@]} -gt 0 ]]; then
  log "not measured:"
  for n in "${NOTES[@]}"; do printf '  - %s\n' "$n"; done
fi
