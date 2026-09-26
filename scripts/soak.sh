#!/usr/bin/env bash
# Soak test: churn containers while sampling for leaks.
#
#   ./scripts/soak.sh --duration 6h
#   R3S_IMAGE=alpine:3 ./scripts/soak.sh --duration 30m
#
# The failure this is looking for is not a crash, it is a slow leak: RSS, file
# descriptors, cgroup directories and pids that grow monotonically over hours
# and take the SD card down with them. So the test fails on a *trend*, not on a
# single sample.

set -euo pipefail
# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

DURATION="${R3S_DURATION:-1h}"
SAMPLE_SECS="${R3S_SAMPLE_SECS:-30}"
RSS_GROWTH_LIMIT_PCT="${R3S_RSS_GROWTH_LIMIT_PCT:-25}"
IMAGE="${R3S_IMAGE:-alpine:3}"
BIN="${R3S_BIN:-/usr/local/bin/r3s}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration) DURATION="$2"; shift 2 ;;
    --sample) SAMPLE_SECS="$2"; shift 2 ;;
    --image) IMAGE="$2"; shift 2 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

have_engine "$BIN" || die "no r3s binary at $BIN; the engine crate is not implemented yet"
"$BIN" run --help >/dev/null 2>&1 || die "$BIN does not support 'run'; nothing to soak"

log "soak: duration=$DURATION sample=${SAMPLE_SECS}s image=$IMAGE"
START_EPOCH="$(date +%s)"
DEADLINE=$((START_EPOCH + $(printf '%s' "$DURATION" | sed -E 's/^([0-9]+)s$/\1/; s/^([0-9]+)m$/\1*60/; s/^([0-9]+)h$/\1*3600/')))
(( DEADLINE > START_EPOCH )) || die "could not parse duration: $DURATION"

samples=()
fail=0
iteration=0

while [[ "$(date +%s)" -lt "$DEADLINE" ]]; do
  iteration=$((iteration + 1))
  name="soak-$$-$iteration"

  if ! "$BIN" run --name "$name" --rm "$IMAGE" /bin/true >/dev/null 2>&1; then
    warn "iteration $iteration: container failed to run"
    fail=$((fail + 1))
  fi

  engine_pid="$(pgrep -xo r3s 2>/dev/null || true)"
  if [[ -n "$engine_pid" && -r "/proc/$engine_pid/status" ]]; then
    rss="$(awk '/^VmRSS/ {print $2}' "/proc/$engine_pid/status" 2>/dev/null || echo 0)"
    fds="$(find "/proc/$engine_pid/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l | tr -d ' ')"
    cg="$(find /sys/fs/cgroup -maxdepth 3 -name 'r3s-*' -type d 2>/dev/null | wc -l | tr -d ' ')"
    samples+=("$rss $fds $cg")
    log "iter=$iteration rss=${rss}kB fds=$fds cgroups=$cg"
  else
    warn "iteration $iteration: engine is not running"
    exit 1
  fi

  if [[ $((iteration % 1)) -eq 0 ]]; then
    sleep "$SAMPLE_SECS"
  fi
done

# --- verdict ----------------------------------------------------------------
total="${#samples[@]}"
if [[ "$total" -lt 4 ]]; then
  die "only $total samples; shorten the sample interval or lengthen the run"
fi

read -ra first <<<"${samples[0]}"
read -ra last <<<"${samples[$((total - 1))]}"

rss_growth=0
[[ "${first[0]}" -gt 0 ]] && rss_growth=$(( (last[0] - first[0]) * 100 / first[0] ))
fd_delta=$(( last[1] - first[1] ))
cgroup_delta=$(( last[2] - first[2] ))

printf '\n'
log "duration: $(( $(date +%s) - START_EPOCH ))s, iterations: $iteration, failures: $fail"
log "rss: ${first[0]} kB -> ${last[0]} kB (${rss_growth}%)"
log "fds: ${first[1]} -> ${last[1]} (delta $fd_delta)"
log "cgroup dirs: ${first[2]} -> ${last[2]} (delta $cgroup_delta)"

bad=0
(( rss_growth > RSS_GROWTH_LIMIT_PCT )) && { warn "RSS grew ${rss_growth}% (limit ${RSS_GROWTH_LIMIT_PCT}%)"; bad=1; }
(( fd_delta > 8 )) && { warn "file descriptors leaked: $fd_delta"; bad=1; }
(( cgroup_delta > 0 )) && { warn "cgroup directories leaked: $cgroup_delta"; bad=1; }
(( fail > 0 )) && { warn "$fail container runs failed"; bad=1; }

if [[ $bad -eq 1 ]]; then
  die "soak failed; the trend above is the finding, not the exit code"
fi
log "soak clean"
