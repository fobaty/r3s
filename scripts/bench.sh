#!/usr/bin/env bash
# Host microbenchmarks. Runs on the dev box; says nothing about the Pi.
#
#   ./scripts/bench.sh
#   ./scripts/bench.sh --filter store
#
# Results land in target/bench/. A host number is not a Pi number and must never
# be copied into docs/BASELINE.md; only scripts/bench-ondevice.sh produces those.

set -euo pipefail
# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

FILTER=()
[[ $# -gt 0 ]] && FILTER=("$@")

need cargo "install rustup"

if ! cargo nextest --version >/dev/null 2>&1 && ! cargo bench --help >/dev/null 2>&1; then
  die "cargo bench is unavailable; check the toolchain"
fi

OUT="$R3S_ROOT/target/bench"
mkdir -p "$OUT"

log "host: $(uname -m), kernel $(kernel_version)"
if [[ -r /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq ]]; then
  log "cpu max freq: $(awk '{printf "%.2f GHz", $1/1e6}' /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq 2>/dev/null)"
fi
if [[ -r /proc/meminfo ]]; then
  log "memory: $(awk '/^MemTotal/ {printf "%.1f GiB", $2/1048576}' /proc/meminfo)"
fi

# `--profile release` is implied by bench, but the criterion-style reporting
# flag keeps the output parseable without an extra tool.
(cd "$R3S_ROOT" && cargo bench --workspace --no-fail-fast "${FILTER[@]+"${FILTER[@]}"}" 2>&1 | tee "$OUT/bench-$(date -u +%Y%m%dT%H%M%SZ).log")

if command -v hyperfine >/dev/null 2>&1; then
  log "hyperfine is available; use it for end-to-end CLI timings"
else
  warn "hyperfine not installed; end-to-end CLI timings are not being measured"
fi

log "logs in $OUT"
