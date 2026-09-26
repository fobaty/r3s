#!/usr/bin/env bash
# Shared helpers for the operator scripts.
#
# Sourced, never executed. Everything here is host-side tooling: the engine
# itself never shells out (AGENTS.md, "no shelling out"), and neither may the
# kernel work these scripts trigger — the engine does that over netlink and
# cgroupfs.

set -euo pipefail

R3S_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export R3S_ROOT

# Minimum kernel with everything this engine needs: cgroup v2 `memory.events`,
# `cgroup.type` threaded-domain support, pidfd, and `mount_setattr`.
# shellcheck disable=SC2034  # read by the scripts that source this file
R3S_MIN_KERNEL="6.1"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33mwarn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

need() {
  # need <command> <how to install>
  command -v "$1" >/dev/null 2>&1 || die "$1 not found; $2"
}

# The board's core, or empty on a non-ARM64 host. The only machine-specific
# input to a build is this one flag (see .cargo/config.toml).
board_cpu() {
  local info="${1:-/proc/cpuinfo}"
  [[ -r "$info" ]] || return 0
  awk -F: '/^model name|^Hardware|^Processor/ {gsub(/^ +/, "", $2); print tolower($2); exit}' "$info" 2>/dev/null
}

target_cpu_flag() {
  local model cpu
  model="$(board_cpu)"
  cpu="${R3S_BOARD_CPU:-}"
  [[ -n "$cpu" ]] || cpu="$model"
  # One pattern per core: `cortex-a72` already contains `a72`, so a second
  # alternative naming the full string can never be reached.
  case "$cpu" in
    *a76*|*cortex-a7[6-9]*) printf 'cortex-a76\n' ;;
    *a72*)                  printf 'cortex-a72\n' ;;
    *a53*)                  printf 'cortex-a53\n' ;;
    *2700*)                 printf 'cortex-a72\n' ;;  # BCM2711 has no model name
    *)                      printf '' ;;
  esac
}

kernel_version() {
  uname -r 2>/dev/null || printf 'unknown'
}

# Numeric part of a `major.minor.patch` string.
kernel_major_minor() {
  local v="${1:-$(uname -r)}"
  printf '%s.%s' "${v%%.*}" "$(printf '%s' "$v" | cut -d. -f2)"
}

kernel_at_least() {
  local want="$1" have
  have="$(kernel_major_minor "${2:-}")"
  [[ "$(printf '%s\n%s\n' "$want" "$have" | sort -V | head -1)" == "$want" ]]
}

# True when the engine binary exists, so benchmark and on-device scripts can
# distinguish "not implemented yet" from "broken".
have_engine() {
  local bin="${1:-${R3S_BIN:-}}"
  [[ -n "$bin" && -x "$bin" ]]
}

# SSH options shared by every remote wrapper. BatchMode is deliberate: a
# password prompt inside a CI step or a bench run turns into a hung run, not a
# failed one.
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10)

# The checkout path *on the device*. It is almost never the same as the local
# R3S_ROOT: the operator's laptop is ~/dev/r3s and the device is /root/r3s, and
# quietly running the laptop's path on the device is a confusing way to learn
# that. Override with R3S_REMOTE_ROOT.
#
# remote_checkout <host> <user> <relative script path>
remote_checkout() {
  local host="$1" user="$2" rel="$3"
  local root="${R3S_REMOTE_ROOT:-$HOME/r3s}"

  case "$root$rel" in
    *"'"*) die "R3S_REMOTE_ROOT and the script path must not contain a single quote (it is quoted for the remote shell)" ;;
  esac
  case "$rel" in
    /*|*..*) die "internal error: script path must be relative and clean" ;;
  esac

  local found
  # shellcheck disable=SC2029  # local expansion into a quoted remote string is intended
  found="$(ssh "${SSH_OPTS[@]}" "$user@$host" \
    "cd '$root' 2>/dev/null && test -x scripts/lib.sh && pwd" 2>/dev/null || true)"
  [[ -n "$found" ]] || die "no r3s checkout on $user@$host at '$root'; set R3S_REMOTE_ROOT, or clone there first"
  printf '%s' "$found/$rel"
}

# Pull a root-owned report back to the operator's machine. `sudo cat` over ssh
# rather than scp: the report is written by a sudo run, so it is root-owned and
# scp as a normal user just fails on permissions.
#
# remote_fetch <host> <user> <remote path> <local path>
remote_fetch() {
  local host="$1" user="$2" remote="$3" local_path="$4"
  case "$remote" in
    *"'"*) die "remote report path must not contain a single quote" ;;
  esac
  mkdir -p "$(dirname "$local_path")"
  # shellcheck disable=SC2029  # local expansion into a quoted remote string is intended
  if ! ssh "${SSH_OPTS[@]}" "$user@$host" "sudo cat '$remote'" >"$local_path"; then
    rm -f "$local_path"
    return 1
  fi
}

json_escape() {
  # Hand-rolled: the device may not have jq, and pulling jq onto a Pi to format
  # a report is a dependency the engine does not otherwise need.
  printf '%s' "${1:-}" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/\\t/g' | tr -d '\n'
}

utc_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# Reports land outside the docs tree; a human promotes a measurement into
# docs/BASELINE.md by hand, with the reproduction command attached. A script
# that can edit the docs can also invent a number in them.
report_dir() {
  printf '%s' "${R3S_REPORT_DIR:-$R3S_ROOT/target/reports}"
}

record_measurement() {
  # record_measurement <file> <key> <value-json> <unit>
  local file="$1" key="$2" value="$3" unit="$4"
  mkdir -p "$(dirname "$file")"
  if [[ -f "$file" ]]; then
    jq --arg k "$key" --argjson v "$value" --arg u "$unit" \
       '. + {($k): {value: $v, unit: $u}}' "$file" >"$file.tmp" 2>/dev/null \
      && mv "$file.tmp" "$file" && return 0
    # jq missing or failing: keep going, the raw log is the record of truth.
  fi
  printf '%s' "$value" >"$file"
}
