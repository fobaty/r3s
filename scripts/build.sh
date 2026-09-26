#!/usr/bin/env bash
# Build the engine for a target, with the board's -C target-cpu.
#
#   ./scripts/build.sh                        # host build, dev profile
#   ./scripts/build.sh --release              # host build, release
#   ./scripts/build.sh --target aarch64-unknown-linux-gnu --release
#   ./scripts/build.sh --board pi4 --release
#
# Per-board tuning is a flag on this command line rather than a custom target
# JSON in .cargo/config.toml, so the toolchain stays the single source of truth
# for the ABI and a hand-written target cannot drift from it.

set -euo pipefail
# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

TARGET=""
PROFILE="dev"
BOARD="${R3S_BOARD:-auto}"
PACKAGE="${R3S_PACKAGE:-r3s-bin}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --release) PROFILE="release"; shift ;;
    --debug) PROFILE="dev"; shift ;;
    --board) BOARD="$2"; shift 2 ;;
    --package) PACKAGE="$2"; shift 2 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

case "$BOARD" in
  auto)
    case "$(uname -m)" in
      aarch64|arm64) cpu="$(target_cpu_flag)" ;;
      *) cpu="" ;;
    esac
    ;;
  pi5) cpu="cortex-a76" ;;
  pi4) cpu="cortex-a72" ;;
  pi3) cpu="cortex-a53" ;;
  "") cpu="" ;;
  *) die "unknown board: $BOARD (expected pi3, pi4, pi5 or auto)" ;;
esac

if [[ -n "$cpu" ]]; then
  log "board $BOARD: -C target-cpu=$cpu"
else
  log "board $BOARD: no target-cpu tuning (unknown board or host)"
fi

args=(--profile "$PROFILE")
[[ -n "$TARGET" ]] && args+=(--target "$TARGET")
if [[ -n "$cpu" ]]; then
  # RUSTFLAGS replaces the per-target rustflags from .cargo/config.toml rather
  # than merging with them, so the hardening link arg is repeated here instead
  # of being silently dropped.
  export RUSTFLAGS="-C link-arg=-Wl,-z,now -C target-cpu=$cpu"
fi

if [[ -d "$R3S_ROOT/crates/$PACKAGE" ]]; then
  log "building $PACKAGE"
  (cd "$R3S_ROOT" && cargo build -p "$PACKAGE" "${args[@]}")
else
  warn "crates/$PACKAGE does not exist yet; building the workspace instead"
  (cd "$R3S_ROOT" && cargo build "${args[@]}")
fi

out_dir="$R3S_ROOT/target/${TARGET:+$TARGET/}${PROFILE}"
if [[ -x "$out_dir/r3s" ]]; then
  log "binary: $out_dir/r3s"
  "$out_dir/r3s" --version 2>/dev/null || true
else
  warn "no r3s binary at $out_dir/r3s (the engine crate is not implemented yet)"
fi
