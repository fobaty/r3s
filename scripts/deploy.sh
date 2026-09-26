#!/usr/bin/env bash
# Build for the Pi, copy the single binary, restart the unit.
#
#   ./scripts/deploy.sh pi.local
#   ./scripts/deploy.sh pi.local pi
#   R3S_REMOTE_DIR=/opt/r3s/bin ./scripts/deploy.sh pi.local
#
# The deployable artefact is one file plus one systemd unit. If this script ever
# needs to ship a second file, the "no sidecar tooling" property has been lost.

set -euo pipefail
# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

HOST="${1:-}"
REMOTE_USER="${2:-${R3S_REMOTE_USER:-root}}"
REMOTE_DIR="${R3S_REMOTE_DIR:-/usr/local/bin}"
UNIT="r3s.service"

[[ -n "$HOST" ]] || die "usage: $0 <host> [user]"

TARGET="${R3S_TARGET:-aarch64-unknown-linux-gnu}"

need ssh "install openssh-client"
need scp "install openssh-client"

log "probing $HOST"
ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$HOST" 'uname -m; id -u' || die "cannot reach $REMOTE_USER@$HOST"

log "building for $TARGET"
"$R3S_ROOT/scripts/build.sh" --target "$TARGET" --release

SRC="$R3S_ROOT/target/$TARGET/release/r3s"
[[ -f "$SRC" ]] || die "$SRC not built; crates/r3s-bin is not implemented yet"

log "copying to $REMOTE_USER@$HOST:$REMOTE_DIR/r3s"
scp "${SSH_OPTS[@]}" "$SRC" "$REMOTE_USER@$HOST:$REMOTE_DIR/r3s.new"

log "installing and restarting $UNIT"
ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$HOST" bash -s -- "$REMOTE_DIR" "$UNIT" <<'REMOTE'
set -euo pipefail
dest_dir="$1"; unit="$2"
target="$dest_dir/r3s"
install -m 0755 "$target.new" "$target"
rm -f "$target.new"
if ! command -v systemctl >/dev/null 2>&1; then
  echo "no systemd on the device; the binary is installed but not started"
  exit 0
fi
if systemctl cat "$unit" >/dev/null 2>&1; then
  systemctl restart "$unit"
  sleep 1
  systemctl is-active --quiet "$unit" || { systemctl status "$unit" --no-pager; exit 1; }
  echo "restarted $unit"
else
  echo "$unit is not installed; copy packaging/systemd/$unit to /etc/systemd/system/"
  exit 0
fi
REMOTE

log "verifying"
# shellcheck disable=SC2029  # local expansion into a quoted remote string is intended
ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$HOST" "$REMOTE_DIR/r3s --version" || \
  warn "the remote binary did not report a version; check journalctl -u $UNIT on the device"
