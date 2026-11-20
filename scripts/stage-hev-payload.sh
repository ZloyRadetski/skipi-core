#!/usr/bin/env bash
# Puts the hev-socks5-tunnel runtime of a platform into internal/hevpayload/payload/, where
# go:embed picks it up: the Core library then carries hev itself (see internal/hevpayload).
#
#   scripts/stage-hev-payload.sh windows   # official hev 2.20.0 + Wintun (any host)
#   scripts/stage-hev-payload.sh macos     # hev built from the submodule (needs a macOS host)
#   scripts/stage-hev-payload.sh clean     # leaves only the placeholder
#
# Run it before `go build` of a release library. Without it the library builds fine and reports
# that it carries no HEV TUN runtime. Linux and Android link hev instead (build-hev-linux.sh,
# build-hev-android.sh) and need no payload.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PAYLOAD="$ROOT/internal/hevpayload/payload"
PYTHON="${PYTHON:-$(command -v python3 || command -v python || echo python3)}"

clean() {
  mkdir -p "$PAYLOAD"
  find "$PAYLOAD" -mindepth 1 ! -name .keep -delete
  : > "$PAYLOAD/.keep"
}

case "${1:-}" in
  clean)
    clean
    ;;
  windows)
    PYTHON="$PYTHON" bash "$ROOT/scripts/package-hev-windows.sh"
    clean
    "$PYTHON" - "$ROOT/build/hev/windows/hev-windows-x64.zip" "$PAYLOAD" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
    z.extractall(sys.argv[2])
PY
    ;;
  macos)
    bash "$ROOT/scripts/build-hev-mac.sh"
    clean
    cp "$ROOT/build/hev/macos/hev-socks5-tunnel" "$ROOT/build/hev/macos/HEV_LICENSE.txt" "$PAYLOAD/"
    ;;
  *)
    echo "usage: $0 windows|macos|clean" >&2
    exit 2
    ;;
esac
echo "hev payload for ${1}:"
ls -l "$PAYLOAD"
