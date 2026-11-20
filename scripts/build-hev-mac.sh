#!/usr/bin/env bash
# Builds hev-socks5-tunnel (HEV TUN) as an executable for the macOS desktop.
#
# On macOS hev is not linked into Core: it runs as a root process of its own that creates the utun
# interface (see internal/hevtun/macsupervisor.go), so it is a plain executable with hev's default
# build flags and without the in-process patches Android and Linux use.
#
# Output: build/hev/macos/hev-socks5-tunnel, built for the host architecture. Run it on a macOS
# host: Apple Silicon makes arm64, an Intel Mac x86_64.
#
# The submodule third_party/hev-socks5-tunnel is never modified: the source is copied to
# build/hev/macos-src and built there.
#
# Needs make and the Xcode command line tools.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUBMODULE="$ROOT/third_party/hev-socks5-tunnel"
OUT="$ROOT/build/hev"
SRC="$OUT/macos-src"
DEST="$OUT/macos"

[ "$(uname -s)" = Darwin ] || { echo "build-hev-mac.sh must run on macOS" >&2; exit 1; }
[ -f "$SUBMODULE/src/hev-main.c" ] || {
  echo "hev-socks5-tunnel sources are missing; run: git submodule update --init --recursive" >&2
  exit 1
}
[ -f "$SUBMODULE/third-part/yaml/src/api.c" ] || {
  echo "hev-socks5-tunnel nested submodules are missing; run: git submodule update --init --recursive" >&2
  exit 1
}

# 1. Fresh copy of the sources; build products of an earlier in-tree build are left out.
rm -rf "$SRC" "$DEST"
mkdir -p "$SRC" "$DEST"
(cd "$SUBMODULE" && tar --exclude=.git --exclude='./bin' --exclude='./build' \
  --exclude='third-part/*/bin' --exclude='third-part/*/build' -cf - .) | (cd "$SRC" && tar -xf -)

# 2. Build. REV_ID is passed in because the copy has no git metadata of its own.
REV_ID="$(git -C "$SUBMODULE" rev-parse --short HEAD 2>/dev/null || echo unknown)"
JOBS="$(sysctl -n hw.ncpu 2>/dev/null || echo 4)"
# -Wno-error: hev builds with -Werror, which a newer Apple clang must not turn into a build break.
make -C "$SRC" -j"$JOBS" CC=cc REV_ID="$REV_ID" CFLAGS="-Wno-error"

BUILT="$SRC/bin/hev-socks5-tunnel"
[ -s "$BUILT" ] || { echo "hev-socks5-tunnel build produced no executable" >&2; exit 1; }
cp "$BUILT" "$DEST/hev-socks5-tunnel"
chmod 755 "$DEST/hev-socks5-tunnel"
cp "$SUBMODULE/LICENSE" "$DEST/HEV_LICENSE.txt"

echo "hev-socks5-tunnel (rev $REV_ID) built for $(uname -m) -> $DEST"
file "$DEST/hev-socks5-tunnel" 2>/dev/null || true
