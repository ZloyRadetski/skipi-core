#!/usr/bin/env bash
# Builds hev-socks5-tunnel (HEV TUN) as static libraries for linux/amd64 with the host gcc.
#
# Output: build/hev/linux-amd64/{libhev-socks5-tunnel,libyaml,liblwip,libhev-task-system}.a
# plus build/hev/include/hev-main.h (the patched public header internal/hevtun includes).
#
# The submodule third_party/hev-socks5-tunnel is never modified: the source is copied to
# build/hev/linux-src, patched there with third_party/patches/hev-socks5-tunnel/*.patch (the same
# patches the Android build applies) and built with hev's own `make static`. Objects are built
# with -fPIC because the archives end up inside a c-shared library (libskipicore.so).
#
# Needs gcc, make, patch, tar. Run on a linux/amd64 host.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUBMODULE="$ROOT/third_party/hev-socks5-tunnel"
PATCH_DIR="$ROOT/third_party/patches/hev-socks5-tunnel"
OUT="$ROOT/build/hev"
SRC="$OUT/linux-src"
DEST="$OUT/linux-amd64"

[ "$(uname -s)" = Linux ] || { echo "build-hev-linux.sh must run on Linux" >&2; exit 1; }
[ -f "$SUBMODULE/src/hev-main.c" ] || {
  echo "hev-socks5-tunnel sources are missing; run: git submodule update --init --recursive" >&2
  exit 1
}
[ -f "$SUBMODULE/third-part/yaml/src/api.c" ] || {
  echo "hev-socks5-tunnel nested submodules are missing; run: git submodule update --init --recursive" >&2
  exit 1
}

# 1. Fresh copy of the sources (only this script's own directories are replaced, so the Android
# libraries under build/hev/android survive). -h dereferences symlinks.
rm -rf "$SRC" "$DEST"
mkdir -p "$SRC" "$DEST" "$OUT/include"
(cd "$SUBMODULE" && tar --exclude=.git -chf - .) | (cd "$SRC" && tar -xf -)

# 2. Normalise line endings (a Windows checkout is CRLF), then apply the patches.
find "$SRC" -type f \( -name '*.c' -o -name '*.h' -o -name '*.S' -o -name '*.mk' -o -name Makefile \) \
  -exec sed -i 's/\r$//' {} +
for p in "$PATCH_DIR"/*.patch; do
  echo "patch: $(basename "$p")"
  patch -p1 -d "$SRC" --no-backup-if-mismatch < "$p"
done

# 3. make static. REV_ID is passed in because the copy has no git metadata of its own.
# -Wno-error: hev builds with -Werror, which a newer host gcc must not turn into a build break.
REV_ID="$(git -C "$SUBMODULE" rev-parse --short HEAD 2>/dev/null || echo unknown)"
JOBS="$(nproc 2>/dev/null || echo 4)"
make -C "$SRC" -j"$JOBS" static REV_ID="$REV_ID" CFLAGS="-fPIC -Wno-error"

# 4. Collect the archives and the patched header.
cp_lib() {
  [ -s "$1" ] || { echo "missing $1" >&2; exit 1; }
  cp "$1" "$DEST/"
}
cp_lib "$SRC/bin/libhev-socks5-tunnel.a"
cp_lib "$SRC/third-part/yaml/bin/libyaml.a"
cp_lib "$SRC/third-part/lwip/bin/liblwip.a"
cp_lib "$SRC/third-part/hev-task-system/bin/libhev-task-system.a"
cp "$SRC/src/hev-main.h" "$OUT/include/hev-main.h"

# 5. The entry point the cgo glue calls must be in the archive.
if command -v nm >/dev/null 2>&1; then
  nm "$DEST/libhev-socks5-tunnel.a" 2>/dev/null | grep -q ' T hev_socks5_tunnel_main_from_str' || {
    echo "hev_socks5_tunnel_main_from_str is missing from libhev-socks5-tunnel.a" >&2
    exit 1
  }
fi
echo "hev-socks5-tunnel (rev $REV_ID) built for linux/amd64 -> $DEST"
