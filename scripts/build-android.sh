#!/usr/bin/env bash
# Builds skipicore.aar: HEV TUN static libraries first, then the gomobile bind that links them
# into libgojni.so. Needs ANDROID_NDK_HOME, Go, and gomobile (go install golang.org/x/mobile/cmd/gomobile@latest; gomobile init).
#
# Extra gomobile flags can be passed through GOMOBILE_EXTRA_FLAGS (CI adds -v -trimpath and a
# stripped -ldflags through it); the default ldflags only carry -checklinkname=0.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

"$ROOT/scripts/build-hev-android.sh"

# github.com/wlynxg/anet requires -checklinkname=0 with Go 1.23+.
# 16 KB page alignment keeps the native library valid on Android 15+.
export CGO_LDFLAGS="${CGO_LDFLAGS:-} -Wl,-z,max-page-size=16384"

LDFLAGS="${SKIPI_LDFLAGS:--checklinkname=0}"
# shellcheck disable=SC2086
gomobile bind ${GOMOBILE_EXTRA_FLAGS:-} -target=android -androidapi 24 -javapkg=app.skipi.core \
  -ldflags="$LDFLAGS" -o skipicore.aar .

echo "built $ROOT/skipicore.aar"

# Prove HEV TUN is linked into the arm64 library (dynamic symbol table survives -s).
NM="$(ls "${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-/nonexistent}}"/toolchains/llvm/prebuilt/*/bin/llvm-nm* 2>/dev/null | head -n 1 || true)"
if [ -n "$NM" ]; then
  CHECK_DIR="$(mktemp -d)"
  unzip -q -o skipicore.aar jni/arm64-v8a/libgojni.so -d "$CHECK_DIR"
  if ! "$NM" -D "$CHECK_DIR/jni/arm64-v8a/libgojni.so" | grep -q ' T hev_socks5_tunnel_main_from_str'; then
    echo "hev_socks5_tunnel_main_from_str is not exported by libgojni.so" >&2
    rm -rf "$CHECK_DIR"
    exit 1
  fi
  rm -rf "$CHECK_DIR"
  echo "verified: libgojni.so contains hev_socks5_tunnel_main_from_str"
fi
