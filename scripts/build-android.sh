#!/usr/bin/env bash
# Builds skipicore.aar: HEV TUN static libraries first, then the gomobile bind that links them
# into libgojni.so. Needs ANDROID_NDK_HOME, Go, and gomobile (go install golang.org/x/mobile/cmd/gomobile@latest; gomobile init).
#
# The library is built like the release in CI by default: -trimpath and stripped ldflags
# (-s -w -buildid=), about half the size of an unstripped one. For a debuggable local build pass
# SKIPI_LDFLAGS=-checklinkname=0. Extra gomobile flags go through GOMOBILE_EXTRA_FLAGS.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

"$ROOT/scripts/build-hev-android.sh"

# Build against the patched xray-core (patches/xray-geodata): tools/xrayoverlay applies the patches to
# the pinned xray-core and prints a go.mod variant. It fails if a patch no longer applies.
#
# gomobile cannot use -modfile (it probes with GO111MODULE=off, where the flag is an error, and
# builds in a temporary module), so here the replace goes into go.mod itself, only while this
# script runs: go.mod and go.sum are restored on exit.
XRAY_MODFILE="$(go run ./tools/xrayoverlay)"
XRAY_PATCHED_DIR="$(dirname "$XRAY_MODFILE")/xray-core"
if command -v cygpath >/dev/null 2>&1; then XRAY_PATCHED_DIR="$(cygpath -m "$XRAY_PATCHED_DIR")"; fi
GOMOD_BACKUP="$(mktemp -d)"
cp go.mod "$GOMOD_BACKUP/go.mod"
cp go.sum "$GOMOD_BACKUP/go.sum"
trap 'cp "$GOMOD_BACKUP/go.mod" "$ROOT/go.mod"; cp "$GOMOD_BACKUP/go.sum" "$ROOT/go.sum"; rm -rf "$GOMOD_BACKUP"' EXIT
printf '\nreplace github.com/xtls/xray-core => %s\n' "$XRAY_PATCHED_DIR" >> go.mod

# github.com/wlynxg/anet requires -checklinkname=0 with Go 1.23+.
# 16 KB page alignment keeps the native library valid on Android 15+.
export CGO_LDFLAGS="${CGO_LDFLAGS:-} -Wl,-z,max-page-size=16384"

LDFLAGS="${SKIPI_LDFLAGS:--s -w -buildid= -checklinkname=0}"
# shellcheck disable=SC2086
gomobile bind -trimpath ${GOMOBILE_EXTRA_FLAGS:-} -target=android -androidapi 24 -javapkg=app.skipi.core \
  -ldflags="$LDFLAGS" -o skipicore.aar .

echo "built $ROOT/skipicore.aar"

# Prove HEV TUN is linked into the arm64 library (dynamic symbol table survives -s).
NM="$(ls "${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-/nonexistent}}"/toolchains/llvm/prebuilt/*/bin/llvm-nm* 2>/dev/null | head -n 1 || true)"
if [ -n "$NM" ]; then
  CHECK_DIR="$(mktemp -d)"
  unzip -q -o skipicore.aar jni/arm64-v8a/libgojni.so -d "$CHECK_DIR"
  # No `grep -q` here: it exits at the first match, llvm-nm then gets SIGPIPE on its remaining
  # output (about 90 KB, more than a pipe holds), and pipefail turns that into a failed check.
  if ! "$NM" -D "$CHECK_DIR/jni/arm64-v8a/libgojni.so" | grep ' T hev_socks5_tunnel_main_from_str' >/dev/null; then
    echo "hev_socks5_tunnel_main_from_str is not exported by libgojni.so" >&2
    rm -rf "$CHECK_DIR"
    exit 1
  fi
  rm -rf "$CHECK_DIR"
  echo "verified: libgojni.so contains hev_socks5_tunnel_main_from_str"
fi
