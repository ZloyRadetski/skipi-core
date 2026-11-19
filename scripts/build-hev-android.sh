#!/usr/bin/env bash
# Builds hev-socks5-tunnel (HEV TUN) as static libraries for every Android ABI Core ships.
#
# Output: build/hev/android/<abi>/{libhev-socks5-tunnel,libyaml,liblwip,libhev-task-system}.a
# plus build/hev/include/hev-main.h (the patched public header internal/hevtun includes).
#
# The submodule third_party/hev-socks5-tunnel is never modified: the source is copied to
# build/hev/src, patched there with third_party/patches/hev-socks5-tunnel/*.patch and built with
# ndk-build (hev's own Android.mk files). ndk-build is used because it ships its own make, so the
# same script works on ubuntu CI and in Git Bash on Windows, where there is no make.
#
# Needs ANDROID_NDK_HOME (or ANDROID_NDK_ROOT). Android API level: 24.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUBMODULE="$ROOT/third_party/hev-socks5-tunnel"
PATCH_DIR="$ROOT/third_party/patches/hev-socks5-tunnel"
OUT="$ROOT/build/hev"
SRC="$OUT/src"
ABIS="arm64-v8a armeabi-v7a x86 x86_64"
API=24

NDK="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
[ -n "$NDK" ] || { echo "ANDROID_NDK_HOME is not set" >&2; exit 1; }
[ -d "$NDK" ] || { echo "ANDROID_NDK_HOME does not exist: $NDK" >&2; exit 1; }
[ -f "$SUBMODULE/src/hev-main.c" ] || {
  echo "hev-socks5-tunnel sources are missing; run: git submodule update --init --recursive" >&2
  exit 1
}
[ -f "$SUBMODULE/third-part/yaml/src/api.c" ] || {
  echo "hev-socks5-tunnel nested submodules are missing; run: git submodule update --init --recursive" >&2
  exit 1
}

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    WINDOWS=1
    native() { cygpath -m "$1"; }
    ;;
  *)
    WINDOWS=0
    native() { printf '%s' "$1"; }
    ;;
esac

# 1. Fresh copy of the sources. -h dereferences symlinks (hev's include/ dirs are symlinks).
# Only this script's own directories are replaced, so the Linux libraries under build/hev survive.
rm -rf "$SRC" "$OUT/android"
mkdir -p "$SRC"
(cd "$SUBMODULE" && tar --exclude=.git -chf - .) | (cd "$SRC" && tar -xf -)

# Without symlink support (Windows checkouts) git stores a symlink as a tiny file holding the
# target path: replace those with a copy of the target.
find "$SRC" -type f -size -257c | while IFS= read -r f; do
  target="$(head -c 256 "$f" | tr -d '\r')"
  case "$target" in
    ../*)
      case "$target" in *$'\n'*) continue ;; esac
      if [ -f "$(dirname "$f")/$target" ]; then cp "$(dirname "$f")/$target" "$f"; fi
      ;;
  esac
done

# 2. Normalise line endings (a Windows checkout is CRLF), then apply the patches.
find "$SRC" -type f \( -name '*.c' -o -name '*.h' -o -name '*.S' -o -name '*.mk' -o -name Makefile \) \
  -exec sed -i 's/\r$//' {} +
for p in "$PATCH_DIR"/*.patch; do
  echo "patch: $(basename "$p")"
  patch -p1 -d "$SRC" --no-backup-if-mismatch < "$p"
done

# 3. Generated top-level Android.mk: hev as a static library next to its third-party libraries.
mkdir -p "$OUT/ndk/jni"
cat > "$OUT/ndk/jni/Android.mk" <<MK
HEV_PATH := $(native "$SRC")
TOP_PATH := \$(HEV_PATH)

include \$(TOP_PATH)/third-part/yaml/Android.mk
include \$(TOP_PATH)/third-part/lwip/Android.mk
ENABLE_MEMALLOC_SLICE := 0
include \$(TOP_PATH)/third-part/hev-task-system/Android.mk

LOCAL_PATH := \$(TOP_PATH)
SRCDIR := \$(LOCAL_PATH)/src
include \$(CLEAR_VARS)
include \$(LOCAL_PATH)/build.mk
LOCAL_MODULE := hev-socks5-tunnel
LOCAL_SRC_FILES := \$(filter-out src/hev-jni.c,\$(patsubst \$(SRCDIR)/%,src/%,\$(SRCFILES)))
LOCAL_C_INCLUDES := \
    \$(LOCAL_PATH)/src \
    \$(LOCAL_PATH)/src/misc \
    \$(LOCAL_PATH)/src/core/include \
    \$(LOCAL_PATH)/third-part/yaml/include \
    \$(LOCAL_PATH)/third-part/lwip/src/include \
    \$(LOCAL_PATH)/third-part/lwip/src/ports/include \
    \$(LOCAL_PATH)/third-part/hev-task-system/include
LOCAL_CFLAGS += -DFD_SET_DEFINED -DSOCKLEN_T_DEFINED -DENABLE_LIBRARY
LOCAL_CFLAGS += -fno-stack-clash-protection \$(VERSION_CFLAGS)
ifeq (\$(TARGET_ARCH_ABI),armeabi-v7a)
LOCAL_CFLAGS += -mfpu=neon
endif
LOCAL_STATIC_LIBRARIES := yaml lwip hev-task-system
include \$(BUILD_STATIC_LIBRARY)
MK

# 4. ndk-build. REV_ID is passed in because the copy has no git metadata of its own.
REV_ID="$(git -C "$SUBMODULE" rev-parse --short HEAD 2>/dev/null || echo unknown)"
if [ "$WINDOWS" = 1 ]; then
  NDK_BUILD=("$(native "$NDK")/ndk-build.cmd")
else
  NDK_BUILD=("$NDK/ndk-build")
fi
JOBS="$(nproc 2>/dev/null || echo 4)"
[ "$JOBS" -le 8 ] || JOBS=8 # ndk-build on Windows can race its dependency files with many jobs
(
  cd "$OUT/ndk"
  "${NDK_BUILD[@]}" -j"$JOBS" \
    NDK_PROJECT_PATH="$(native "$OUT/ndk")" \
    APP_BUILD_SCRIPT="$(native "$OUT/ndk/jni/Android.mk")" \
    APP_ABI="$ABIS" \
    APP_MODULES="hev-socks5-tunnel yaml lwip hev-task-system" \
    APP_PLATFORM="android-$API" \
    NDK_LIBS_OUT="$(native "$OUT/ndk/libs")" \
    NDK_OUT="$(native "$OUT/ndk/obj")" \
    APP_CFLAGS="-O3" \
    REV_ID="$REV_ID"
)

# 5. Collect the archives and the patched header.
for abi in $ABIS; do
  dest="$OUT/android/$abi"
  mkdir -p "$dest"
  for lib in hev-socks5-tunnel yaml lwip hev-task-system; do
    a="$OUT/ndk/obj/local/$abi/lib$lib.a"
    [ -s "$a" ] || { echo "missing $a" >&2; exit 1; }
    cp "$a" "$dest/lib$lib.a"
  done
done
mkdir -p "$OUT/include"
cp "$SRC/src/hev-main.h" "$OUT/include/hev-main.h"
echo "hev-socks5-tunnel (rev $REV_ID) built for: $ABIS -> $OUT/android"
