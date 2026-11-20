#!/usr/bin/env bash
# Packages the hev-socks5-tunnel runtime for Windows: hev-socks5-tunnel.exe and the Wintun driver
# library.
#
# hev's Windows build cannot be loaded into the Core DLL, so Core runs it as a supervised child
# process (internal/hevtun/hevtun_windows.go). The official release archive is used as is, pinned by
# SHA-256. Since 2.20.0 it is a native build that imports only system DLLs; earlier versions needed
# the MSYS runtime (msys-2.0.dll, msys-gcc_s-seh-1.dll) beside the executable.
#
# Output: build/hev/windows/hev-windows-x64.zip with the two files, the licence and a notice.
# Needs curl, python3 (or PYTHON=...) and sha256sum; it runs on any host.
set -euo pipefail

HEV_VERSION="2.20.0"
HEV_ARCHIVE_SHA256="34fb2bef8000c2c6f948694caeaaf90ee0c307a124e8e436485953804b06c99d"

PYTHON="${PYTHON:-$(command -v python3 || command -v python || echo python3)}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUBMODULE="$ROOT/third_party/hev-socks5-tunnel"
OUT="$ROOT/build/hev/windows"
STAGE="$OUT/stage"

# The pinned archive must be the release of the hev version the submodule is on.
SUBMODULE_VERSION="$(git -C "$SUBMODULE" describe --tags --abbrev=0 2>/dev/null || true)"
if [ -n "$SUBMODULE_VERSION" ] && [ "${SUBMODULE_VERSION#v}" != "$HEV_VERSION" ]; then
  echo "the hev submodule is at $SUBMODULE_VERSION but this script packages $HEV_VERSION; update HEV_VERSION and HEV_ARCHIVE_SHA256" >&2
  exit 1
fi

check_sha() { # file expected
  local actual
  actual="$(sha256sum "$1" | cut -d' ' -f1)"
  [ "$actual" = "$2" ] || { echo "$(basename "$1"): checksum mismatch, expected $2, got $actual" >&2; exit 1; }
}

[ -f "$SUBMODULE/third-part/wintun/LICENSE.txt" ] || {
  echo "hev-socks5-tunnel nested submodules are missing; run: git submodule update --init --recursive" >&2
  exit 1
}

rm -rf "$OUT"
mkdir -p "$STAGE"
ARCHIVE="$OUT/hev-socks5-tunnel-win-x64.zip"
curl -fsSL --retry 3 -o "$ARCHIVE" \
  "https://github.com/heiher/hev-socks5-tunnel/releases/download/$HEV_VERSION/hev-socks5-tunnel-win-x64.zip"
check_sha "$ARCHIVE" "$HEV_ARCHIVE_SHA256"

"$PYTHON" - "$ARCHIVE" "$STAGE" <<'PY'
import sys, zipfile, os
archive, stage = sys.argv[1], sys.argv[2]
wanted = ["hev-socks5-tunnel.exe", "wintun.dll"]
with zipfile.ZipFile(archive) as z:
    names = {os.path.basename(n): n for n in z.namelist() if not n.endswith("/")}
    for w in wanted:
        if w not in names:
            sys.exit("the hev archive does not contain " + w)
        with z.open(names[w]) as src, open(os.path.join(stage, w), "wb") as dst:
            dst.write(src.read())
PY

cp "$SUBMODULE/third-part/wintun/LICENSE.txt" "$STAGE/WINTUN_LICENSE.txt"
cat > "$STAGE/HEV_RUNTIME_NOTICE.txt" <<EOF
hev-socks5-tunnel $HEV_VERSION (MIT) - https://github.com/heiher/hev-socks5-tunnel
wintun.dll (Wintun, see WINTUN_LICENSE.txt) - https://www.wintun.net/
EOF

"$PYTHON" - "$STAGE" "$OUT/hev-windows-x64.zip" <<'PY'
import sys, zipfile, os
stage, out = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for name in sorted(os.listdir(stage)):
        z.write(os.path.join(stage, name), name)
PY

echo "hev-socks5-tunnel $HEV_VERSION runtime for Windows -> $OUT/hev-windows-x64.zip"
