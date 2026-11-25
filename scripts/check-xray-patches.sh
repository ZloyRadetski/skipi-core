#!/usr/bin/env bash
# Run this after every xray-core update (go get github.com/xtls/xray-core@...) and before a release.
#
# 1. Applies patches/xray-geodata to the xray-core version pinned in go.mod (fails if a patch no longer
#    applies).
# 2. Builds the Core and the desktop entry point against the patched xray-core.
# 3. Runs xray-core's own geodata tests plus the SKIPI patch tests (compact IP sets vs netipx, streaming
#    loader vs the upstream loader, entry index refresh) against real geoip.dat/geosite.dat.
#
# Usage: scripts/check-xray-patches.sh <dir with geoip.dat and geosite.dat>
#   (for example the Loyalsoldier files from skipi-box/shared/bundled/geo, unpacked with xz -d)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

GEO_DIR="${1:-}"
if [ -z "$GEO_DIR" ] || [ ! -f "$GEO_DIR/geoip.dat" ] || [ ! -f "$GEO_DIR/geosite.dat" ]; then
  echo "usage: $0 <dir with geoip.dat and geosite.dat>" >&2
  exit 2
fi

MODFILE="$(go run ./tools/xrayoverlay)"
echo "patches apply; patched xray-core: $(dirname "$MODFILE")/xray-core"
export GOFLAGS="${GOFLAGS:+$GOFLAGS }-modfile=$MODFILE"

go build . ./cmd/...

# xray-core's tests read ../../resources relative to the package: give them the real geo files.
mkdir -p "$(dirname "$MODFILE")/xray-core/resources"
cp "$GEO_DIR/geoip.dat" "$GEO_DIR/geosite.dat" "$(dirname "$MODFILE")/xray-core/resources/"
go test github.com/xtls/xray-core/common/geodata/... github.com/xtls/xray-core/app/router/...

echo "xray patches OK. Now also run the Core's own tests: GOFLAGS=\"$GOFLAGS\" go test ."
