# Patches to xray-core's geodata package

SKIPI Core builds against a lightly patched xray-core. xray-core itself is neither forked nor copied
into the repository: `go.mod` pins the upstream version as usual, and these patches are applied to a
copy of that exact version at build time.

## What they do and why

Routing rules with `geoip:`/`geosite:` make xray load the geo files when a tunnel starts. Measured on
the real Loyalsoldier and RunetFreedom files (a heavy rule set with ads, ru-blocked, us, de, cn, nl ...):

| | upstream | patched |
|---|---|---|
| start time | 380-550 ms | 190-210 ms |
| peak memory (Go runtime Sys) | 150-170 MB | 50-65 MB |
| live heap after start | 17 MB | 12 MB |

- `_add/common/geodata/skipi_geoscan.go`: an entry table (code -> offset, length) per geo file, built once
  from the entry headers and reused by every `geoip:`/`geosite:` lookup and by core restarts. Upstream
  reads the file from the start for every code (73 MB for the RunetFreedom geosite).
- `_add/common/geodata/skipi_ipset.go`: streaming decode of a geoip entry straight into packed sorted ranges
  (8 bytes per IPv4 range, 32 per IPv6) instead of `[]*CIDR` -> `netipx.IPSetBuilder` (about 6 copies of
  48 bytes per range) and `IPSet.Prefixes()` twice. Matching results and `max4`/`max6` are the same.
- `modify/common/geodata/geodat_loader.go.patch`: `find`/`loadSite` use the entry table; the forced
  `runtime.GC()` calls before each load are gone.
- `modify/common/geodata/ip_matcher.go.patch`: `IPSet` uses the packed sets, `GetOrCreateFromGeoIPRules`
  loads in two passes (count, then fill exact-size slices), `createFrom` (custom CIDR rules) uses the same builder.
- `_add/common/geodata/skipi_ipset_test.go`: compares the compact sets with netipx on random data, the
  streaming loader with the upstream loader, and the entry table refresh when a file changes.

## How it is built in

`go run ./tools/xrayoverlay` copies xray-core of the version in `go.mod` to `build/xray-overlay/xray-core`,
adds `_add/` files, applies the `modify/` diffs strictly (every context line must match; only line offsets
may move), and prints the path of a `go.mod` variant that replaces xray-core with that copy. `go.mod` and
`go.sum` are not touched. It is cached by a stamp, so it costs ~0.5 s when nothing changed.

```bash
GOFLAGS="-modfile=$(go run ./tools/xrayoverlay)" go build ./...
```

`scripts/build-android.sh` does this itself, and so does the Gradle task that builds the desktop Core
in skipi-box (`BuildDesktopSkipiCoreTask`). Any other way to build the Core (a new CI job, an IDE) must pass
the same `-modfile`, otherwise it builds the unpatched xray-core: it still works, just slower and hungrier.
(`-overlay` cannot be used: Go refuses to replace files in the module cache.)

## Updating xray-core (do all of it)

1. `go get github.com/xtls/xray-core@<version>` (and `go mod tidy`).
2. `scripts/check-xray-patches.sh <dir with geoip.dat and geosite.dat>`. It applies the patches, builds, and
   runs xray's own geodata and router tests plus ours against real geo files. Then run the Core's tests with
   the same `GOFLAGS` it prints.
3. If a patch does not apply, `xrayoverlay` says which file and hunk. Redo the change on the new upstream
   file: copy the pristine file from the module cache to a scratch folder, edit it, and regenerate the
   diff with `git diff --no-index --no-prefix`-style headers `a/<path>` `b/<path>` (see an existing
   `.patch` for the header format). Compare with upstream's own changes to the same place first: if xray
   made geo loading cheaper itself, drop our part of it instead.
4. If xray changed `geodata` internals our files rely on (`seek`, `consumeField`, `errInvalidUTF8`,
   `IPSet` fields `max4`/`max6`, `IPSetFactory`), the build fails to compile: fix `_add/` files.
5. Measure: run the probe or `BenchmarkStartLoopWithGeoRules` with `SKIPI_BENCH_GEO` on the biggest geo
   files and compare with the table above.
