# SKIPI Core (`skipicore`)

[![Go Reference](https://pkg.go.dev/badge/github.com/ZloyRadetski/skipi-core.svg)](https://pkg.go.dev/github.com/ZloyRadetski/skipi-core)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)

**`skipicore`** is an ultra-fast, modern Go wrapper library around the official [Xray-core](https://github.com/XTLS/Xray-core) engine, specifically designed for seamless mobile integration ([SKIPI](https://github.com/ZloyRadetski/skipi-box) on Android).

## Layout

The root package is the gomobile-bound facade; implementation lives in `internal/` and the desktop
host code in `desktop/`. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the map, the gomobile
binding rule and how to add an exported function. The exported API is pinned by
`testdata/public_api.golden` (`go test .` fails when it changes).

---

## Build (AAR for Android)

```bash
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init
git submodule update --init --recursive   # hev-socks5-tunnel (HEV TUN) and its nested submodules
export ANDROID_NDK_HOME=/path/to/ndk       # NDK r26d or newer
scripts/build-android.sh                   # -> skipicore.aar
```

`scripts/build-android.sh` first runs `scripts/build-hev-android.sh`, which builds
[hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel) (`third_party/hev-socks5-tunnel`,
pinned to 2.19.3) as static libraries for arm64-v8a, armeabi-v7a, x86 and x86_64 into
`build/hev/android/<abi>/`. The submodule is copied, patched with
`third_party/patches/hev-socks5-tunnel/*.patch` (readiness callback, credential-free logs) and built
with `ndk-build`, so it works in Git Bash on Windows as well as on Linux. It then runs
`gomobile bind` with `-androidapi 24 -javapkg=app.skipi.core -ldflags=-checklinkname=0` and
`CGO_LDFLAGS=-Wl,-z,max-page-size=16384` (16 KB page alignment for Android 15+;
`-checklinkname=0` is required by github.com/wlynxg/anet with Go 1.23+), which links the hev
libraries into `libgojni.so` through cgo. `internal/hevtun` is the Go side: Android and Linux
(cgo) link hev in process, Windows runs the hev executable named in the session plan as a
supervised process, macOS runs the same executable under a root supervisor started through the
system's administrator prompt (osascript), and every other build gets a stub that returns "HEV TUN is not built into this
Core on <GOOS>".

In PowerShell, quote `'-javapkg=app.skipi.core'` so the dotted Java package
prefix is passed to `gomobile` as one argument.

## Build (shared library for desktop)

`cmd/skipicore-desktop` packages the same SKIPI Core process as a native shared
 library. It does not launch an external `xray` process. The initial desktop
 targets are Windows x64 and Linux x64.

The build needs a GCC-compatible C compiler. On Windows, use MSYS2 UCRT64 with
`mingw-w64-ucrt-x86_64-gcc`; Visual Studio's `cl.exe` alone is not compatible
with the flags used by Go's CGo toolchain.

On Linux, build HEV TUN first (needs `gcc`, `make`, `patch`; the submodules must be checked out
with `git submodule update --init --recursive`). It links into `libskipicore.so`:

```bash
scripts/build-hev-linux.sh     # -> build/hev/linux-amd64/*.a (patched copy of the submodule, -fPIC)
CGO_ENABLED=1 go build -buildmode=c-shared -trimpath -ldflags='-s -w -buildid= -checklinkname=0' -o libskipicore.so ./cmd/skipicore-desktop
nm -D libskipicore.so | grep hev_socks5_tunnel_main_from_str   # HEV TUN is in the library
```

On Windows the library needs no hev build: the host ships the hev executable (with `wintun.dll`
and its MSYS runtime DLLs next to it) and passes its path as `hev.executable` in the session plan.

```powershell
$env:CGO_ENABLED = "1"
$env:CC = "gcc"
$env:CXX = "g++"
go build -buildmode=c-shared -trimpath -ldflags='-s -w -buildid= -checklinkname=0' -o skipicore.dll ./cmd/skipicore-desktop
```

The command produces `skipicore.dll` and Go's generated C header. The stable
consumer-facing declaration is
[`desktop/include/skipicore_desktop.h`](desktop/include/skipicore_desktop.h).
Call `SkipiCoreDesktopInitializeAssets` with a directory containing the core
assets before creating a session. Strings returned by the API must be released
with `SkipiCoreDesktopFreeString`.

GitHub Actions builds and tests the native library on every pull request and
push to `main`. When tagging a release (`v*`), the desktop binaries and packages
(`skipicore.dll`, `libskipicore.so`, `skipicore-windows-amd64.zip`,
`skipicore-linux-amd64.tar.gz`) are automatically published to the GitHub Release.

---

## 📄 License

This project is licensed under the [GPL-3.0 License](LICENSE).
