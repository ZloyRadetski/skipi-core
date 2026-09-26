# SKIPI Core (`skipicore`)

[![Go Reference](https://pkg.go.dev/badge/github.com/ZloyRadetski/skipi-core.svg)](https://pkg.go.dev/github.com/ZloyRadetski/skipi-core)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)

**`skipicore`** is an ultra-fast, modern Go wrapper library around the official [Xray-core](https://github.com/XTLS/Xray-core) engine, specifically designed for seamless mobile integration ([SKIPI](https://github.com/ZloyRadetski/skipi-box) on Android).
---

## Build (AAR for Android)
```bash
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init
# github.com/wlynxg/anet requires this linker flag with Go 1.23+.
# Align native library to 16 KB page size for Android 15+ compatibility:
export CGO_LDFLAGS="-Wl,-z,max-page-size=16384"
gomobile bind -target=android -androidapi 24 -javapkg=app.skipi.core -ldflags=-checklinkname=0 -o skipicore.aar .
```

In PowerShell, quote `'-javapkg=app.skipi.core'` so the dotted Java package
prefix is passed to `gomobile` as one argument.

## Build (shared library for desktop)

`cmd/skipicore-desktop` packages the same SKIPI Core process as a native shared
 library. It does not launch an external `xray` process. The initial desktop
 targets are Windows x64 and Linux x64.

The build needs a GCC-compatible C compiler. On Windows, use MSYS2 UCRT64 with
`mingw-w64-ucrt-x86_64-gcc`; Visual Studio's `cl.exe` alone is not compatible
with the flags used by Go's CGo toolchain.

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
push to `main`. The Windows build uses MSYS2; the artifacts are
`skipicore-desktop-windows-amd64` and `skipicore-desktop-linux-amd64`.

---

## 📄 License

This project is licensed under the [GPL-3.0 License](LICENSE).
