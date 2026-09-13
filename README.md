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
gomobile bind -target=android -androidapi 24 -javapkg=app.skipi.core -ldflags=-checklinkname=0 -o skipicore.aar .
```

In PowerShell, quote `'-javapkg=app.skipi.core'` so the dotted Java package
prefix is passed to `gomobile` as one argument.

---

## 📄 License

This project is licensed under the [GPL-3.0 License](LICENSE).
