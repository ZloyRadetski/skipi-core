# SKIPI Core (`skipicore`)

[![Go Reference](https://pkg.go.dev/badge/github.com/ZloyRadetski/skipi-core.svg)](https://pkg.go.dev/github.com/ZloyRadetski/skipi-core)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)

**`skipicore`** is an ultra-fast, modern Go wrapper library around the official [Xray-core](https://github.com/XTLS/Xray-core) engine, specifically designed for seamless mobile integration ([SKIPI](https://github.com/ZloyRadetski/skipi-box) on Android).

---

## 🌟 Key Features

* 🚀 **Full Xray-core Integration:** Complete support for VLESS (XTLS Reality & Vision), VMess, Trojan, Shadowsocks (2022), Hysteria 2, WireGuard, and standard SOCKS5/HTTP.
* 📦 **Mobile-Optimized Bindings:** Direct GoMobile bindings generating Android AAR with clean JNI exports.
* ⚡ **High Performance & Stability:** Thread-safe instance management with minimal overhead and rapid startup/teardown.
* 🔍 **Built-in Latency Prober:** Fast outbound latency and availability testing against HTTP endpoints.
* 🛡 **100% Free & Open-Source:** Licensed under GPL-3.0 with zero telemetry and zero ads.

---

## 🛠 Local Build (AAR for Android)

To build `skipicore.aar` locally for Android:

```bash
# 1. Install gomobile
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init

# 2. Compile AAR targeting Android ABI architectures
gomobile bind -target=android -androidapi 24 -javapkg=app.skipi.core -o skipicore.aar .
```

---

## 📄 License

This project is licensed under the [GPL-3.0 License](LICENSE).
