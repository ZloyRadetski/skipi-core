---
title: "Core speed review: the Go side is not the bottleneck, so GOMAXPROCS and the relay were left alone"
author: Radetski
date: 2026-11-20
branch: main
id: l-5f70a045
scope: repo
status: active
src: agent
touches:
  - desktop/sysproxy/manager.go
  - internal/amneziawg/resolve.go
  - internal/amneziawg/socks.go
---

## Decided
- Measured on a 20-core machine: a full Xray start with geo routing rules takes about 44 ms and does not change with GOMAXPROCS 2, 4, 10 or 20 (it is single-threaded work). Core's relay for AmneziaWG SOCKS runs at the speed of a plain io.Copy (about 1.5-1.7 GB/s on loopback). The traffic snapshot costs about 10 microseconds and a routed connection about 2 microseconds in the connection log.
- So the halved GOMAXPROCS (mobile-first profile, also applied on desktop) was not changed: the proxy path already moves gigabytes per second at 2 threads, far above any real link, and more threads would only compete with the app's UI in the same process.
- The lease file of the system proxy is now synced to disk before the rename, so a crash leaves the old or the new lease, never an empty one (an empty file reads as no lease and strands the user's proxy settings).

## Tried and ruled out
- A loopback throughput benchmark through Xray: it counted bytes written, not delivered, and overstated the speed; dropped rather than kept as a misleading number.
- golangci-lint and govulncheck: the installed binaries were built with Go 1.26 and cannot load a Go 1.27 module; running a fresh govulncheck was refused. Only go vet (clean on Windows, Linux, macOS), gofmt and go mod tidy were checked.

## Watch out
- The C ABI keeps one global last-error string that every successful call clears, so a poll on another thread can erase the message of a failed call before the host reads it. Not changed.
- Windows hev: a crash of the host leaves its YAML (SOCKS credentials, protected file rights) in the temp folder; nothing sweeps old ones at the next start. Not changed.
- Benchmarks live in internal/amneziawg, internal/connlog, internal/trafficstats and bench_start_test.go (set SKIPI_BENCH_GEO to a folder with geoip.dat and geosite.dat).

In the code: skipi-core desktop/sysproxy/manager.go (saveLease), internal/runtimetuning, internal/amneziawg/socks.go (Relay).
