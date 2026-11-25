---
title: "Core 1.2.5 audit: failed tunnel DNS lookups are cached; the SOCKS pre-auth limit and UDP first-sender binding were left alone on purpose"
author: Radetski
date: 2026-11-20
branch: main
id: l-ee24ffdc
scope: repo
status: active
src: agent
touches:
  - amneziawg_socks.go
  - desktop/winnet/defaults_windows.go
  - amneziawg_dnscache_test.go
  - desktop/winnet/systemtool_windows_test.go
---

## Decided
- The AmneziaWG tunnel DNS remembers failed lookups for 5 seconds and lets callers asking for one name share a single query that runs under its own timeout. A dead name used to cost the full 5 s lookup timeout on every datagram, and a UDP association has one reader, so it stalled the whole association. A full cache now gives up one entry, not all.
- On Windows, netsh and powershell.exe are started from the Windows directory, not through PATH, because Core can run elevated.

## Tried and ruled out
- A separate limit for connections still in the SOCKS handshake: every client on loopback looks the same, so silent connections would block the real client as well. It is the same-user trust boundary, nothing gained.
- Tightening the UDP association so only a named client address is accepted: the first loopback sender fixes the client address when none was named. Xray may open the association without an address, so this could break UDP. Not changed; check how Xray opens it first.

## Watch out
- The installed govulncheck was built with an older Go and cannot load the Go 1.27 standard library ("generic method requires go1.27"). Dependencies were not scanned for known vulnerabilities in this audit; run a govulncheck built with Go 1.27.
- Whether the desktop build calls runtimetuning.Init (which halves GOMAXPROCS on every platform) was not checked.

In the code: skipi-core amneziawg_socks.go (lookupTunnelHost, storeTunnelDNSLocked), desktop/winnet/defaults_windows.go (systemTool), tests amneziawg_dnscache_test.go and desktop/winnet/systemtool_windows_test.go. Released as v1.2.5.
