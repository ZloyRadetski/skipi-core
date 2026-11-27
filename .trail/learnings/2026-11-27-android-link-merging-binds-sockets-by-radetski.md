---
title: "Android link merging binds sockets by network handle through a host binder, not by interface"
author: Radetski
date: 2026-11-27
branch: feat/net-merge
id: l-35b667fb
scope: repo
status: active
src: agent
touches:
  - desktop/egress/dialer.go
  - desktop/multilink/engine.go
  - desktop/multilink/nics/kind.go
  - desktop/multilink/nics/nics.go
  - desktop/multilink/probe.go
  - desktop/multilink/sched.go
  - testdata/public_api.golden
---

## Decided
On Android the application reports the links (internal/hostlinks, root API MultilinkSetLinks/Apply/Status) and each link carries the system's network handle, because only the app can list Android's networks. A link with a handle is dialed by egress.dialBound, which binds the socket with android_setsocknetwork (cgo, internal/hostlinks/bind_android.go) before it connects; probes use the same binding through Slot.Control. Without a handle everything is as on desktop.

## Tried and ruled out
Giving Xray's dialer the interface name as on desktop: an Android app may not bind to a device (it fails with a permission error) and routing there follows the network, so the socket would not leave over the chosen link.

## Watch out
Counters (nics.Octets) need an interface index, so Android links show only what SKIPI itself moves. Pinned UDP sockets are still returned as the bare PacketConnWrapper, because transports assert that type.

In the code: desktop/egress/bound.go, desktop/multilink/nics/host.go, internal/hostlinks, multilink_host.go, testdata/public_api.golden.
