---
title: "Core puts its own dialer in front of Xray at load, so dialer controllers go through it, never Xray's registry"
author: Radetski
date: 2026-11-27
branch: feat/net-merge
id: l-db850069
scope: repo
status: active
src: agent
touches:
  - desktop/egress/install.go
  - desktop/egress/dialer.go
  - desktop/tunhost/binding.go
  - desktop/bridge/bridge_test.go
---

## Decided
SKIPI Core's desktop library installs one system dialer for Xray when it loads (link merging needs a choice per connection). Xray accepts RegisterDialerController only while its default dialer is in effect, so the one controller is registered first, at load, and everything else swaps what it runs: the TUN binding to the physical link sets it through egress.

Off, or with fewer than two usable links, every dial reaches Xray's dialer unchanged; that is the guarantee that TUN, DNS and AmneziaWG behave as before.

UDP sockets are pinned to a link but returned unwrapped: masque, WireGuard and udphop assert *net.PacketConnWrapper, and quic-go only enables GSO on a bare UDP socket. TCP connections are wrapped to count bytes and see the close, which costs Vision its splice/readv while merging is on.

## Tried and ruled out
Calling RegisterDialerController lazily from tunhost after the dialer is installed: Xray refuses it and TUN mode stops starting (the tunhost tests caught it).

## Watch out
A test or package that needs to see every dial must append to internet.Controllers under ControllersLock (as the bridge tests do) or use egress.SetController; RegisterDialerController fails once the package egress is linked.

In the code: desktop/egress/install.go, desktop/egress/dialer.go, desktop/tunhost/binding.go, desktop/bridge/bridge_test.go TestMain.
