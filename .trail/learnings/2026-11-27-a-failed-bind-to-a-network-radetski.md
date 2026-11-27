---
title: "A failed bind to a network counts as a dead link, and a dial spends 4 seconds per attempt while other links remain"
author: Radetski
date: 2026-11-27
branch: feat/net-merge
id: l-5ac562cb
scope: repo
status: active
src: agent
touches:
  - desktop/egress/dialer.go
  - desktop/multilink/nics/host.go
  - desktop/multilink/flowconn.go
  - multilink_host.go
---

## Decided
- A socket that cannot be bound to its Android network fails over to another link and marks the link bad, the same as an unreachable network. Before, only ENETUNREACH did, so the window between a network vanishing and the app reporting new links failed dials.
- The per-attempt budget (4 s) lives in the egress dialer, not in the bound dial, so it also covers the plain base dialer. The last attempt keeps the full budget.
- On Android the app reports the links, so the engine does not run its own rescan loop.

## Tried and ruled out
- Windows error codes in tests: CI is Linux, use portable errno values.
- Running -race through a zig cc wrapper locally: not worth it, CI runs -race.

## Watch out
- TestBrokenLinkFailsOverWithinTheDial was flaky: links are picked at random, with 3 dials Wi-Fi could stay unpicked about 1 time in 8. It uses 40 dials now.
- Known and not done yet: dead game-mode code, limits that do not apply to UDP transports, keepalive for phones not wired, netlink and regexp pulled into the Android AAR.

In the code: desktop/egress/dialer.go, desktop/multilink/nics/host.go (BindError), desktop/multilink/flowconn.go (Classify), multilink_host.go (NoRescan).
