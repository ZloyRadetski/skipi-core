---
title: "The Linux TUN descriptor is duplicated before Xray gets it, so tests that start the controller must stub the duplicate"
author: Radetski
date: 2026-11-23
branch: main
id: l-29a45488
scope: repo
status: active
src: agent
touches:
  - internal/hevtun/hevtun_cgo.c
  - tunfd_linux.go
  - tunfd_other.go
  - stop_timeout_test.go
---

## Decided
On Linux the core hands Xray a duplicate of the TUN descriptor, because Xray closes the one it is given and the desktop TUN session closes its own. A duplicate that cannot be made stops the start.

## Tried and ruled out
Moving the v1.2.8 tag after the CI failure: a published tag is not rewritten, the fix went out as v1.2.9.

## Watch out
Tests start the controller with made-up descriptor numbers (4242, 11, 22). On Linux the duplicate fails on them with "bad file descriptor", and this only shows in CI, not on Windows where the duplicate is an identity function. Any new test that calls StartLoop with a fake descriptor must go through installFakeCore, which stubs the duplicate and the close.

In the code:
- tunfd_linux.go, tunfd_other.go: platformDupTunFd, platformCloseTunFd
- stop_timeout_test.go: installFakeCore
