---
title: "Tests that fake a network error use portable errors, because CI runs them on Linux"
author: Radetski
date: 2026-11-27
branch: feat/net-merge
id: l-40cd2076
scope: repo
status: active
src: agent
touches:
  - desktop/egress/dialer_test.go
  - desktop/multilink/flowconn.go
---

## Decided
Tests that fake a dial error use syscall.ENETUNREACH and syscall.ECONNREFUSED, because the release CI runs go test on Linux and a Windows WSA code (10051, 10061) is not read as "network unreachable" there; the failover test then saw no link error and dialed the link 0 times instead of once.

## Watch out
Tests written on Windows pass locally and can still fail on the Linux CI; the local machine has no gcc, so go test -race cannot be run here, and a CI failure is only visible in the Actions log.

In the code: desktop/egress/dialer_test.go (unreachable(), TestRefusalIsNotRetried), classified by desktop/multilink/flowconn.go Classify.
