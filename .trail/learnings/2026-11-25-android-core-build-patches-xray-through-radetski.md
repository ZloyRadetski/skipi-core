---
title: "Android core build patches xray through a temporary go.mod replace, because gomobile rejects -modfile and GOWORK"
author: Radetski
date: 2026-11-25
branch: main
id: l-2e1813a5
scope: repo
status: active
src: agent
touches:
  - internal/hevtun/hevtun_cgo.c
  - go.mod
  - go.sum
  - scripts/check-xray-patches.sh
  - scripts/build-android.sh
---

## Decided
The Android AAR build adds a replace for xray-core to go.mod only while the script runs and restores go.mod and go.sum on exit. Desktop and CI tests keep using -modfile.

## Tried and ruled out
- GOFLAGS=-modfile: gomobile probes with GO111MODULE=off, where the flag is an error, so its "x/mobile in module graph" check fails.
- GOWORK with a replace: gomobile builds ./gobind in a temporary module that is not in the workspace.

## Watch out
If the script is killed hard, go.mod can keep the replace line; check git diff go.mod. Recheck patches after every xray-core update (scripts/check-xray-patches.sh).

In the code: scripts/build-android.sh (trap restoring go.mod), tools/xrayoverlay, patches/xray-geodata.
