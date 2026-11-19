// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build !windows && !darwin && !(cgo && (android || (linux && skipi_hev)))

package hevtun

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestStubStartReportsClearError(t *testing.T) {
	err := Start("tunnel:\n  mtu: 1500\n", Options{TunFd: 7})
	if err == nil {
		t.Fatal("Start must fail where HEV TUN is not built in")
	}
	want := "HEV TUN is not built into this Core on " + runtime.GOOS
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("Start error = %q, want it to contain %q", err, want)
	}
}

func TestStubWaitReadyReportsClearError(t *testing.T) {
	err := WaitReady(10 * time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "HEV TUN is not built into this Core on "+runtime.GOOS) {
		t.Fatalf("WaitReady error = %v", err)
	}
}

func TestStubIsInertOtherwise(t *testing.T) {
	if Running() {
		t.Fatal("Running() = true on a build without HEV TUN")
	}
	if err := Stop(); err != nil {
		t.Fatalf("Stop() = %v, want nil (nothing to stop)", err)
	}
	if a, b, c, d := Stats(); a|b|c|d != 0 {
		t.Fatalf("Stats() = %d %d %d %d, want zeros", a, b, c, d)
	}
}

func TestSentinelErrorsAreDistinct(t *testing.T) {
	if ErrReadyTimeout == nil || ErrExited == nil || ErrReadyTimeout == ErrExited {
		t.Fatal("ErrReadyTimeout and ErrExited must be distinct non-nil errors")
	}
}

func TestStubStillValidatesTheDescriptor(t *testing.T) {
	if !NeedsTunFd() {
		t.Fatal("NeedsTunFd() = false on a stub build")
	}
}
