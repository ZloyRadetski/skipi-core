// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package hevtun

import (
	"testing"
	"time"
)

func TestQuitWaitsUntilNativeLaunch(t *testing.T) {
	var lifecycle instanceLifecycle
	inst, err := lifecycle.start()
	if err != nil {
		t.Fatal(err)
	}
	quit := make(chan struct{})
	go func() {
		if inst.waitUntilQuitReady() {
			close(quit)
		}
	}()
	select {
	case <-quit:
		t.Fatal("quit was called before native launch")
	case <-time.After(20 * time.Millisecond):
	}
	close(inst.ready)
	select {
	case <-quit:
	case <-time.After(time.Second):
		t.Fatal("quit did not proceed after native launch")
	}
}

func TestQuitSkippedWhenSessionExitsBeforeLaunch(t *testing.T) {
	var lifecycle instanceLifecycle
	inst, err := lifecycle.start()
	if err != nil {
		t.Fatal(err)
	}
	close(inst.done)
	if inst.waitUntilQuitReady() {
		t.Fatal("quit should be skipped after the session exits")
	}
}

func TestStartRejectedUntilPreviousQuitReturns(t *testing.T) {
	var lifecycle instanceLifecycle
	old, err := lifecycle.start()
	if err != nil {
		t.Fatal(err)
	}
	if got, quit := lifecycle.beginStop(); got != old || !quit {
		t.Fatal("stop did not claim the old session")
	}
	// HEV can return while the thread that called quit is still inside native code.
	close(old.done)
	if _, err := lifecycle.start(); err == nil {
		t.Fatal("started a new session while the old quit was still running")
	}
	lifecycle.endQuit()
	if _, err := lifecycle.start(); err != nil {
		t.Fatalf("start after quit returned: %v", err)
	}
}

func TestConcurrentStopDoesNotQuitTwice(t *testing.T) {
	var lifecycle instanceLifecycle
	old, err := lifecycle.start()
	if err != nil {
		t.Fatal(err)
	}
	if got, quit := lifecycle.beginStop(); got != old || !quit {
		t.Fatal("first stop did not claim the session")
	}
	if got, quit := lifecycle.beginStop(); got != old || quit {
		t.Fatal("second stop did not wait for the same session")
	}
	lifecycle.endQuit()
	if got, quit := lifecycle.beginStop(); got != old || quit {
		t.Fatal("stop requested native quit again before the session exited")
	}
	close(old.done)
}
