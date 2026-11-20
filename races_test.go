// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ZloyRadetski/skipi-core/internal/hevtun"
)

// M1: a stop that finishes after the next start published its TUN descriptor must not clear it.
func TestAStopDoesNotClearTheDescriptorOfTheNextStart(t *testing.T) {
	first, second := newFakeCoreInstance(), newFakeCoreInstance()
	second.startRelease = make(chan struct{})
	installFakeCore(t, first, second)
	c := NewCoreController(nil)
	if err := c.StartLoop(stopTestConfig, 11); err != nil {
		t.Fatal(err)
	}

	secondErr := make(chan error, 1)
	afterStop := func() {
		go func() { secondErr <- c.StartLoop(stopTestConfig, 22) }()
		waitSignal(t, second.startEntered, "the next start")
	}
	testHookAfterStopUnlock.Store(&afterStop)
	defer testHookAfterStopUnlock.Store(nil)
	if err := c.StopLoop(); err != nil {
		t.Fatal(err)
	}
	testHookAfterStopUnlock.Store(nil)
	got := os.Getenv(tunFdKey)
	close(second.startRelease)
	if err := <-secondErr; err != nil {
		t.Fatal(err)
	}
	_ = c.StopLoop()
	if got != "22" {
		t.Fatalf("the next start's descriptor = %q after the old stop, want 22", got)
	}
}

// M2: a start that ForceStop aborted must not stop the HEV TUN a newer session already runs.
func TestAnAbortedStartLeavesTheNextSessionsHevAlone(t *testing.T) {
	hev := &fakeHev{}
	hev.firstWaitGate = make(chan struct{})
	installOrderedFakes(t, hev)
	hevReadyTimeout = 10 * time.Second
	c := NewCoreController(nil)

	aErr := make(chan error, 1)
	go func() { aErr <- c.StartSession(hevPlan(t, reserveLocalPort(t), false), 0) }()
	deadline := time.Now().Add(3 * time.Second)
	for hev.log.count("hev.waitReady") == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the first readiness wait never began")
		}
		time.Sleep(2 * time.Millisecond)
	}
	_ = c.ForceStop()

	if err := c.StartSession(hevPlan(t, reserveLocalPort(t), false), 0); err != nil {
		t.Fatalf("the next session: %v", err)
	}
	t.Cleanup(func() { _ = c.ForceStop() })
	close(hev.firstWaitGate)
	select {
	case err := <-aErr:
		if err == nil {
			t.Fatal("the aborted start must fail")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the aborted start did not return")
	}
	if !hev.Running() || c.State() != SessionRunning {
		t.Fatalf("the next session lost its HEV TUN: running=%v state=%d log=%s", hev.Running(), c.State(), hev.log)
	}
}

// M5: the listener hears the transitions in the order they happened, even when the goroutine of
// an earlier one is slow to deliver it.
func TestStateNotificationsArriveInOrder(t *testing.T) {
	installFakeCore(t, newFakeCoreInstance())
	c := NewCoreController(nil)
	l := &recordingListener{}
	c.SetStateListener(l)

	inHook, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	beforeDeliver := func(state int) {
		if state == SessionStarting {
			once.Do(func() { close(inHook); <-release })
		}
	}
	testHookBeforeDeliver.Store(&beforeDeliver)
	defer testHookBeforeDeliver.Store(nil)

	startErr := make(chan error, 1)
	go func() { startErr <- c.StartLoop(stopTestConfig, 0) }()
	waitSignal(t, inHook, "the Starting delivery")
	forced := make(chan struct{})
	go func() { _ = c.ForceStop(); close(forced) }()
	select {
	case <-forced:
	case <-time.After(3 * time.Second):
		t.Fatal("ForceStop waited for the listener of another goroutine")
	}
	close(release)
	<-startErr

	deadline := time.Now().Add(3 * time.Second)
	for len(l.states()) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	states := l.states()
	if len(states) != 2 || states[0] != SessionStarting || states[1] != SessionIdle {
		t.Fatalf("states = %v, want [Starting Idle]", states)
	}
}

var _ = hevtun.ErrReadyTimeout
