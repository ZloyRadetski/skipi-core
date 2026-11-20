// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"errors"
	"testing"
	"time"
)

// installBlockingAwgBuild makes the slow part of StartAmneziaWg (DNS, device up) wait for release.
func installBlockingAwgBuild(t *testing.T) (entered, release chan struct{}, stops *int) {
	t.Helper()
	entered, release = make(chan struct{}, 4), make(chan struct{})
	n := 0
	stops = &n
	origBuild, origStop := buildAwgRunner, awgStop
	buildAwgRunner = func(string, int) (*AmneziaWgRunner, error) {
		entered <- struct{}{}
		<-release
		return &AmneziaWgRunner{running: true}, nil
	}
	awgStop = func(*AmneziaWgRunner) error { n++; return nil }
	t.Cleanup(func() {
		buildAwgRunner, awgStop = origBuild, origStop
		awgGlobalMu.Lock()
		activeAwgRunner = nil
		awgGlobalMu.Unlock()
	})
	return entered, release, stops
}

// H3: the global AmneziaWG lock is not held while a runner resolves its peer and comes up.
func TestAwgStopAndStateDoNotWaitForASlowAwgStart(t *testing.T) {
	entered, release, stops := installBlockingAwgBuild(t)
	startErr := make(chan error, 1)
	go func() { startErr <- StartAmneziaWg("{}", 1080) }()
	<-entered

	within(t, time.Second, "IsAmneziaWgRunning", func() { _ = IsAmneziaWgRunning() })
	within(t, time.Second, "StopAmneziaWgWithTimeout", func() { _ = StopAmneziaWgWithTimeout(100) })
	within(t, time.Second, "ForceStop", func() { _ = NewCoreController(nil).ForceStop() })

	close(release)
	err := <-startErr
	if err == nil {
		t.Fatal("a start that a stop overtook must fail")
	}
	if IsAmneziaWgRunning() {
		t.Fatal("the runner built after the stop must not be left running")
	}
	if *stops != 1 {
		t.Fatalf("the late runner must be stopped once, stops = %d", *stops)
	}
}

// H4: a latency probe (the public StartAmneziaWg/StopAmneziaWg) must never take the runner of a
// running session away; the session would stay Running with its traffic dead.
func TestAProbeCannotReplaceOrStopTheSessionsRunner(t *testing.T) {
	awg := installFakeAwg(t, 0)
	installFakeCore(t, newFakeCoreInstance())
	port := reserveLocalPort(t)
	c := NewCoreController(nil)
	if err := c.StartSession(buildPlan(t, port, true), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.ForceStop() })
	awgGlobalMu.Lock()
	sessionRunner := activeAwgRunner
	awgGlobalMu.Unlock()

	if err := StartAmneziaWg("{}", reserveLocalPort(t)); !errors.Is(err, ErrAmneziaWgInUse) {
		t.Fatalf("probe start err = %v, want ErrAmneziaWgInUse", err)
	}
	if err := StopAmneziaWg(); err != nil {
		t.Fatalf("probe stop err = %v", err)
	}
	awgGlobalMu.Lock()
	still := activeAwgRunner
	awgGlobalMu.Unlock()
	if still != sessionRunner || awg.stops.Load() != 0 {
		t.Fatalf("the session's runner was touched: same=%v stops=%d", still == sessionRunner, awg.stops.Load())
	}
	if err := c.StopLoop(); err != nil {
		t.Fatal(err)
	}
	if awg.stops.Load() != 1 {
		t.Fatalf("the session's own stop must stop its runner, stops = %d", awg.stops.Load())
	}
}
