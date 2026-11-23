// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/core"
)

const stopTestConfig = `{
	"log": { "loglevel": "none" },
	"outbounds": [ { "protocol": "freedom", "tag": "direct" } ]
}`

// fakeCoreInstance stands in for *core.Instance. Close and Start block until released when the
// matching channel is non-nil.
type fakeCoreInstance struct {
	closeEntered chan struct{}
	closeRelease chan struct{} // nil: Close returns at once
	closeErr     error
	closeCalls   atomic.Int32

	startEntered chan struct{}
	startRelease chan struct{} // nil: Start returns at once
}

func newFakeCoreInstance() *fakeCoreInstance {
	return &fakeCoreInstance{
		closeEntered: make(chan struct{}, 4),
		startEntered: make(chan struct{}, 4),
	}
}

func (f *fakeCoreInstance) Close() error {
	f.closeCalls.Add(1)
	f.closeEntered <- struct{}{}
	if f.closeRelease != nil {
		<-f.closeRelease
	}
	return f.closeErr
}

// installFakeCore routes controller starts to the supplied fakes, one per start, and restores
// the production constructors afterwards.
func installFakeCore(t *testing.T, fakes ...*fakeCoreInstance) {
	t.Helper()
	origCreate, origStart := createCoreInstance, startCoreInstance
	origDup, origCloseFd := dupTunFd, closeTunFd
	// These tests hand StartLoop made-up descriptor numbers, which the Linux duplicate rejects.
	dupTunFd, closeTunFd = func(fd int64) (int64, error) { return fd, nil }, func(int64) {}
	var next atomic.Int32
	createCoreInstance = func(*core.Config) (coreInstance, error) {
		i := int(next.Add(1)) - 1
		return fakes[i], nil
	}
	startCoreInstance = func(inst coreInstance) error {
		f := inst.(*fakeCoreInstance)
		f.startEntered <- struct{}{}
		if f.startRelease != nil {
			<-f.startRelease
		}
		return nil
	}
	t.Cleanup(func() {
		createCoreInstance, startCoreInstance = origCreate, origStart
		dupTunFd, closeTunFd = origDup, origCloseFd
		waitAbandonedZero(t)
	})
}

func waitAbandonedZero(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for AbandonedInstances() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("AbandonedInstances() = %d, want 0", AbandonedInstances())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func within(t *testing.T, limit time.Duration, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatalf("%s did not return within %v", what, limit)
	}
}

func waitSignal(t *testing.T, ch chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

type recordingCallback struct {
	startups, shutdowns atomic.Int32
}

func (r *recordingCallback) Startup() int64                                { r.startups.Add(1); return 0 }
func (r *recordingCallback) Shutdown() int64                               { r.shutdowns.Add(1); return 0 }
func (r *recordingCallback) OnEmitStatus(code int64, message string) int64 { return 0 }

func TestStopLoopWithTimeoutReturnsWhenCloseHangs(t *testing.T) {
	fake := newFakeCoreInstance()
	fake.closeRelease = make(chan struct{})
	installFakeCore(t, fake)
	cb := &recordingCallback{}
	ctrl := NewCoreController(cb)
	if err := ctrl.StartLoop(stopTestConfig, 4242); err != nil {
		t.Fatalf("StartLoop: %v", err)
	}

	began := time.Now()
	var err error
	within(t, 2*time.Second, "StopLoopWithTimeout", func() { err = ctrl.StopLoopWithTimeout(100) })
	elapsed := time.Since(began)

	if !errors.Is(err, ErrStopTimedOut) {
		t.Fatalf("err = %v, want ErrStopTimedOut", err)
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("message %q must contain 'timed out'", err.Error())
	}
	if elapsed < 90*time.Millisecond || elapsed > 1500*time.Millisecond {
		t.Fatalf("returned after %v, want about 100ms", elapsed)
	}
	if ctrl.IsRunning() {
		t.Fatal("controller must be detached and not running")
	}
	if got := os.Getenv(tunFdKey); got != "" {
		t.Fatalf("tun fd env not cleared: %q", got)
	}
	if cb.shutdowns.Load() != 1 {
		t.Fatalf("Shutdown callbacks = %d, want 1", cb.shutdowns.Load())
	}
	if got := AbandonedInstances(); got != 1 {
		t.Fatalf("AbandonedInstances() = %d, want 1", got)
	}

	close(fake.closeRelease)
	waitAbandonedZero(t)
}

func TestStopLoopWithTimeoutReturnsCloseError(t *testing.T) {
	fake := newFakeCoreInstance()
	fake.closeErr = errors.New("close boom")
	installFakeCore(t, fake)
	cb := &recordingCallback{}
	ctrl := NewCoreController(cb)
	if err := ctrl.StartLoop(stopTestConfig, 0); err != nil {
		t.Fatalf("StartLoop: %v", err)
	}
	err := ctrl.StopLoopWithTimeout(1000)
	if err == nil || errors.Is(err, ErrStopTimedOut) || err.Error() != "close boom" {
		t.Fatalf("err = %v, want the Close error", err)
	}
	if ctrl.IsRunning() || cb.shutdowns.Load() != 1 || AbandonedInstances() != 0 {
		t.Fatalf("cleanup incomplete: running=%v shutdowns=%d abandoned=%d",
			ctrl.IsRunning(), cb.shutdowns.Load(), AbandonedInstances())
	}
}

func TestStopLoopWithTimeoutWhenNotRunningIsNil(t *testing.T) {
	ctrl := NewCoreController(&recordingCallback{})
	if err := ctrl.StopLoopWithTimeout(10); err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if err := ctrl.ForceStop(); err != nil {
		t.Fatalf("ForceStop on idle = %v, want nil", err)
	}
}

func TestStopLoopWithTimeoutNonPositiveUsesDefault(t *testing.T) {
	orig := defaultStopTimeout
	defaultStopTimeout = 80 * time.Millisecond
	t.Cleanup(func() { defaultStopTimeout = orig })

	fake := newFakeCoreInstance()
	fake.closeRelease = make(chan struct{})
	installFakeCore(t, fake)
	ctrl := NewCoreController(&recordingCallback{})
	if err := ctrl.StartLoop(stopTestConfig, 0); err != nil {
		t.Fatalf("StartLoop: %v", err)
	}
	var err error
	within(t, 2*time.Second, "StopLoopWithTimeout(0)", func() { err = ctrl.StopLoopWithTimeout(0) })
	if !errors.Is(err, ErrStopTimedOut) {
		t.Fatalf("err = %v, want ErrStopTimedOut", err)
	}
	close(fake.closeRelease)
}

func TestControllerReadsStayResponsiveWhileCloseIsBlocked(t *testing.T) {
	fake := newFakeCoreInstance()
	fake.closeRelease = make(chan struct{})
	installFakeCore(t, fake)
	ctrl := NewCoreController(&recordingCallback{})
	if err := ctrl.StartLoop(stopTestConfig, 0); err != nil {
		t.Fatalf("StartLoop: %v", err)
	}
	stopDone := make(chan error, 1)
	go func() { stopDone <- ctrl.StopLoopWithTimeout(2000) }()
	waitSignal(t, fake.closeEntered, "Close to start")

	within(t, 500*time.Millisecond, "reads during blocked Close", func() {
		_ = ctrl.IsRunning()
		_ = ctrl.QueryTrafficStats()
		_ = ctrl.QueryAllOutboundTrafficStats()
		_ = ctrl.ReadConnectionLog(0)
		ctrl.SetConnectionLogEnabled(true)
		_, _ = ctrl.MeasureDelay("http://127.0.0.1:1/")
	})

	close(fake.closeRelease)
	if err := <-stopDone; err != nil {
		t.Fatalf("StopLoopWithTimeout: %v", err)
	}
}

func TestForceStopAbortsStartInFlight(t *testing.T) {
	fake := newFakeCoreInstance()
	fake.startRelease = make(chan struct{})
	installFakeCore(t, fake)
	cb := &recordingCallback{}
	ctrl := NewCoreController(cb)

	startErr := make(chan error, 1)
	go func() { startErr <- ctrl.StartLoop(stopTestConfig, 777) }()
	waitSignal(t, fake.startEntered, "server.Start")

	within(t, time.Second, "ForceStop during start", func() { _ = ctrl.ForceStop() })
	if ctrl.IsRunning() {
		t.Fatal("must not be running")
	}

	close(fake.startRelease) // the hung start finally returns
	select {
	case err := <-startErr:
		if err == nil {
			t.Fatal("StartLoop must fail after ForceStop")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("StartLoop did not return")
	}
	waitSignal(t, fake.closeEntered, "half-built instance to be closed")
	if ctrl.IsRunning() || cb.startups.Load() != 0 {
		t.Fatalf("aborted start was installed: running=%v startups=%d", ctrl.IsRunning(), cb.startups.Load())
	}
	waitAbandonedZero(t)
}

func TestForceStopWhileStopIsHungDoesNotDoubleCount(t *testing.T) {
	fake := newFakeCoreInstance()
	fake.closeRelease = make(chan struct{})
	installFakeCore(t, fake)
	ctrl := NewCoreController(&recordingCallback{})
	if err := ctrl.StartLoop(stopTestConfig, 0); err != nil {
		t.Fatalf("StartLoop: %v", err)
	}
	stopErr := make(chan error, 1)
	go func() { stopErr <- ctrl.StopLoopWithTimeout(60000) }()
	waitSignal(t, fake.closeEntered, "Close to start")

	var err error
	within(t, time.Second, "ForceStop during hung stop", func() { err = ctrl.ForceStop() })
	if !errors.Is(err, ErrStopTimedOut) {
		t.Fatalf("ForceStop err = %v, want ErrStopTimedOut", err)
	}
	if got := AbandonedInstances(); got != 1 {
		t.Fatalf("AbandonedInstances() = %d, want 1", got)
	}
	select {
	case e := <-stopErr:
		if !errors.Is(e, ErrStopTimedOut) {
			t.Fatalf("original StopLoop err = %v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("original StopLoopWithTimeout still blocked after ForceStop")
	}
	if ctrl.IsRunning() {
		t.Fatal("must not be running")
	}
	close(fake.closeRelease)
	waitAbandonedZero(t)
}

func TestForceStopOnRunningUsesShortDeadline(t *testing.T) {
	fake := newFakeCoreInstance()
	fake.closeRelease = make(chan struct{})
	installFakeCore(t, fake)
	ctrl := NewCoreController(&recordingCallback{})
	if err := ctrl.StartLoop(stopTestConfig, 0); err != nil {
		t.Fatalf("StartLoop: %v", err)
	}
	var err error
	within(t, 4*time.Second, "ForceStop", func() { err = ctrl.ForceStop() })
	if !errors.Is(err, ErrStopTimedOut) || ctrl.IsRunning() || AbandonedInstances() != 1 {
		t.Fatalf("err=%v running=%v abandoned=%d", err, ctrl.IsRunning(), AbandonedInstances())
	}
	close(fake.closeRelease)
}

func TestStartLoopWorksAfterTimedOutStop(t *testing.T) {
	first := newFakeCoreInstance()
	first.closeRelease = make(chan struct{})
	second := newFakeCoreInstance()
	installFakeCore(t, first, second)
	ctrl := NewCoreController(&recordingCallback{})

	if err := ctrl.StartLoop(stopTestConfig, 0); err != nil {
		t.Fatalf("first StartLoop: %v", err)
	}
	if err := ctrl.StopLoopWithTimeout(50); !errors.Is(err, ErrStopTimedOut) {
		t.Fatalf("stop err = %v", err)
	}
	if err := ctrl.StartLoop(stopTestConfig, 0); err != nil {
		t.Fatalf("second StartLoop: %v", err)
	}
	if !ctrl.IsRunning() {
		t.Fatal("second start must be running")
	}
	// Releasing the abandoned first Close must not disturb the new session.
	close(first.closeRelease)
	waitAbandonedZero(t)
	if !ctrl.IsRunning() {
		t.Fatal("new session must survive the abandoned Close finishing")
	}
	if err := ctrl.StopLoop(); err != nil {
		t.Fatalf("StopLoop: %v", err)
	}
	if second.closeCalls.Load() != 1 {
		t.Fatalf("second Close calls = %d", second.closeCalls.Load())
	}
}

func TestStartLoopRejectedWhileStarting(t *testing.T) {
	fake := newFakeCoreInstance()
	fake.startRelease = make(chan struct{})
	installFakeCore(t, fake)
	ctrl := NewCoreController(&recordingCallback{})
	startErr := make(chan error, 1)
	go func() { startErr <- ctrl.StartLoop(stopTestConfig, 0) }()
	waitSignal(t, fake.startEntered, "server.Start")
	within(t, time.Second, "second StartLoop", func() {
		if err := ctrl.StartLoop(stopTestConfig, 0); err == nil {
			t.Error("second StartLoop must be rejected")
		}
	})
	close(fake.startRelease)
	if err := <-startErr; err != nil {
		t.Fatalf("first StartLoop: %v", err)
	}
}

func TestStopAmneziaWgWithTimeoutDetachesHungClose(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	origStop := awgStop
	awgStop = func(*AmneziaWgRunner) error {
		entered <- struct{}{}
		<-release
		return nil
	}
	awgGlobalMu.Lock()
	activeAwgRunner = &AmneziaWgRunner{running: true}
	awgGlobalMu.Unlock()
	t.Cleanup(func() {
		awgStop = origStop
		awgGlobalMu.Lock()
		activeAwgRunner = nil
		awgGlobalMu.Unlock()
		waitAbandonedZero(t)
	})

	var err error
	within(t, 2*time.Second, "StopAmneziaWgWithTimeout", func() { err = StopAmneziaWgWithTimeout(100) })
	if !errors.Is(err, ErrStopTimedOut) || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v, want ErrStopTimedOut", err)
	}
	waitSignal(t, entered, "runner Stop")
	if IsAmneziaWgRunning() {
		t.Fatal("runner must be detached")
	}
	if got := AbandonedInstances(); got != 1 {
		t.Fatalf("AbandonedInstances() = %d, want 1", got)
	}
	close(release)
	waitAbandonedZero(t)
}

func TestStopAmneziaWgWithTimeoutCompletes(t *testing.T) {
	origStop := awgStop
	awgStop = func(*AmneziaWgRunner) error { return errors.New("awg boom") }
	awgGlobalMu.Lock()
	activeAwgRunner = &AmneziaWgRunner{running: true}
	awgGlobalMu.Unlock()
	t.Cleanup(func() { awgStop = origStop })
	if err := StopAmneziaWgWithTimeout(1000); err == nil || err.Error() != "awg boom" {
		t.Fatalf("err = %v", err)
	}
	if err := StopAmneziaWgWithTimeout(1000); err != nil {
		t.Fatalf("second stop = %v, want nil", err)
	}
}
