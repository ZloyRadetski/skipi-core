// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"errors"
	"fmt"
	"github.com/xtls/xray-core/core"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type stateEvent struct {
	state  int
	detail string
}

type recordingListener struct {
	mu     sync.Mutex
	events []stateEvent
	onCall func(state int)
}

func (l *recordingListener) OnStateChanged(state int, detail string) {
	l.mu.Lock()
	l.events = append(l.events, stateEvent{state, detail})
	cb := l.onCall
	l.mu.Unlock()
	if cb != nil {
		cb(state)
	}
}

func (l *recordingListener) snapshot() []stateEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]stateEvent(nil), l.events...)
}

func (l *recordingListener) states() []int {
	var out []int
	for _, e := range l.snapshot() {
		out = append(out, e.state)
	}
	return out
}

// fakeAwg replaces the AmneziaWG runner: it registers a fake active runner and opens the SOCKS
// listener after listenDelay (never when negative).
type fakeAwg struct {
	started atomic.Int32
	stops   atomic.Int32
	mu      sync.Mutex
	ln      net.Listener
}

func installFakeAwg(t *testing.T, listenDelay time.Duration) *fakeAwg {
	t.Helper()
	f := &fakeAwg{}
	origStart, origStop := startAmneziaWgFn, awgStop
	startAmneziaWgFn = func(_ string, port int) error {
		return f.start(port, listenDelay)
	}
	awgStop = func(*AmneziaWgRunner) error {
		f.stops.Add(1)
		f.mu.Lock()
		if f.ln != nil {
			_ = f.ln.Close()
			f.ln = nil
		}
		f.mu.Unlock()
		return nil
	}
	t.Cleanup(func() {
		startAmneziaWgFn, awgStop = origStart, origStop
		awgGlobalMu.Lock()
		activeAwgRunner = nil
		awgGlobalMu.Unlock()
		f.mu.Lock()
		if f.ln != nil {
			_ = f.ln.Close()
		}
		f.mu.Unlock()
	})
	return f
}

func (f *fakeAwg) start(port int, delay time.Duration) error {
	f.started.Add(1)
	awgGlobalMu.Lock()
	activeAwgRunner = &AmneziaWgRunner{running: true, socksPort: port}
	awgGlobalMu.Unlock()
	if delay >= 0 {
		go func() {
			time.Sleep(delay)
			ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
			if err != nil {
				return
			}
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					_ = c.Close()
				}
			}()
			f.mu.Lock()
			f.ln = ln
			f.mu.Unlock()
		}()
	}
	return nil
}

func buildPlan(t *testing.T, port int, withAwg bool) string {
	t.Helper()
	awg := "null"
	if withAwg {
		awg = fmt.Sprintf(`{"config":"{}","socksPort":%d}`, port)
	}
	xray := strings.NewReplacer(`"`, `\"`, "\n", `\n`, "\t", `\t`).Replace(stopTestConfig)
	return fmt.Sprintf(`{"xrayConfig":"%s","amneziaWg":%s,"connectionLog":true,"future":1}`, xray, awg)
}

func TestParseSessionPlan(t *testing.T) {
	cases := []struct {
		name, plan string
		wantErr    string
	}{
		{"missing xray", `{"amneziaWg":null}`, "xrayConfig"},
		{"blank xray", `{"xrayConfig":"  "}`, "xrayConfig"},
		{"not json", `nope`, "plan"},
		{"awg zero port", `{"xrayConfig":"{}","amneziaWg":{"config":"{}","socksPort":0}}`, "socksPort"},
		{"awg blank config", `{"xrayConfig":"{}","amneziaWg":{"config":" ","socksPort":1080}}`, "config"},
		{"unknown fields ignored", `{"xrayConfig":"{}","x":[1],"amneziaWg":{"config":"{}","socksPort":1080,"y":2}}`, ""},
		{"awg null", `{"xrayConfig":"{}","amneziaWg":null}`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := parseSessionPlan(tc.plan)
			if tc.wantErr == "" {
				if err != nil || p == nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestSessionConstantsAreStable(t *testing.T) {
	if SessionIdle != 0 || SessionStarting != 1 || SessionRunning != 2 || SessionStopping != 3 {
		t.Fatal("session state values are part of the host contract")
	}
}

func TestStartSessionWaitsForAwgListenerInGo(t *testing.T) {
	installFakeCore(t, newFakeCoreInstance())
	awg := installFakeAwg(t, 300*time.Millisecond)
	port := reserveLocalPort(t)
	c := NewCoreController(&dummyCallbackHandler{})
	l := &recordingListener{}
	c.SetStateListener(l)

	begin := time.Now()
	if err := c.StartSession(buildPlan(t, port, true), 0); err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	if time.Since(begin) < 250*time.Millisecond {
		t.Fatal("StartSession returned before the SOCKS listener was ready")
	}
	if c.State() != SessionRunning || !c.IsRunning() {
		t.Fatalf("State = %d, want Running", c.State())
	}
	if got := l.states(); fmt.Sprint(got) != "[1 2]" {
		t.Fatalf("listener states = %v, want [1 2]", got)
	}
	if awg.started.Load() != 1 {
		t.Fatal("AWG must be started once")
	}
	if err := c.StopLoop(); err != nil {
		t.Fatal(err)
	}
}

func TestStartSessionWithoutAwgNeverTouchesIt(t *testing.T) {
	installFakeCore(t, newFakeCoreInstance())
	awg := installFakeAwg(t, 0)
	c := NewCoreController(nil)
	if err := c.StartSession(buildPlan(t, 0, false), 0); err != nil {
		t.Fatal(err)
	}
	if err := c.StopLoop(); err != nil {
		t.Fatal(err)
	}
	if awg.started.Load() != 0 || awg.stops.Load() != 0 {
		t.Fatal("a session without amneziaWg must not touch AmneziaWG")
	}
}

func TestStartSessionAwgNeverReadyFailsWithinDeadline(t *testing.T) {
	installFakeCore(t, newFakeCoreInstance())
	awg := installFakeAwg(t, -1)
	orig := awgReadyTimeout
	awgReadyTimeout = 400 * time.Millisecond
	t.Cleanup(func() { awgReadyTimeout = orig })
	port := reserveLocalPort(t)
	c := NewCoreController(nil)
	l := &recordingListener{}
	c.SetStateListener(l)

	begin := time.Now()
	err := c.StartSession(buildPlan(t, port, true), 0)
	if err == nil {
		t.Fatal("expected a readiness error")
	}
	if el := time.Since(begin); el > 2*time.Second {
		t.Fatalf("took %v, want about the deadline", el)
	}
	msg := err.Error()
	if !strings.Contains(msg, fmt.Sprint(port)) || !strings.Contains(msg, "timed out") {
		t.Fatalf("error %q must mention the port and the timeout", msg)
	}
	if awg.stops.Load() != 1 {
		t.Fatalf("AWG stops = %d, want 1", awg.stops.Load())
	}
	if c.State() != SessionIdle || c.IsRunning() {
		t.Fatalf("State = %d, want Idle", c.State())
	}
	ev := l.snapshot()
	if len(ev) != 2 || ev[0].state != SessionStarting || ev[1].state != SessionIdle || ev[1].detail != msg {
		t.Fatalf("listener events = %+v", ev)
	}
}

func TestStartSessionXrayFailureStopsAwg(t *testing.T) {
	installFakeCore(t, newFakeCoreInstance())
	awg := installFakeAwg(t, 0)
	boom := errors.New("xray boom")
	startCoreInstance = func(coreInstance) error { return boom }
	port := reserveLocalPort(t)
	c := NewCoreController(nil)
	l := &recordingListener{}
	c.SetStateListener(l)

	err := c.StartSession(buildPlan(t, port, true), 0)
	if err == nil || !strings.Contains(err.Error(), "xray boom") {
		t.Fatalf("error = %v, want the xray error", err)
	}
	if awg.stops.Load() != 1 {
		t.Fatalf("AWG stops = %d, want 1", awg.stops.Load())
	}
	ev := l.snapshot()
	if len(ev) != 2 || ev[1].state != SessionIdle || !strings.Contains(ev[1].detail, "xray boom") {
		t.Fatalf("listener events = %+v", ev)
	}
}

func TestStopLoopAfterSessionStopsAwgButNotAfterPlainStartLoop(t *testing.T) {
	installFakeCore(t, newFakeCoreInstance(), newFakeCoreInstance())
	awg := installFakeAwg(t, 0)
	port := reserveLocalPort(t)
	c := NewCoreController(nil)

	if err := c.StartSession(buildPlan(t, port, true), 0); err != nil {
		t.Fatal(err)
	}
	if err := c.StopLoop(); err != nil {
		t.Fatal(err)
	}
	if awg.stops.Load() != 1 {
		t.Fatalf("AWG stops after session StopLoop = %d, want 1", awg.stops.Load())
	}

	// Plain StartLoop with AWG started on its own (Desktop measurement code).
	if err := startAmneziaWgFn("{}", port); err != nil {
		t.Fatal(err)
	}
	if err := c.StartLoop(stopTestConfig, 0); err != nil {
		t.Fatal(err)
	}
	if err := c.StopLoop(); err != nil {
		t.Fatal(err)
	}
	if awg.stops.Load() != 1 {
		t.Fatalf("plain StopLoop touched AWG: stops = %d", awg.stops.Load())
	}
	if err := StopAmneziaWg(); err != nil {
		t.Fatal(err)
	}
	if awg.stops.Load() != 2 {
		t.Fatal("explicit StopAmneziaWg must still stop it")
	}
}

func TestSessionStopTimedOutAwgIsCountedAbandoned(t *testing.T) {
	installFakeCore(t, newFakeCoreInstance())
	installFakeAwg(t, 0)
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	awgStop = func(*AmneziaWgRunner) error {
		entered <- struct{}{}
		<-release
		return nil
	}
	port := reserveLocalPort(t)
	c := NewCoreController(nil)
	if err := c.StartSession(buildPlan(t, port, true), 0); err != nil {
		t.Fatal(err)
	}
	err := c.StopLoopWithTimeout(100)
	if !errors.Is(err, ErrStopTimedOut) {
		t.Fatalf("err = %v, want ErrStopTimedOut", err)
	}
	<-entered
	if AbandonedInstances() != 1 {
		t.Fatalf("abandoned = %d, want 1", AbandonedInstances())
	}
	close(release)
	waitAbandonedZero(t)
}

func TestForceStopDuringAwgReadinessWaitAbortsPromptly(t *testing.T) {
	installFakeCore(t, newFakeCoreInstance())
	awg := installFakeAwg(t, -1)
	orig := awgReadyTimeout
	awgReadyTimeout = 10 * time.Second
	t.Cleanup(func() { awgReadyTimeout = orig })
	port := reserveLocalPort(t)
	c := NewCoreController(nil)

	done := make(chan error, 1)
	go func() { done <- c.StartSession(buildPlan(t, port, true), 0) }()
	for i := 0; awg.started.Load() == 0; i++ {
		if i > 500 {
			t.Fatal("AWG never started")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)

	begin := time.Now()
	_ = c.ForceStop()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("aborted StartSession must return an error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("StartSession did not abort")
	}
	if el := time.Since(begin); el > 2*time.Second {
		t.Fatalf("abort took %v", el)
	}
	if awg.stops.Load() < 1 {
		t.Fatal("AWG must be stopped")
	}
	if c.State() != SessionIdle {
		t.Fatalf("State = %d, want Idle", c.State())
	}
}

func TestStateAnswersWhileStopHangsAndListenerSeesStopping(t *testing.T) {
	fake := newFakeCoreInstance()
	fake.closeRelease = make(chan struct{})
	installFakeCore(t, fake)
	c := NewCoreController(nil)
	l := &recordingListener{}
	c.SetStateListener(l)
	if err := c.StartLoop(stopTestConfig, 0); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- c.StopLoopWithTimeout(30000) }()
	<-fake.closeEntered

	got := make(chan int, 1)
	go func() { got <- c.State() }()
	select {
	case s := <-got:
		if s != SessionStopping {
			t.Fatalf("State = %d, want Stopping", s)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("State blocked on a hanging stop")
	}
	close(fake.closeRelease)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if ev := l.snapshot(); fmt.Sprint(l.states()) != "[1 2 3 0]" || ev[3].detail != "" {
		t.Fatalf("events = %+v", ev)
	}
}

func TestStateListenerRunsOutsideTheLockAndMayPanic(t *testing.T) {
	installFakeCore(t, newFakeCoreInstance())
	c := NewCoreController(nil)
	l := &recordingListener{}
	var calls atomic.Int32
	l.onCall = func(state int) {
		_ = c.State() // would deadlock if the listener ran under c.mu
		calls.Add(1)
		if state == SessionStarting {
			panic("listener bug")
		}
	}
	c.SetStateListener(l)
	if err := c.StartLoop(stopTestConfig, 0); err != nil {
		t.Fatalf("a panicking listener broke StartLoop: %v", err)
	}
	if c.State() != SessionRunning {
		t.Fatalf("State = %d", c.State())
	}
	c.SetStateListener(nil)
	if err := c.StopLoop(); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("listener calls = %d, want 2 (a cleared listener is silent)", calls.Load())
	}
}

func TestStartSessionRejectsBadPlanWithoutStateChange(t *testing.T) {
	c := NewCoreController(nil)
	l := &recordingListener{}
	c.SetStateListener(l)
	if err := c.StartSession(`{"amneziaWg":null}`, 0); err == nil {
		t.Fatal("expected an error")
	}
	if len(l.snapshot()) != 0 || c.State() != SessionIdle {
		t.Fatal("a rejected plan must not change state")
	}
}

// Perf 6: the Xray config is parsed while AmneziaWG comes up, not after it.
func TestXrayConfigIsParsedWhileAwgStarts(t *testing.T) {
	installFakeAwg(t, 0)
	installFakeCore(t, newFakeCoreInstance())
	parsing := make(chan struct{})
	origLoad, origAwg := loadXrayConfig, startAmneziaWgFn
	loadXrayConfig = func(text string) (*core.Config, error) {
		close(parsing)
		return origLoad(text)
	}
	overlapped := false
	startAmneziaWgFn = func(cfg string, port int) error {
		select {
		case <-parsing:
			overlapped = true
		case <-time.After(2 * time.Second):
		}
		return origAwg(cfg, port)
	}
	t.Cleanup(func() { loadXrayConfig, startAmneziaWgFn = origLoad, origAwg })

	c := NewCoreController(nil)
	if err := c.StartSession(buildPlan(t, reserveLocalPort(t), true), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.StopLoop() })
	if !overlapped {
		t.Fatal("the Xray config was not parsed while AmneziaWG started")
	}
}
