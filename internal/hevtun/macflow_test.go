// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package hevtun

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// Ported from DesktopMacTunTest.kt (the tunnel session part). The flow runs against a fake file
// system, a fake launcher and a fake clock, so it is tested on every host.

type fakeFS struct {
	mu    sync.Mutex
	files map[string]string
	modes map[string]os.FileMode
	dirs  map[string]os.FileMode
}

func newFakeFS() *fakeFS {
	return &fakeFS{files: map[string]string{}, modes: map[string]os.FileMode{}, dirs: map[string]os.FileMode{}}
}

func (f *fakeFS) MkdirAll(d string, p os.FileMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.dirs[d]; !ok {
		f.dirs[d] = p
	}
	return nil
}
func (f *fakeFS) Chmod(path string, p os.FileMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.dirs[path]; ok {
		f.dirs[path] = p
	} else {
		f.modes[path] = p
	}
	return nil
}
func (f *fakeFS) Remove(path string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.files, path)
	delete(f.modes, path)
	return nil
}
func (f *fakeFS) WriteFile(path string, data []byte, p os.FileMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[path] = string(data)
	f.modes[path] = p
	return nil
}
func (f *fakeFS) ReadFile(path string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return []byte(s), nil
}
func (f *fakeFS) Exists(path string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.files[path]
	return ok
}
func (f *fakeFS) put(path, s string) { _ = f.WriteFile(path, []byte(s), 0o600) }

const (
	runDir   = "/Users/test/SKIPI/run"
	stateDir = "/var/run/skipi-hev.501"
	token    = "00112233445566778899aabbccddeeff"
	hevHash  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

type macHarness struct {
	mu        sync.Mutex
	fs        *fakeFS
	launches  [][]string
	launchErr error
	// onLaunch runs while the prompt is "up"; ctx is the launch context.
	onLaunch func(ctx context.Context) error
	hashErr  error
	alive    map[int64]bool
	clock    time.Time
	onSleep  func()
	tun      *macTunnel
}

func newHarness() *macHarness {
	h := &macHarness{fs: newFakeFS(), alive: map[int64]bool{7777: true}, clock: time.Unix(1000, 0)}
	h.onLaunch = func(context.Context) error { h.fs.put(stateDir+"/tun-ready", "7777 "+token+"\n"); return nil }
	h.tun = newMacTunnel(macEnv{
		FS: h.fs,
		Launch: func(ctx context.Context, cmd []string) error {
			h.mu.Lock()
			h.launches = append(h.launches, cmd)
			err := h.launchErr
			h.mu.Unlock()
			if err != nil {
				return err
			}
			return h.onLaunch(ctx)
		},
		HashFile: func(p string) (string, error) { return hevHash, h.hashErr },
		NewToken: func() string { return token },
		IsAlive:  func(pid int64) bool { h.mu.Lock(); defer h.mu.Unlock(); return h.alive[pid] },
		Now:      func() time.Time { h.mu.Lock(); defer h.mu.Unlock(); return h.clock },
		Sleep: func(d time.Duration) {
			h.mu.Lock()
			h.clock = h.clock.Add(d)
			f := h.onSleep
			h.mu.Unlock()
			if f != nil {
				f()
			}
		},
		AppPid:       4242,
		StateDir:     stateDir,
		ReadyTimeout: 5 * time.Second,
		StopTimeout:  8 * time.Second,
	})
	return h
}

func macOpts() Options {
	return Options{
		Executable:   "/Applications/SKIPI.app/Contents/Resources/hev/hev-socks5-tunnel",
		RunDirectory: runDir,
		MacInterface: &MacInterface{Name: "utun9", MTU: 1400, Addresses: []string{"172.19.0.1/30"}, Routes: []string{"0.0.0.0/1", "128.0.0.0/1"}},
	}
}

func (h *macHarness) start(t *testing.T) error {
	t.Helper()
	if err := h.tun.start("tunnel:\n  mtu: 1400\n", macOpts()); err != nil {
		return err
	}
	return h.tun.waitReady(time.Second)
}

func launchedScript(t *testing.T, cmd []string) string {
	t.Helper()
	m := regexp.MustCompile(`do shell script "echo ([A-Za-z0-9+/=]+) `).FindStringSubmatch(cmd[2])
	if m == nil {
		t.Fatal(cmd)
	}
	raw, _ := base64.StdEncoding.DecodeString(m[1])
	return string(raw)
}

func TestStartAsksForRightsRunsTheSupervisorAndWaitsUntilReady(t *testing.T) {
	h := newHarness()
	if err := h.start(t); err != nil {
		t.Fatal(err)
	}
	if len(h.launches) != 1 || h.launches[0][0] != "/usr/bin/osascript" {
		t.Fatalf("launches = %v", h.launches)
	}
	script := launchedScript(t, h.launches[0])
	wantIn(t, script, "route -n add -net '0.0.0.0/1'")
	wantIn(t, script, "APP_PID=4242")
	wantIn(t, script, "STATE='"+stateDir+"'")
	wantIn(t, script, "STOP='"+runDir+"/tun-stop'")
	wantIn(t, script, "TOKEN='"+token+"'")
	wantIn(t, script, "HEV_SHA='"+hevHash+"'")
	wantIn(t, script, base64.StdEncoding.EncodeToString([]byte("tunnel:\n  mtu: 1400\n")))
	wantIn(t, script, "IFACE='utun9'")
	wantIn(t, script, "'172.19.0.1' '172.19.0.1' mtu 1400 up")
	if !h.tun.running() {
		t.Fatal("running must be true once ready")
	}
}

// C2/C3/C7: the config is no longer written where the user can swap or read it later.
func TestNoConfigIsWrittenIntoTheUsersDirectory(t *testing.T) {
	h := newHarness()
	h.fs.put(runDir+"/tun-hev.yaml", "password: left by an older version")
	if err := h.start(t); err != nil {
		t.Fatal(err)
	}
	for path := range h.fs.files {
		if strings.HasPrefix(path, runDir) {
			t.Errorf("%s is in the user's directory", path)
		}
	}
	if h.fs.dirs[runDir] != 0o700 {
		t.Fatalf("run directory mode = %o", h.fs.dirs[runDir])
	}
}

func TestAnExecutableThatCannotBeHashedIsNotStarted(t *testing.T) {
	h := newHarness()
	h.hashErr = errors.New("no such file")
	if err := h.start(t); err == nil || !strings.Contains(err.Error(), "no such file") {
		t.Fatalf("err = %v", err)
	}
	if len(h.launches) != 0 {
		t.Fatal("the prompt must not be shown")
	}
}

func TestCancellingThePasswordPromptIsReportedInPlainWords(t *testing.T) {
	h := newHarness()
	h.launchErr = errors.New("execution error: User canceled. (-128)")
	err := h.start(t)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "administrator") {
		t.Fatalf("err = %v", err)
	}
	if h.tun.running() {
		t.Fatal("must not be running")
	}
}

func TestOtherLaunchFailureIsDescribed(t *testing.T) {
	h := newHarness()
	h.launchErr = errors.New("osascript: command not found")
	err := h.start(t)
	if err == nil || err.Error() != "Could not start the privileged tunnel: osascript: command not found" {
		t.Fatalf("err = %v", err)
	}
}

func TestSupervisorErrorFailsTheStartWithItsText(t *testing.T) {
	h := newHarness()
	h.onLaunch = func(context.Context) error {
		h.fs.put(stateDir+"/tun-error", token+"\nThe tunnel interface did not appear\n")
		return nil
	}
	err := h.start(t)
	if err == nil || err.Error() != "The tunnel interface did not appear" {
		t.Fatalf("err = %v", err)
	}
}

func TestBlankSupervisorErrorGetsADefaultText(t *testing.T) {
	h := newHarness()
	h.onLaunch = func(context.Context) error { h.fs.put(stateDir+"/tun-error", token+"\n \n"); return nil }
	err := h.start(t)
	if err == nil || err.Error() != "The tunnel could not be started" {
		t.Fatalf("err = %v", err)
	}
}

// Markers of another session (an older supervisor, a crash) carry another token and are ignored.
func TestMarkersOfAnotherSessionAreIgnored(t *testing.T) {
	h := newHarness()
	h.onLaunch = func(context.Context) error {
		h.fs.put(stateDir+"/tun-error", "ffffffffffffffffffffffffffffffff\nold failure")
		h.fs.put(stateDir+"/tun-ready", "7777 ffffffffffffffffffffffffffffffff")
		return nil
	}
	if err := h.tun.start("y", macOpts()); err != nil {
		t.Fatal(err)
	}
	if err := h.tun.waitReady(300 * time.Millisecond); !errors.Is(err, ErrReadyTimeout) {
		t.Fatalf("err = %v, want ErrReadyTimeout", err)
	}
	if h.tun.running() {
		t.Fatal("a ready marker of another session is not this tunnel")
	}
}

func TestSupervisorThatNeverBecomesReadyTimesOutAndAsksForACleanup(t *testing.T) {
	h := newHarness()
	h.onLaunch = func(context.Context) error { return nil }
	begin := h.clock
	if err := h.tun.start("y", macOpts()); err != nil {
		t.Fatal(err)
	}
	err := h.tun.waitReady(time.Minute)
	if err == nil || !strings.Contains(err.Error(), "did not become ready in time") {
		t.Fatalf("err = %v", err)
	}
	if h.clock.Sub(begin) < 5*time.Second {
		t.Fatalf("it waited only %v of the 5 s timeout", h.clock.Sub(begin))
	}
	if !h.fs.Exists(runDir + "/tun-stop") {
		t.Fatal("the supervisor must be asked to clean up what it did get done")
	}
}

func TestWaitReadySliceShorterThanTheDeadlineReportsReadyTimeout(t *testing.T) {
	h := newHarness()
	h.onLaunch = func(context.Context) error { return nil }
	if err := h.tun.start("y", macOpts()); err != nil {
		t.Fatal(err)
	}
	if err := h.tun.waitReady(300 * time.Millisecond); !errors.Is(err, ErrReadyTimeout) {
		t.Fatalf("err = %v, want ErrReadyTimeout", err)
	}
	if h.fs.Exists(runDir + "/tun-stop") {
		t.Fatal("a slice timeout is not a failure; no stop file yet")
	}
	h.fs.put(stateDir+"/tun-ready", "7777 "+token)
	if err := h.tun.waitReady(300 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
}

func TestWaitReadyBeforeStartFails(t *testing.T) {
	if err := newHarness().tun.waitReady(time.Millisecond); err == nil {
		t.Fatal("expected an error")
	}
}

// supervisorObeysStop: on seeing the stop file the supervisor cleans up and writes its exit marker last.
func (h *macHarness) supervisorObeysStop() {
	h.onSleep = func() {
		if h.fs.Exists(runDir + "/tun-stop") {
			_ = h.fs.Remove(stateDir + "/tun-ready")
			h.fs.put(stateDir+"/tun-exit", token+"\n")
		}
	}
}

func TestStopAsksThroughTheStopFileAndWaitsForTheSupervisorToExit(t *testing.T) {
	h := newHarness()
	if err := h.start(t); err != nil {
		t.Fatal(err)
	}
	h.supervisorObeysStop()
	if err := h.tun.stop(); err != nil {
		t.Fatal(err)
	}
	if !h.fs.Exists(stateDir + "/tun-exit") {
		t.Fatal("stop must wait for the supervisor's exit marker")
	}
	if h.tun.running() {
		t.Fatal("must not be running after stop")
	}
}

// H2: a supervisor that was launched but never got ready is still asked to stop and waited for.
func TestStopOfASupervisorThatIsNotReadyYetStillWaitsForIt(t *testing.T) {
	h := newHarness()
	h.onLaunch = func(context.Context) error { return nil }
	if err := h.tun.start("y", macOpts()); err != nil {
		t.Fatal(err)
	}
	h.supervisorObeysStop()
	if err := h.tun.stop(); err != nil {
		t.Fatal(err)
	}
	if !h.fs.Exists(runDir + "/tun-stop") {
		t.Fatal("the stop file must be written even before ready")
	}
	if !h.fs.Exists(stateDir + "/tun-exit") {
		t.Fatal("stop must wait for the supervisor to exit")
	}
}

// H2: Stop while the administrator prompt is up ends the prompt and leaves a stop request, so a
// supervisor that still gets started exits before it installs a route.
func TestStopDuringThePasswordPromptCancelsItAndLeavesAStopRequest(t *testing.T) {
	h := newHarness()
	prompting := make(chan struct{})
	h.onLaunch = func(ctx context.Context) error {
		close(prompting)
		<-ctx.Done()
		return errors.New("osascript: killed")
	}
	startErr := make(chan error, 1)
	go func() { startErr <- h.tun.start("y", macOpts()) }()
	<-prompting
	stopped := make(chan error, 1)
	go func() { stopped <- h.tun.stop() }()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stop waited for the prompt instead of cancelling it")
	}
	select {
	case err := <-startErr:
		if err == nil || !strings.Contains(err.Error(), "cancel") {
			t.Fatalf("start err = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("start did not return")
	}
	if !h.fs.Exists(runDir + "/tun-stop") {
		t.Fatal("the stop request must stay for a supervisor that still gets started")
	}
	if h.tun.running() {
		t.Fatal("must not be running")
	}
}

func TestStopThatTheSupervisorNeverAnswersTimesOut(t *testing.T) {
	h := newHarness()
	if err := h.start(t); err != nil {
		t.Fatal(err)
	}
	begin := h.clock
	err := h.tun.stop()
	if err == nil || err.Error() != "The tunnel did not stop in time; its routes may still be installed" {
		t.Fatalf("err = %v", err)
	}
	if h.clock.Sub(begin) < 8*time.Second {
		t.Fatalf("waited only %v", h.clock.Sub(begin))
	}
}

func TestStopOfASupervisorThatDiedIsImmediate(t *testing.T) {
	h := newHarness()
	if err := h.start(t); err != nil {
		t.Fatal(err)
	}
	h.alive = map[int64]bool{}
	begin := h.clock
	if err := h.tun.stop(); err != nil {
		t.Fatal(err)
	}
	if h.clock.Sub(begin) > time.Second {
		t.Fatalf("waited %v for a dead supervisor", h.clock.Sub(begin))
	}
}

func TestTunnelThatWasNeverStartedStopsQuietly(t *testing.T) {
	h := newHarness()
	if err := h.tun.stop(); err != nil {
		t.Fatal(err)
	}
	if h.tun.running() {
		t.Fatal("must not be running")
	}
	if len(h.fs.files) != 0 {
		t.Fatalf("no file may be written: %v", h.fs.files)
	}
}

func TestNotRunningOnceTheSupervisorProcessIsGone(t *testing.T) {
	h := newHarness()
	if err := h.start(t); err != nil {
		t.Fatal(err)
	}
	h.alive = map[int64]bool{}
	if h.tun.running() {
		t.Fatal("a dead supervisor pid means not running")
	}
}

func TestNotRunningWhileAStopIsPendingOrTheReadyFileIsGarbage(t *testing.T) {
	h := newHarness()
	if err := h.start(t); err != nil {
		t.Fatal(err)
	}
	h.fs.put(runDir+"/tun-stop", "")
	if h.tun.running() {
		t.Fatal("a pending stop file means not running")
	}
	_ = h.fs.Remove(runDir + "/tun-stop")
	h.fs.put(stateDir+"/tun-ready", "not a pid "+token)
	if h.tun.running() {
		t.Fatal("an unreadable pid means not running")
	}
	h.fs.put(stateDir+"/tun-ready", " 7777 "+token+"\n")
	if !h.tun.running() {
		t.Fatal("a pid with whitespace around it counts")
	}
}

func TestLeftoversOfAnEarlierSessionAreClearedBeforeStarting(t *testing.T) {
	h := newHarness()
	for _, f := range []string{"tun-error", "tun-stop", "tun-ready", "tun-hev.yaml"} {
		h.fs.put(runDir+"/"+f, "old")
	}
	h.onLaunch = func(context.Context) error {
		for _, f := range []string{"tun-error", "tun-stop", "tun-ready", "tun-hev.yaml"} {
			if h.fs.Exists(runDir + "/" + f) {
				t.Errorf("%s survived into the launch", f)
			}
		}
		h.fs.put(stateDir+"/tun-ready", "7777 "+token)
		return nil
	}
	if err := h.start(t); err != nil {
		t.Fatal(err)
	}
}

func TestStartRejectsBadInputBeforeAskingForRights(t *testing.T) {
	h := newHarness()
	if err := h.tun.start("", macOpts()); err == nil {
		t.Error("empty config accepted")
	}
	o := macOpts()
	o.MacInterface = nil
	if err := h.tun.start("y", o); err == nil {
		t.Error("missing macInterface accepted")
	}
	o = macOpts()
	o.MacInterface.Routes = []string{"default"}
	if err := h.tun.start("y", o); err == nil {
		t.Error("bad route accepted")
	}
	o = macOpts()
	o.MacInterface.Addresses = []string{"fc00::1/64"}
	if err := h.tun.start("y", o); err == nil {
		t.Error("no IPv4 address accepted")
	}
	o = macOpts()
	o.Executable = "hev-socks5-tunnel"
	if err := h.tun.start("y", o); err == nil {
		t.Error("relative executable accepted")
	}
	if len(h.launches) != 0 {
		t.Fatalf("the prompt must not be shown for an invalid plan: %v", h.launches)
	}
}
