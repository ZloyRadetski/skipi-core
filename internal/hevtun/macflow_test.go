// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package hevtun

import (
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

const runDir = "/Users/test/SKIPI/run"

type macHarness struct {
	fs        *fakeFS
	launches  [][]string
	launchErr error
	onLaunch  func()
	alive     map[int64]bool
	clock     time.Time
	onSleep   func()
	tun       *macTunnel
}

func newHarness() *macHarness {
	h := &macHarness{fs: newFakeFS(), alive: map[int64]bool{7777: true}, clock: time.Unix(1000, 0)}
	h.onLaunch = func() { h.fs.put(runDir+"/tun-ready", "7777") }
	h.tun = newMacTunnel(macEnv{
		FS: h.fs,
		Launch: func(cmd []string) error {
			h.launches = append(h.launches, cmd)
			if h.launchErr != nil {
				return h.launchErr
			}
			h.onLaunch()
			return nil
		},
		IsAlive: func(pid int64) bool { return h.alive[pid] },
		Now:     func() time.Time { return h.clock },
		Sleep: func(d time.Duration) {
			h.clock = h.clock.Add(d)
			if h.onSleep != nil {
				h.onSleep()
			}
		},
		AppPid:       4242,
		UserUid:      501,
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

func TestStartAsksForRightsRunsTheSupervisorAndWaitsUntilReady(t *testing.T) {
	h := newHarness()
	if err := h.start(t); err != nil {
		t.Fatal(err)
	}
	if len(h.launches) != 1 || h.launches[0][0] != "/usr/bin/osascript" {
		t.Fatalf("launches = %v", h.launches)
	}
	if !strings.Contains(h.fs.files[runDir+"/tun-hev.yaml"], "mtu: 1400") {
		t.Fatal("hev must read the generated config")
	}
	m := regexp.MustCompile(`do shell script "echo ([A-Za-z0-9+/=]+) `).FindStringSubmatch(h.launches[0][2])
	if m == nil {
		t.Fatal(h.launches[0])
	}
	raw, _ := base64.StdEncoding.DecodeString(m[1])
	script := string(raw)
	wantIn(t, script, "route -n add -net '0.0.0.0/1'")
	wantIn(t, script, "APP_PID=4242")
	wantIn(t, script, "chown 501")
	wantIn(t, script, "'"+runDir+"/tun-hev.yaml'")
	wantIn(t, script, "IFACE='utun9'")
	wantIn(t, script, "'172.19.0.1' '172.19.0.1' mtu 1400 up")
	if !h.tun.running() {
		t.Fatal("running must be true once ready")
	}
}

func TestFilesAndDirectoryAreRestrictedToTheUser(t *testing.T) {
	h := newHarness()
	if err := h.start(t); err != nil {
		t.Fatal(err)
	}
	if h.fs.dirs[runDir] != 0o700 {
		t.Fatalf("run directory mode = %o", h.fs.dirs[runDir])
	}
	if h.fs.modes[runDir+"/tun-hev.yaml"] != 0o600 {
		t.Fatalf("config mode = %o", h.fs.modes[runDir+"/tun-hev.yaml"])
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
	h.onLaunch = func() { h.fs.put(runDir+"/tun-error", "The tunnel interface did not appear\n") }
	err := h.start(t)
	if err == nil || err.Error() != "The tunnel interface did not appear" {
		t.Fatalf("err = %v", err)
	}
}

func TestBlankSupervisorErrorGetsADefaultText(t *testing.T) {
	h := newHarness()
	h.onLaunch = func() { h.fs.put(runDir+"/tun-error", " \n") }
	err := h.start(t)
	if err == nil || err.Error() != "The tunnel could not be started" {
		t.Fatalf("err = %v", err)
	}
}

func TestSupervisorThatNeverBecomesReadyTimesOutAndAsksForACleanup(t *testing.T) {
	h := newHarness()
	h.onLaunch = func() {}
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
	h.onLaunch = func() {}
	if err := h.tun.start("y", macOpts()); err != nil {
		t.Fatal(err)
	}
	if err := h.tun.waitReady(300 * time.Millisecond); !errors.Is(err, ErrReadyTimeout) {
		t.Fatalf("err = %v, want ErrReadyTimeout", err)
	}
	if h.fs.Exists(runDir + "/tun-stop") {
		t.Fatal("a slice timeout is not a failure; no stop file yet")
	}
	h.fs.put(runDir+"/tun-ready", "7777")
	if err := h.tun.waitReady(300 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
}

func TestWaitReadyBeforeStartFails(t *testing.T) {
	if err := newHarness().tun.waitReady(time.Millisecond); err == nil {
		t.Fatal("expected an error")
	}
}

func TestStopAsksThroughTheStopFileAndWaitsForTheSupervisorToClean(t *testing.T) {
	h := newHarness()
	if err := h.start(t); err != nil {
		t.Fatal(err)
	}
	// The supervisor, on seeing the stop file, removes its ready marker as its last cleanup step.
	h.onSleep = func() {
		if h.fs.Exists(runDir + "/tun-stop") {
			_ = h.fs.Remove(runDir + "/tun-ready")
		}
	}
	if err := h.tun.stop(); err != nil {
		t.Fatal(err)
	}
	if h.fs.Exists(runDir + "/tun-ready") {
		t.Fatal("ready marker must be gone")
	}
	if h.tun.running() {
		t.Fatal("must not be running after stop")
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
	h.fs.put(runDir+"/tun-ready", "not a pid")
	if h.tun.running() {
		t.Fatal("an unreadable pid means not running")
	}
	h.fs.put(runDir+"/tun-ready", " 7777\n")
	if !h.tun.running() {
		t.Fatal("a pid with whitespace around it counts")
	}
}

func TestLeftoversOfAnEarlierSessionAreClearedBeforeStarting(t *testing.T) {
	h := newHarness()
	h.fs.put(runDir+"/tun-error", "old failure")
	h.fs.put(runDir+"/tun-stop", "")
	h.fs.put(runDir+"/tun-ready", "1")
	h.onLaunch = func() {
		for _, f := range []string{"tun-error", "tun-stop"} {
			if h.fs.Exists(runDir + "/" + f) {
				t.Errorf("%s survived into the launch", f)
			}
		}
		h.fs.put(runDir+"/tun-ready", "7777")
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
	if len(h.launches) != 0 {
		t.Fatalf("the prompt must not be shown for an invalid plan: %v", h.launches)
	}
}
