// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build windows

package hevtun

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	fakeDir  string
	fakeExe  string
	fakeOnce sync.Once
	fakeErr  error
)

func TestMain(m *testing.M) {
	// Built before any test redirects the temp directory.
	fakeOnce.Do(buildFake)
	code := m.Run()
	if fakeDir != "" {
		_ = os.RemoveAll(fakeDir)
	}
	os.Exit(code)
}

func buildFake() {
	fakeDir, fakeErr = os.MkdirTemp("", "fakehev-")
	if fakeErr != nil {
		return
	}
	fakeExe = filepath.Join(fakeDir, "hev-fake.exe")
	out, err := exec.Command("go", "build", "-o", fakeExe, "./testdata/fakehev").CombinedOutput()
	if err != nil {
		fakeErr = errors.New(string(out))
	}
}

// fakeHev builds testdata/fakehev once and returns the path of the executable.
func fakeHev(t *testing.T) string {
	t.Helper()
	fakeOnce.Do(buildFake)
	if fakeErr != nil {
		t.Fatalf("build fake hev: %v", fakeErr)
	}
	return fakeExe
}

// isolate points the temp directory at a fresh one so the config files are countable, stops a
// leftover process at the end, and captures the log.
func isolate(t *testing.T) (tmp string, logged func() string) {
	t.Helper()
	tmp = t.TempDir()
	t.Setenv("TMP", tmp)
	t.Setenv("TEMP", tmp)
	var mu sync.Mutex
	var sb strings.Builder
	orig := logf
	logf = func(format string, args ...any) {
		mu.Lock()
		sb.WriteString(strings.TrimSpace(fmt.Sprintf(format, args...)) + "\n")
		mu.Unlock()
	}
	t.Cleanup(func() { _ = Stop(); logf = orig })
	return tmp, func() string { mu.Lock(); defer mu.Unlock(); return sb.String() }
}

func configFiles(t *testing.T, dir string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(dir, "skipi-hev-*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestWindowsNeedsNoTunFd(t *testing.T) {
	if NeedsTunFd() {
		t.Fatal("process mode creates the interface itself; no descriptor is needed")
	}
}

func TestWindowsStartRunsStopsAndCleansUp(t *testing.T) {
	tmp, logged := isolate(t)
	exe := fakeHev(t)

	if err := Start("mode: run\n", Options{TunFd: -1, Executable: exe}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !Running() {
		t.Fatal("Running() = false after Start")
	}
	if err := WaitReady(time.Second); err != nil {
		t.Fatalf("WaitReady: %v", err)
	}
	files := configFiles(t, tmp)
	if len(files) != 1 {
		t.Fatalf("config files while running = %v, want one", files)
	}
	if err := Start("mode: run\n", Options{TunFd: 0, Executable: exe}); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("second Start = %v, want already running", err)
	}
	if a, b, c, d := Stats(); a|b|c|d != 0 {
		t.Fatalf("Stats() = %d %d %d %d, want zeros", a, b, c, d)
	}

	began := time.Now()
	if err := Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if took := time.Since(began); took > 5*time.Second {
		t.Fatalf("Stop took %v", took)
	}
	if Running() {
		t.Fatal("Running() = true after Stop")
	}
	if left := configFiles(t, tmp); len(left) != 0 {
		t.Fatalf("config files after Stop = %v, want none", left)
	}
	if err := Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
	// Output was drained to the Core log, and the process ran from the executable's directory.
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(logged(), "hello from fakehev cwd="+filepath.Dir(exe)) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := logged(); !strings.Contains(got, "hello from fakehev cwd="+filepath.Dir(exe)) {
		t.Fatalf("log = %q, want the process output with its working directory", got)
	}
}

func TestWindowsEarlyExitIsAFailureWithOutput(t *testing.T) {
	tmp, _ := isolate(t)
	exe := fakeHev(t)

	err := Start("mode: exit\n", Options{TunFd: 0, Executable: exe})
	if err == nil {
		t.Fatal("Start must fail when the process exits during the grace window")
	}
	for _, want := range []string{"exited", "code 3", "boom", "stderr-line", filepath.Dir(exe)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	if Running() {
		t.Fatal("Running() = true after a failed start")
	}
	if left := configFiles(t, tmp); len(left) != 0 {
		t.Fatalf("config files after a failed start = %v", left)
	}
}

func TestWindowsEarlyExitOutputIsCapped(t *testing.T) {
	isolate(t)
	err := Start("mode: flood\n", Options{TunFd: 0, Executable: fakeHev(t)})
	if err == nil {
		t.Fatal("Start must fail")
	}
	if n := len(err.Error()[strings.Index(err.Error(), ": ")+2:]); n != 4096 {
		t.Fatalf("error carries %d output bytes, want 4096", n)
	}
}

func TestWindowsExitAfterStartIsReportedByWaitReadyAndStopIsClean(t *testing.T) {
	tmp, _ := isolate(t)
	if err := Start("mode: exitlater\n", Options{TunFd: 0, Executable: fakeHev(t)}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for Running() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if Running() {
		t.Fatal("process should have exited by itself")
	}
	if err := WaitReady(time.Second); !errors.Is(err, ErrExited) && (err == nil || !strings.Contains(err.Error(), "not running")) {
		t.Fatalf("WaitReady after exit = %v", err)
	}
	if err := Stop(); err != nil {
		t.Fatal(err)
	}
	if left := configFiles(t, tmp); len(left) != 0 {
		t.Fatalf("config files = %v, want none", left)
	}
}

func TestWindowsMissingExecutableIsAClearError(t *testing.T) {
	tmp, _ := isolate(t)
	missing := filepath.Join(tmp, "nope", "hev.exe")
	err := Start("mode: run\n", Options{TunFd: 0, Executable: missing})
	if err == nil || !strings.Contains(err.Error(), missing) {
		t.Fatalf("Start with missing exe = %v, want an error naming %s", err, missing)
	}
	err = Start("mode: run\n", Options{})
	if err == nil || !strings.Contains(err.Error(), "executable") {
		t.Fatalf("Start without exe = %v, want an error about the executable", err)
	}
	if err := Start("", Options{TunFd: 0, Executable: fakeHev(t)}); err == nil {
		t.Fatal("blank config must be rejected")
	}
	if left := configFiles(t, tmp); len(left) != 0 {
		t.Fatalf("config files = %v, want none", left)
	}
	if Running() {
		t.Fatal("nothing must be running")
	}
}

func TestWindowsWaitReadyWithoutStart(t *testing.T) {
	isolate(t)
	if err := WaitReady(10 * time.Millisecond); err == nil {
		t.Fatal("WaitReady with nothing running must fail")
	}
}
