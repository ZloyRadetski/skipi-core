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

	"github.com/ZloyRadetski/skipi-core/internal/hevpayload"
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
	// The embedded runtime is the fake hev, installed under tmp instead of next to the Core library.
	fake, err := os.ReadFile(fakeHev(t))
	if err != nil {
		t.Fatal(err)
	}
	origFiles, origRoot := payloadFiles, installRoot
	payloadFiles = func() ([]hevpayload.File, error) {
		return []hevpayload.File{{Name: hevExecutableName, Data: fake}}, nil
	}
	installRoot = func() (string, error) { return filepath.Join(tmp, "install"), nil }
	var mu sync.Mutex
	var sb strings.Builder
	orig := logf
	logf = func(format string, args ...any) {
		mu.Lock()
		sb.WriteString(strings.TrimSpace(fmt.Sprintf(format, args...)) + "\n")
		mu.Unlock()
	}
	t.Cleanup(func() { _ = Stop(); logf = orig; payloadFiles, installRoot = origFiles, origRoot })
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

	if err := Start("mode: run\n", Options{TunFd: -1}); err != nil {
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
	installDir := filepath.Dir(current().cmd.Path)
	if err := Start("mode: run\n", Options{TunFd: 0}); err == nil || !strings.Contains(err.Error(), "already running") {
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
	for !strings.Contains(logged(), "hello from fakehev cwd="+installDir) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := logged(); !strings.Contains(got, "hello from fakehev cwd="+installDir) {
		t.Fatalf("log = %q, want the process output with its working directory", got)
	}
}

func TestWindowsEarlyExitIsAFailureWithOutput(t *testing.T) {
	tmp, _ := isolate(t)

	err := Start("mode: exit\n", Options{TunFd: 0})
	if err == nil {
		t.Fatal("Start must fail when the process exits during the grace window")
	}
	for _, want := range []string{"exited", "code 3", "boom", "stderr-line", filepath.Join(tmp, "install")} {
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
	err := Start("mode: flood\n", Options{TunFd: 0})
	if err == nil {
		t.Fatal("Start must fail")
	}
	if n := len(err.Error()[strings.Index(err.Error(), ": ")+2:]); n != 4096 {
		t.Fatalf("error carries %d output bytes, want 4096", n)
	}
}

func TestWindowsExitAfterStartIsReportedByWaitReadyAndStopIsClean(t *testing.T) {
	tmp, _ := isolate(t)
	if err := Start("mode: exitlater\n", Options{TunFd: 0}); err != nil {
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

func TestWindowsWithoutTheEmbeddedRuntimeFailsClearly(t *testing.T) {
	tmp, _ := isolate(t)
	payloadFiles = func() ([]hevpayload.File, error) { return nil, hevpayload.ErrNotBundled }
	err := Start("mode: run\n", Options{TunFd: 0})
	if err == nil || !strings.Contains(err.Error(), "does not carry") {
		t.Fatalf("Start without a payload = %v, want the build to say it carries no hev", err)
	}
	if err := Start("", Options{TunFd: 0}); err == nil {
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

func TestWindowsMemoryBytesIsTheHevProcessMemory(t *testing.T) {
	isolate(t)
	if got := MemoryBytes(); got != 0 {
		t.Fatalf("MemoryBytes() = %d before Start, want 0", got)
	}
	if err := Start("mode: run\n", Options{}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got := MemoryBytes(); got < 100*1024 {
		t.Fatalf("MemoryBytes() = %d while hev runs, want the child's private memory (>= 100 KiB)", got)
	}
	if err := Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := MemoryBytes(); got != 0 {
		t.Fatalf("MemoryBytes() = %d after Stop, want 0", got)
	}
}
