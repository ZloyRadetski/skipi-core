// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build windows

package hevtun

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Windows runs hev as a supervised child process. Its MSYS build cannot be loaded into the Core
// DLL, and hev creates and configures the Wintun adapter itself, so no TUN descriptor is used
// (tunFd is ignored). The executable runs from its own directory, where wintun.dll and the MSYS
// runtime DLLs sit next to it.
//
// There is no ready callback across processes. hev prints nothing when it is up, and a start that
// cannot work (a missing DLL, a bad config) ends within a few tens of milliseconds, so Start
// waits startupGrace and treats a process still alive after it as up; WaitReady then only
// reports whether the process is still alive. hev's own counters are not reachable from another
// process either: Stats reports zeros.

const (
	startupGrace = 150 * time.Millisecond
	// maxStartOutput bounds the process output quoted in a start failure.
	maxStartOutput = 4096
)

var (
	// stopTimeout is how long Stop waits for the process to end after terminating it.
	stopTimeout = 5 * time.Second
	// logf receives the process output, line by line.
	logf = log.Printf
)

// NeedsTunFd is false: hev creates the Wintun adapter itself.
func NeedsTunFd() bool { return false }

type process struct {
	cmd    *exec.Cmd
	config string
	done   chan struct{} // closed when the process exited and its output was drained
	exit   int
	out    *outputWriter
}

var (
	mu     sync.Mutex
	active *process
)

// outputWriter forwards the process output to the Core log line by line and keeps the first
// maxStartOutput bytes for a start failure.
type outputWriter struct {
	mu      sync.Mutex
	head    bytes.Buffer
	pending []byte
}

func (w *outputWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if room := maxStartOutput - w.head.Len(); room > 0 {
		w.head.Write(p[:min(room, len(p))])
	}
	w.pending = append(w.pending, p...)
	for {
		i := bytes.IndexByte(w.pending, '\n')
		if i < 0 {
			break
		}
		w.emit(w.pending[:i])
		w.pending = w.pending[i+1:]
	}
	return len(p), nil
}

func (w *outputWriter) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.pending) > 0 {
		w.emit(w.pending)
		w.pending = nil
	}
}

func (w *outputWriter) emit(line []byte) {
	if s := strings.TrimRight(string(line), "\r"); s != "" {
		logf("HEV TUN: %s", s)
	}
}

func (w *outputWriter) first() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return strings.TrimSpace(w.head.String())
}

// current returns the known process, forgetting (and cleaning up after) one that already exited.
func current() *process {
	mu.Lock()
	defer mu.Unlock()
	if active != nil {
		select {
		case <-active.done:
			_ = os.Remove(active.config)
			active = nil
		default:
		}
	}
	return active
}

// Start writes the YAML to a temporary file (0600) and runs "<executable> <config>" from the
// executable's directory. A process that exits within the startup grace is a failed start; the
// error carries its first 4 KB of output. tunFd is ignored.
func Start(configYAML string, opts Options) error {
	executable := opts.Executable
	if configYAML == "" {
		return errors.New("HEV TUN config is empty")
	}
	if strings.TrimSpace(executable) == "" {
		return errors.New("HEV TUN executable path is required on Windows")
	}
	info, err := os.Stat(executable)
	if err != nil {
		return fmt.Errorf("HEV TUN executable %s: %w", executable, err)
	}
	if info.IsDir() {
		return fmt.Errorf("HEV TUN executable %s is a directory", executable)
	}
	if current() != nil {
		return errors.New("HEV TUN is already running")
	}

	cfg, err := os.CreateTemp("", "skipi-hev-*.yml") // created 0600
	if err != nil {
		return fmt.Errorf("HEV TUN config file: %w", err)
	}
	cfgPath := cfg.Name()
	_, werr := cfg.WriteString(configYAML)
	if cerr := cfg.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(cfgPath)
		return fmt.Errorf("HEV TUN config file: %w", werr)
	}

	out := &outputWriter{}
	cmd := exec.Command(executable, cfgPath)
	cmd.Dir = filepath.Dir(executable)
	cmd.Stdout = out
	cmd.Stderr = out
	cmd.WaitDelay = 2 * time.Second // a grandchild holding the pipe must not hang Wait
	if err := cmd.Start(); err != nil {
		_ = os.Remove(cfgPath)
		return fmt.Errorf("HEV TUN executable %s did not start: %w", executable, err)
	}
	p := &process{cmd: cmd, config: cfgPath, done: make(chan struct{}), out: out}
	go func() {
		_ = cmd.Wait()
		out.flush()
		p.exit = cmd.ProcessState.ExitCode()
		close(p.done)
	}()
	mu.Lock()
	active = p
	mu.Unlock()

	select {
	case <-p.done:
		mu.Lock()
		if active == p {
			active = nil
		}
		mu.Unlock()
		_ = os.Remove(cfgPath)
		msg := fmt.Sprintf("HEV TUN exited during start (code %d)", p.exit)
		if text := out.first(); text != "" {
			msg += ": " + text
		}
		return errors.New(msg)
	case <-time.After(startupGrace):
		return nil
	}
}

// WaitReady reports whether the process is still alive; see the package comment above. There is
// nothing further to wait for, so timeout is not used.
func WaitReady(timeout time.Duration) error {
	p := current()
	if p == nil {
		return errors.New("HEV TUN is not running")
	}
	select {
	case <-p.done:
		return fmt.Errorf("%w (code %d)", ErrExited, p.exit)
	default:
		return nil
	}
}

// Stop terminates the process and waits (at most stopTimeout) for it to end. A process that is
// still alive afterwards stays known, so a later Stop or ForceStop can end it. Stopping a tunnel
// that is not running is a no-op.
func Stop() error {
	p := current()
	if p == nil {
		return nil
	}
	_ = p.cmd.Process.Kill() // TerminateProcess; an error just means it is already gone
	select {
	case <-p.done:
	case <-time.After(stopTimeout):
		return fmt.Errorf("HEV TUN process did not stop within %v", stopTimeout)
	}
	mu.Lock()
	if active == p {
		active = nil
	}
	mu.Unlock()
	_ = os.Remove(p.config)
	return nil
}

// Stats reports zeros: hev's counters live in another process.
func Stats() (txPackets, txBytes, rxPackets, rxBytes uint64) { return 0, 0, 0, 0 }

// Running reports whether the hev process is alive.
func Running() bool { return current() != nil }
