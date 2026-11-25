// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build darwin

package hevtun

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/ZloyRadetski/skipi-core/internal/hevpayload"
)

// macOS runs hev as a root supervisor started through the system's administrator prompt
// (osascript "do shell script ... with administrator privileges"); see macsupervisor.go for the
// script and macflow.go for the flow. hev creates the utun interface itself, so no TUN descriptor
// is used (Options.TunFd is ignored). hev's counters live in another process: Stats reports zeros.
// Running means the supervisor's ready file exists and names a live process (a pending stop file
// counts as not running).

// launchTimeout bounds the osascript run (the password prompt included).
const launchTimeout = 120 * time.Second

type osFS struct{}

func (osFS) MkdirAll(dir string, perm os.FileMode) error { return os.MkdirAll(dir, perm) }
func (osFS) Chmod(path string, perm os.FileMode) error   { return os.Chmod(path, perm) }
func (osFS) Remove(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
func (osFS) WriteFile(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}
func (osFS) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }
func (osFS) Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// runLauncher runs the command; a failure carries the command's output (osascript reports a
// cancelled prompt there), else the exec error.
func runLauncher(parent context.Context, command []string) error {
	ctx, cancel := context.WithTimeout(parent, launchTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, command[0], command[1:]...).CombinedOutput()
	if err == nil {
		return nil
	}
	if text := strings.TrimSpace(string(out)); text != "" {
		return errors.New(text)
	}
	return err
}

// isAlive probes a pid; EPERM means the (root) supervisor exists but belongs to another user.
func isAlive(pid int64) bool {
	err := syscall.Kill(int(pid), 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

var tunnel = newMacTunnel(macEnv{
	FS:           osFS{},
	Launch:       runLauncher,
	Runtime:      func(dir string) (string, string, error) { return installMacRuntime(hevpayload.Files, dir) },
	NewToken:     randomToken,
	IsAlive:      isAlive,
	Now:          time.Now,
	Sleep:        time.Sleep,
	AppPid:       int64(os.Getpid()),
	StateDir:     MacStateDirectory(os.Getuid()),
	ReadyTimeout: MacReadyTimeout,
	StopTimeout:  MacStopTimeout,
})

// NeedsTunFd is false: hev creates the utun interface itself.
func NeedsTunFd() bool { return false }

// Start writes the hev Core carries into opts.RunDirectory (0700), shows the administrator prompt and
// starts the supervisor with the config; it returns once the prompt is answered. WaitReady follows the supervisor.
func Start(configYAML string, opts Options) error { return tunnel.start(configYAML, opts) }

// WaitReady polls for the supervisor's ready or error marker; see macTunnel.waitReady.
func WaitReady(timeout time.Duration) error { return tunnel.waitReady(timeout) }

// Stop asks the supervisor to stop through the stop file and waits up to 8 s for it to clean up.
func Stop() error { return tunnel.stop() }

// Stats reports zeros: hev's counters live in the root process.
func Stats() (txPackets, txBytes, rxPackets, rxBytes uint64) { return 0, 0, 0, 0 }

// Running reports whether the supervisor is up.
func Running() bool { return tunnel.running() }

// Exited is nil: hev lives in a root process this one cannot wait on, so callers poll Running.
func Exited() <-chan struct{} { return nil }

// MemoryBytes is zero: hev lives in a root process this one cannot measure.
func MemoryBytes() int64 { return 0 }
