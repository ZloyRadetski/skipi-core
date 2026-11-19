// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package hevtun

import (
	"errors"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The macOS tunnel flow: prepare the run directory, run the root supervisor through the
// administrator prompt, then follow it through marker files in that directory that only the
// supervisor and Core can touch (tun-ready holds the supervisor's pid, tun-error its failure text,
// tun-stop is Core's request to stop). No build tag: the real file system and launcher are wired
// in hevtun_darwin.go, tests inject fakes.

const (
	macPollInterval = 100 * time.Millisecond
	// MacReadyTimeout is how long the supervisor may take to report ready after the prompt returns.
	MacReadyTimeout = 30 * time.Second
	// MacStopTimeout is how long Stop waits for the supervisor to clean up.
	MacStopTimeout = 8 * time.Second
)

// macFS is the file system the flow uses.
type macFS interface {
	MkdirAll(dir string, perm os.FileMode) error
	Chmod(path string, perm os.FileMode) error
	// Remove deletes a file; a missing file is not an error.
	Remove(path string) error
	WriteFile(path string, data []byte, perm os.FileMode) error
	ReadFile(path string) ([]byte, error)
	Exists(path string) bool
}

type macEnv struct {
	FS           macFS
	Launch       func(command []string) error
	IsAlive      func(pid int64) bool
	Now          func() time.Time
	Sleep        func(time.Duration)
	AppPid       int64
	UserUid      int
	ReadyTimeout time.Duration
	StopTimeout  time.Duration
}

type macTunnel struct {
	env macEnv
	op  sync.Mutex // serializes Start and Stop

	mu       sync.Mutex // guards dir and deadline, so running() never waits for a Stop
	dir      string
	deadline time.Time
}

func newMacTunnel(env macEnv) *macTunnel { return &macTunnel{env: env} }

func (m *macTunnel) file(dir, name string) string { return path.Join(dir, name) }

func (m *macTunnel) directory() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dir
}

// restrict narrows a mode; a file system that cannot do it is not an error.
func (m *macTunnel) restrict(p string, perm os.FileMode) { _ = m.env.FS.Chmod(p, perm) }

func (m *macTunnel) start(configYAML string, opts Options) error {
	m.op.Lock()
	defer m.op.Unlock()
	if configYAML == "" {
		return errors.New("HEV TUN config is empty")
	}
	if strings.TrimSpace(opts.RunDirectory) == "" {
		return errors.New("HEV TUN run directory is required on macOS")
	}
	if strings.TrimSpace(opts.Executable) == "" {
		return errors.New("HEV TUN executable path is required on macOS")
	}
	if opts.MacInterface == nil {
		return errors.New("HEV TUN needs the macOS interface plan")
	}
	dir := opts.RunDirectory
	ready, errFile, stop, config := m.file(dir, "tun-ready"), m.file(dir, "tun-error"), m.file(dir, "tun-stop"), m.file(dir, "tun-hev.yaml")

	if err := m.env.FS.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	m.restrict(dir, 0o700)
	for _, f := range []string{ready, errFile, stop} {
		_ = m.env.FS.Remove(f)
	}
	if err := m.env.FS.WriteFile(config, []byte(configYAML), 0o600); err != nil {
		return err
	}
	m.restrict(config, 0o600)

	mac := opts.MacInterface
	ipv4, err := MacIPv4Of(mac.Addresses)
	if err != nil {
		return err
	}
	script, err := MacTunSupervisorScript(MacTunSupervisorSpec{
		InterfaceName: mac.Name,
		MTU:           mac.MTU,
		IPv4Address:   ipv4,
		Routes:        mac.Routes,
		HevExecutable: opts.Executable,
		HevConfig:     config,
		StopFile:      stop,
		ReadyFile:     ready,
		ErrorFile:     errFile,
		AppPid:        m.env.AppPid,
		UserUid:       m.env.UserUid,
	})
	if err != nil {
		return err
	}
	if err := m.env.Launch(MacPrivilegedLaunchCommand(MacPrivilegedShellCommand(script))); err != nil {
		return errors.New(DescribeMacLaunchFailure(err))
	}
	m.mu.Lock()
	m.dir = dir
	m.deadline = m.env.Now().Add(m.env.ReadyTimeout)
	m.mu.Unlock()
	return nil
}

// waitReady waits up to timeout for the supervisor's verdict. The whole wait since Start is
// bounded by the ready timeout: past it the supervisor is asked to clean up and the wait fails
// for good. A slice that ends first is ErrReadyTimeout.
func (m *macTunnel) waitReady(timeout time.Duration) error {
	m.mu.Lock()
	dir, deadline := m.dir, m.deadline
	m.mu.Unlock()
	if dir == "" {
		return errors.New("HEV TUN is not running")
	}
	ready, errFile, stop := m.file(dir, "tun-ready"), m.file(dir, "tun-error"), m.file(dir, "tun-stop")
	sliceEnd := m.env.Now().Add(timeout)
	for {
		if m.env.FS.Exists(errFile) {
			reason := ""
			if b, err := m.env.FS.ReadFile(errFile); err == nil {
				reason = strings.TrimSpace(string(b))
			}
			if reason == "" {
				reason = "The tunnel could not be started"
			}
			return errors.New(reason)
		}
		if m.env.FS.Exists(ready) {
			return nil
		}
		now := m.env.Now()
		if !now.Before(deadline) {
			// Ask the supervisor to clean up whatever it did get done.
			_ = m.env.FS.WriteFile(stop, nil, 0o600)
			return errors.New("The tunnel did not become ready in time")
		}
		if !now.Before(sliceEnd) {
			return ErrReadyTimeout
		}
		m.env.Sleep(macPollInterval)
	}
}

func (m *macTunnel) stop() error {
	m.op.Lock()
	defer m.op.Unlock()
	dir := m.directory()
	if dir == "" {
		return nil
	}
	ready, stop := m.file(dir, "tun-ready"), m.file(dir, "tun-stop")
	if !m.env.FS.Exists(ready) {
		return nil
	}
	if err := m.env.FS.WriteFile(stop, nil, 0o600); err != nil {
		return err
	}
	deadline := m.env.Now().Add(m.env.StopTimeout)
	for m.env.FS.Exists(ready) {
		if !m.env.Now().Before(deadline) {
			return errors.New("The tunnel did not stop in time; its routes may still be installed")
		}
		m.env.Sleep(macPollInterval)
	}
	return nil
}

// running mirrors the app's isRunning: false while a stop is pending, otherwise the ready file
// must hold the pid of a live supervisor.
func (m *macTunnel) running() bool {
	dir := m.directory()
	if dir == "" {
		return false
	}
	if m.env.FS.Exists(m.file(dir, "tun-stop")) {
		return false
	}
	b, err := m.env.FS.ReadFile(m.file(dir, "tun-ready"))
	if err != nil {
		return false
	}
	pid, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return false
	}
	return m.env.IsAlive(pid)
}
