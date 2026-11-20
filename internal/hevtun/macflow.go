// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package hevtun

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The macOS tunnel flow: hash the shipped hev, run the root supervisor through the administrator
// prompt, then follow it through the markers it writes into its own root-owned state directory
// (tun-ready, tun-error, tun-exit, each carrying this session's token). Core asks it to stop with
// tun-stop in the user's run directory, the one file there root looks at. No build tag: the real
// file system and launcher are wired in hevtun_darwin.go, tests inject fakes.

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
	FS macFS
	// Launch runs the privileged command; cancelling ctx ends it (and the password prompt).
	Launch func(ctx context.Context, command []string) error
	// Runtime writes the hev this Core carries into dir and returns its path and SHA-256. The hash is
	// that of the embedded bytes, so the root copy is checked against what Core itself carries, not
	// against a file a user could have replaced.
	Runtime      func(dir string) (path, sha256 string, err error)
	NewToken     func() string
	IsAlive      func(pid int64) bool
	Now          func() time.Time
	Sleep        func(time.Duration)
	AppPid       int64
	StateDir     string
	ReadyTimeout time.Duration
	StopTimeout  time.Duration
}

type macPhase int

const (
	macIdle      macPhase = iota
	macLaunching          // the administrator prompt is up
	macLaunched           // the supervisor was started
)

type macTunnel struct {
	env macEnv
	op  sync.Mutex // serializes starts

	mu           sync.Mutex // guards the fields below; never held across a launch or a wait
	phase        macPhase
	dir          string
	token        string
	deadline     time.Time
	cancelLaunch context.CancelFunc
	launchDone   chan struct{}
	stopAsked    bool
}

func newMacTunnel(env macEnv) *macTunnel { return &macTunnel{env: env} }

// randomToken is 16 random bytes in hex.
func randomToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (m *macTunnel) userFile(dir, name string) string { return path.Join(dir, name) }
func (m *macTunnel) stateFile(name string) string     { return path.Join(m.env.StateDir, name) }

// restrict narrows a mode; a file system that cannot do it is not an error.
func (m *macTunnel) restrict(p string, perm os.FileMode) { _ = m.env.FS.Chmod(p, perm) }

// marker reads a state marker and splits it into fields; an absent marker is nil.
func (m *macTunnel) marker(name string) []string {
	b, err := m.env.FS.ReadFile(m.stateFile(name))
	if err != nil {
		return nil
	}
	return strings.Fields(string(b))
}

// readyPid is the supervisor pid of a ready marker that carries token, else 0.
func (m *macTunnel) readyPid(token string) int64 {
	f := m.marker("tun-ready")
	if len(f) != 2 || f[1] != token {
		return 0
	}
	pid, err := strconv.ParseInt(f[0], 10, 64)
	if err != nil || pid <= 0 {
		return 0
	}
	return pid
}

// supervisorError is the reason of an error marker that carries token.
func (m *macTunnel) supervisorError(token string) (string, bool) {
	b, err := m.env.FS.ReadFile(m.stateFile("tun-error"))
	if err != nil {
		return "", false
	}
	first, rest, _ := strings.Cut(string(b), "\n")
	if strings.TrimSpace(first) != token {
		return "", false
	}
	reason := strings.TrimSpace(rest)
	if reason == "" {
		reason = "The tunnel could not be started"
	}
	return reason, true
}

func (m *macTunnel) exited(token string) bool {
	f := m.marker("tun-exit")
	return len(f) == 1 && f[0] == token
}

func (m *macTunnel) start(configYAML string, opts Options) error {
	m.op.Lock()
	defer m.op.Unlock()
	if configYAML == "" {
		return errors.New("HEV TUN config is empty")
	}
	if strings.TrimSpace(opts.RunDirectory) == "" {
		return errors.New("HEV TUN run directory is required on macOS")
	}
	if opts.MacInterface == nil {
		return errors.New("HEV TUN needs the macOS interface plan")
	}
	if err := ValidateMacPlan(opts.RunDirectory, opts.MacInterface); err != nil {
		return err
	}
	dir := opts.RunDirectory
	stop := m.userFile(dir, "tun-stop")
	mac := opts.MacInterface
	ipv4, err := MacIPv4Of(mac.Addresses)
	if err != nil {
		return err
	}
	if err := m.env.FS.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	m.restrict(dir, 0o700)
	hevPath, sum, err := m.env.Runtime(dir)
	if err != nil {
		return err
	}
	token := m.env.NewToken()
	script, err := MacTunSupervisorScript(MacTunSupervisorSpec{
		InterfaceName: mac.Name,
		MTU:           mac.MTU,
		IPv4Address:   ipv4,
		Routes:        mac.Routes,
		HevExecutable: hevPath,
		HevSHA256:     sum,
		HevConfigYAML: configYAML,
		StateDir:      m.env.StateDir,
		StopFile:      stop,
		Token:         token,
		AppPid:        m.env.AppPid,
	})
	if err != nil {
		return err
	}

	// Leftovers of an earlier session, including the hev config (with its SOCKS password) that
	// older versions kept here.
	for _, name := range []string{"tun-ready", "tun-error", "tun-stop", "tun-hev.yaml"} {
		_ = m.env.FS.Remove(m.userFile(dir, name))
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	m.mu.Lock()
	m.phase = macLaunching
	m.dir = dir
	m.token = token
	m.cancelLaunch = cancel
	m.launchDone = done
	m.stopAsked = false
	m.mu.Unlock()

	launchErr := m.env.Launch(ctx, MacPrivilegedLaunchCommand(MacPrivilegedShellCommand(script)))
	cancel()

	m.mu.Lock()
	defer close(done)
	defer m.mu.Unlock()
	if m.stopAsked {
		// Stop came while the prompt was up. Its stop file stays, so a supervisor that got
		// started anyway leaves before it installs anything.
		m.phase = macIdle
		return errors.New("The tunnel start was cancelled")
	}
	if launchErr != nil {
		m.phase = macIdle
		return errors.New(DescribeMacLaunchFailure(launchErr))
	}
	m.phase = macLaunched
	m.deadline = m.env.Now().Add(m.env.ReadyTimeout)
	return nil
}

// waitReady waits up to timeout for the supervisor's verdict. The whole wait since Start is
// bounded by the ready timeout: past it the supervisor is asked to clean up and the wait fails
// for good. A slice that ends first is ErrReadyTimeout.
func (m *macTunnel) waitReady(timeout time.Duration) error {
	m.mu.Lock()
	phase, dir, token, deadline := m.phase, m.dir, m.token, m.deadline
	m.mu.Unlock()
	if phase != macLaunched {
		return errors.New("HEV TUN is not running")
	}
	sliceEnd := m.env.Now().Add(timeout)
	for {
		if reason, failed := m.supervisorError(token); failed {
			return errors.New(reason)
		}
		if m.readyPid(token) != 0 {
			return nil
		}
		now := m.env.Now()
		if !now.Before(deadline) {
			// Ask the supervisor to clean up whatever it did get done.
			_ = m.env.FS.WriteFile(m.userFile(dir, "tun-stop"), nil, 0o600)
			return errors.New("The tunnel did not become ready in time")
		}
		if !now.Before(sliceEnd) {
			return ErrReadyTimeout
		}
		m.env.Sleep(macPollInterval)
	}
}

// stop asks the supervisor to leave and waits up to the stop timeout until it has cleaned up. It
// never waits for the password prompt: a stop during the prompt ends it and leaves the stop file
// for a supervisor that is started anyway.
func (m *macTunnel) stop() error {
	m.mu.Lock()
	phase, dir, token := m.phase, m.dir, m.token
	if phase == macIdle {
		m.mu.Unlock()
		return nil
	}
	m.stopAsked = true
	cancel, done := m.cancelLaunch, m.launchDone
	m.mu.Unlock()

	if err := m.env.FS.WriteFile(m.userFile(dir, "tun-stop"), nil, 0o600); err != nil {
		return err
	}
	if phase == macLaunching {
		cancel()
		select {
		case <-done:
		case <-time.After(m.env.StopTimeout):
		}
		m.mu.Lock()
		phase = m.phase
		m.mu.Unlock()
		if phase != macLaunched {
			return nil
		}
	}

	deadline := m.env.Now().Add(m.env.StopTimeout)
	for !m.exited(token) {
		if pid := m.readyPid(token); pid != 0 && !m.env.IsAlive(pid) {
			break // killed without a cleanup; nothing is left to wait for
		}
		if !m.env.Now().Before(deadline) {
			return errors.New("The tunnel did not stop in time; its routes may still be installed")
		}
		m.env.Sleep(macPollInterval)
	}
	m.mu.Lock()
	if m.token == token {
		m.phase = macIdle
	}
	m.mu.Unlock()
	return nil
}

// running is true while a stop is not pending and this session's ready marker names a live supervisor.
func (m *macTunnel) running() bool {
	m.mu.Lock()
	phase, dir, token := m.phase, m.dir, m.token
	m.mu.Unlock()
	if phase != macLaunched {
		return false
	}
	if m.env.FS.Exists(m.userFile(dir, "tun-stop")) {
		return false
	}
	pid := m.readyPid(token)
	return pid != 0 && m.env.IsAlive(pid)
}
