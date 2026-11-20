// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

// Package sysproxy owns the operating system's proxy settings on the desktop: it points them at the
// local Xray endpoints for the length of a session and gives the user's own values back afterwards,
// also after a crash (the lease file) and without overwriting a setting the user changed meanwhile.
//
// The lease logic (lock, lease file, rollback, recovery) is the same everywhere; what differs is how
// a platform reads, writes and restores its settings, which a Backend does.
package sysproxy

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// LeaseVersion is the format of the lease file.
const LeaseVersion = 1

const loopbackHost = "127.0.0.1"

// Endpoints are the local proxy listeners. Only loopback is accepted: enabling a system proxy must
// never publish a remote address by accident.
type Endpoints struct {
	Host      string `json:"host"`
	HTTPPort  int    `json:"httpPort"`
	SocksPort int    `json:"socksPort"`
}

// Validate refuses anything but loopback and valid ports.
func (e Endpoints) Validate() error {
	if e.Host != loopbackHost {
		return fmt.Errorf("system proxy must use %s", loopbackHost)
	}
	if e.HTTPPort < 1 || e.HTTPPort > 65535 {
		return errors.New("HTTP proxy port must be in 1..65535")
	}
	if e.SocksPort < 1 || e.SocksPort > 65535 {
		return errors.New("SOCKS proxy port must be in 1..65535")
	}
	return nil
}

// Phase says how far a lease got: Prepared is written before the system is touched, Active after.
type Phase string

const (
	PhasePrepared Phase = "prepared"
	PhaseActive   Phase = "active"
)

// Lease is what survives a crash: who owns the proxy, what it points at, and the user's values.
type Lease struct {
	Version    int             `json:"version"`
	Phase      Phase           `json:"phase"`
	OwnerToken string          `json:"ownerToken"`
	Endpoints  Endpoints       `json:"endpoints"`
	Snapshot   json.RawMessage `json:"snapshot"`
}

// Ownership is how a lease relates to the system's current settings.
type Ownership int

const (
	// Active: the system still points at this lease's endpoints.
	Active Ownership = iota
	// Restorable: the settings are the lease's or the original ones (an interrupted change), so
	// restoring is safe.
	Restorable
	// NotOwned: someone else changed the settings; they must be left alone.
	NotOwned
)

// Action is what a manager call did, for the host to word.
type Action string

const (
	ActionAcquired         Action = "acquired"
	ActionAlreadyAcquired  Action = "alreadyAcquired"
	ActionReleased         Action = "released"
	ActionNothingToRelease Action = "nothingToRelease"
	ActionRecovered        Action = "recovered"
	ActionSkippedNotOwner  Action = "skippedNotOwner"
)

// Result is the outcome of a call.
type Result struct {
	Action Action `json:"action"`
}

// Backend is one platform's way to read and change its proxy settings.
type Backend interface {
	// Supported reports whether this machine has a proxy setting we can manage.
	Supported() bool
	// Capture reads the user's current values, in a form Restore can write back.
	Capture() (json.RawMessage, error)
	// Apply points the system at the lease's endpoints. It may leave the system half changed on
	// failure; the manager then calls Restore.
	Apply(l Lease) error
	// Ownership says whether the system still reflects this lease.
	Ownership(l Lease) (Ownership, error)
	// Restore writes the lease's snapshot back.
	Restore(l Lease) error
	// Discard drops our mark of the lease without touching the user's settings.
	Discard(l Lease) error
	// ForceClear switches the system proxy off whatever the lease says.
	ForceClear() error
	// RepairStale switches off a proxy of ours that points at a port nobody serves.
	RepairStale() (bool, error)
}

// Manager runs the lease protocol over a Backend.
type Manager struct {
	backend   Backend
	leasePath string
	newToken  func() string
	mu        sync.Mutex
}

// NewManager keeps its lease at leasePath (a file next to it holds the lock).
func NewManager(backend Backend, leasePath string) *Manager {
	return &Manager{backend: backend, leasePath: leasePath, newToken: randomToken}
}

// Supported reports whether the backend can manage a proxy here.
func (m *Manager) Supported() bool { return m.backend.Supported() }

// Acquire snapshots the user's settings, writes the lease, and points the system at endpoints. Call
// it only once Xray has bound them.
func (m *Manager) Acquire(endpoints Endpoints) (Result, error) {
	if err := endpoints.Validate(); err != nil {
		return Result{}, err
	}
	return locked(m, func() (Result, error) {
		existing, err := loadLease(m.leasePath)
		if err != nil {
			return Result{}, err
		}
		if existing != nil {
			own, err := m.backend.Ownership(*existing)
			if err != nil {
				return Result{}, err
			}
			switch {
			case own == Active && existing.Phase == PhaseActive && existing.Endpoints == endpoints:
				return Result{Action: ActionAlreadyAcquired}, nil
			case own == NotOwned:
				if err := m.discard(*existing); err != nil {
					return Result{}, err
				}
			default:
				// Our own lease on other endpoints (a dynamic port moves at every start) or an
				// interrupted one: hand the user's settings back first, so the new snapshot is theirs.
				if err := m.restore(*existing); err != nil {
					return Result{}, err
				}
			}
		}

		snapshot, err := m.backend.Capture()
		if err != nil {
			return Result{}, err
		}
		lease := Lease{
			Version:    LeaseVersion,
			Phase:      PhasePrepared,
			OwnerToken: m.newToken(),
			Endpoints:  endpoints,
			Snapshot:   snapshot,
		}
		if err := saveLease(m.leasePath, lease); err != nil {
			return Result{}, err
		}
		if err := m.backend.Apply(lease); err != nil {
			if rollback := m.restore(lease); rollback != nil {
				return Result{}, fmt.Errorf("could not enable the system proxy: %w; automatic restoration also failed: %v", err, rollback)
			}
			return Result{}, err
		}
		lease.Phase = PhaseActive
		if err := saveLease(m.leasePath, lease); err != nil {
			return Result{}, err
		}
		return Result{Action: ActionAcquired}, nil
	})
}

// Release gives the user's settings back, but only while the lease still owns them.
func (m *Manager) Release() (Result, error) { return m.finish(ActionReleased) }

// Recover is Release for the start of a new run, after a crash left a lease behind.
func (m *Manager) Recover() (Result, error) { return m.finish(ActionRecovered) }

func (m *Manager) finish(done Action) (Result, error) {
	return locked(m, func() (Result, error) {
		lease, err := loadLease(m.leasePath)
		if err != nil {
			return Result{}, err
		}
		if lease == nil {
			return Result{Action: ActionNothingToRelease}, nil
		}
		own, err := m.backend.Ownership(*lease)
		if err != nil {
			return Result{}, err
		}
		if own == NotOwned {
			if err := m.discard(*lease); err != nil {
				return Result{}, err
			}
			return Result{Action: ActionSkippedNotOwner}, nil
		}
		if err := m.restore(*lease); err != nil {
			return Result{}, err
		}
		return Result{Action: done}, nil
	})
}

// ForceClear switches the system proxy off and drops the lease, whatever state they are in. Every
// step runs and the first failure is reported.
func (m *Manager) ForceClear() error {
	_, err := locked(m, func() (struct{}, error) {
		first := m.backend.ForceClear()
		if err := os.Remove(m.leasePath); err != nil && !os.IsNotExist(err) && first == nil {
			first = err
		}
		return struct{}{}, first
	})
	return err
}

// RepairStale switches off a proxy of ours that an earlier run left pointing at a dead port. True
// when something was changed.
func (m *Manager) RepairStale() (bool, error) {
	return locked(m, func() (bool, error) { return m.backend.RepairStale() })
}

// restore writes the snapshot back and, only then, drops the lease: a failed restore stays retryable.
func (m *Manager) restore(l Lease) error {
	if err := m.backend.Restore(l); err != nil {
		return err
	}
	return removeLease(m.leasePath)
}

func (m *Manager) discard(l Lease) error {
	if err := m.backend.Discard(l); err != nil {
		return err
	}
	return removeLease(m.leasePath)
}

func locked[T any](m *Manager, body func() (T, error)) (T, error) {
	var zero T
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(m.leasePath), 0o700); err != nil {
		return zero, err
	}
	unlock, err := lockFile(m.leasePath + ".lock")
	if err != nil {
		return zero, fmt.Errorf("Another SKIPI process is changing the system proxy: %w", err)
	}
	defer unlock()
	return body()
}

func randomToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func loadLease(path string) (*Lease, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(trimSpace(data)) == 0 {
		return nil, nil
	}
	return decodeLease(data)
}

// storedLease is a lease file as either writer left it: Core's own, or the Kotlin host's that came before
// (no version field, a capitalised phase, "endpoint" on Windows, "services" on macOS). A session of the old
// app that ended without releasing leaves such a file, and the user's settings must come back from it.
type storedLease struct {
	Version    int        `json:"version"`
	Phase      string     `json:"phase"`
	OwnerToken string     `json:"ownerToken"`
	Endpoints  *Endpoints `json:"endpoints"`
	Endpoint   *struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	} `json:"endpoint"`
	Snapshot json.RawMessage `json:"snapshot"`
	Services json.RawMessage `json:"services"`
	// AppliedProxyOverride is what the old Windows host stored beside the snapshot.
	AppliedProxyOverride string `json:"appliedProxyOverride"`
}

func decodeLease(data []byte) (*Lease, error) {
	var raw storedLease
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("unreadable system proxy lease: %w", err)
	}
	// 0 is the old host, which left the default out of its files.
	if raw.Version != 0 && raw.Version != LeaseVersion {
		return nil, errors.New("unsupported system proxy lease format")
	}
	lease := &Lease{Version: LeaseVersion, Phase: Phase(strings.ToLower(raw.Phase)), OwnerToken: raw.OwnerToken, Snapshot: raw.Snapshot}
	switch {
	case raw.Endpoints != nil:
		lease.Endpoints = *raw.Endpoints
	case raw.Endpoint != nil:
		lease.Endpoints = Endpoints{Host: orLoopback(raw.Endpoint.Host), HTTPPort: raw.Endpoint.Port}
	}
	lease.Endpoints.Host = orLoopback(lease.Endpoints.Host)
	if len(lease.Snapshot) == 0 {
		lease.Snapshot = raw.Services
	}
	if raw.AppliedProxyOverride != "" {
		var fields map[string]json.RawMessage
		if json.Unmarshal(lease.Snapshot, &fields) == nil {
			fields["appliedProxyOverride"], _ = json.Marshal(raw.AppliedProxyOverride)
			lease.Snapshot, _ = json.Marshal(fields)
		}
	}
	if lease.Phase != PhasePrepared && lease.Phase != PhaseActive {
		return nil, errors.New("unsupported system proxy lease format")
	}
	return lease, nil
}

func orLoopback(host string) string {
	if host == "" {
		return loopbackHost
	}
	return host
}

func saveLease(path string, l Lease) error {
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func removeLease(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\n' || b[0] == '\r' || b[0] == '\t') {
		b = b[1:]
	}
	return b
}
