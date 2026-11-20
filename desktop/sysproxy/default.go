// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package sysproxy

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"runtime"
)

var goos = runtime.GOOS

// leaseFileName is the name the Kotlin host gave its lease on each system. It is kept, so that a lease
// that host left behind is found and restored by Core.
func leaseFileName() string {
	switch goos {
	case "darwin":
		return "mac-system-proxy-lease.json"
	case "windows":
		return "system-proxy-lease.json"
	}
	return "linux-system-proxy-lease.json"
}

// NewDefault is the manager for this operating system, keeping its lease in dir.
func NewDefault(dir string) *Manager {
	return NewManager(platformBackend(), filepath.Join(dir, leaseFileName()))
}

var errUnsupported = errors.New("the system proxy is not supported on this platform")

// unsupportedBackend stands in on platforms without a system proxy to manage.
type unsupportedBackend struct{}

func (unsupportedBackend) Supported() bool                    { return false }
func (unsupportedBackend) Capture() (json.RawMessage, error)  { return nil, errUnsupported }
func (unsupportedBackend) Apply(Lease) error                  { return errUnsupported }
func (unsupportedBackend) Ownership(Lease) (Ownership, error) { return NotOwned, nil }
func (unsupportedBackend) Restore(Lease) error                { return nil }
func (unsupportedBackend) Discard(Lease) error                { return nil }
func (unsupportedBackend) ForceClear() error                  { return nil }
func (unsupportedBackend) RepairStale() (bool, error)         { return false, nil }
