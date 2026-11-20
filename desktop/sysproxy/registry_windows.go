// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build windows

package sysproxy

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/windows/registry"
)

// hkcuRegistry is HKCU through in-process Win32 calls: no reg.exe or PowerShell process per read.
type hkcuRegistry struct{}

func (hkcuRegistry) Read(key, name string) (*RegValue, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, key, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open HKCU\\%s: %w", key, err)
	}
	defer k.Close()
	_, kind, err := k.GetValue(name, nil)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read HKCU\\%s\\%s: %w", key, name, err)
	}
	switch kind {
	case registry.DWORD:
		n, _, err := k.GetIntegerValue(name)
		if err != nil {
			return nil, err
		}
		return &RegValue{Type: regDword, Data: strconv.FormatUint(n, 10)}, nil
	case registry.SZ, registry.EXPAND_SZ:
		s, _, err := k.GetStringValue(name)
		if err != nil {
			return nil, err
		}
		return &RegValue{Type: regString, Data: s}, nil
	default:
		return nil, fmt.Errorf("HKCU\\%s\\%s has an unsupported type %d", key, name, kind)
	}
}

func (hkcuRegistry) Write(key, name string, v RegValue) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, key, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open HKCU\\%s: %w", key, err)
	}
	defer k.Close()
	switch v.Type {
	case regDword:
		n, ok := parseDword(v.Data)
		if !ok {
			return fmt.Errorf("invalid DWORD %q", v.Data)
		}
		err = k.SetDWordValue(name, uint32(n))
	default:
		err = k.SetStringValue(name, v.Data)
	}
	if err != nil {
		return fmt.Errorf("write HKCU\\%s\\%s: %w", key, name, err)
	}
	return nil
}

func (hkcuRegistry) Delete(key, name string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, key, registry.SET_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open HKCU\\%s: %w", key, err)
	}
	defer k.Close()
	if err := k.DeleteValue(name); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return fmt.Errorf("delete HKCU\\%s\\%s: %w", key, name, err)
	}
	return nil
}

// refreshWinInet tells running programs that the Internet settings changed.
func refreshWinInet() error {
	const (
		settingsChanged = 39 // INTERNET_OPTION_SETTINGS_CHANGED
		refresh         = 37 // INTERNET_OPTION_REFRESH
	)
	proc := syscall.NewLazyDLL("wininet.dll").NewProc("InternetSetOptionW")
	for _, option := range []uintptr{settingsChanged, refresh} {
		r, _, err := proc.Call(0, option, 0, 0)
		if r == 0 {
			return fmt.Errorf("Windows did not refresh its Internet proxy settings: %v", err)
		}
	}
	return nil
}

func loopbackPortOpen(port int) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 250*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func platformBackend() Backend {
	return newWindowsBackend(hkcuRegistry{}, refreshWinInet, loopbackPortOpen)
}
