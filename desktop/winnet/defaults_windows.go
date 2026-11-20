// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build windows

package winnet

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/ZloyRadetski/skipi-core/desktop/netbind"
	"golang.org/x/sys/windows"
)

const commandTimeout = 30 * time.Second

func applyPlatformDefaults(cfg *Config) {
	if cfg.Run == nil {
		cfg.Run = runHidden
		// With the real command runner the routes go in natively, without a process each.
		if cfg.AddRoute == nil {
			cfg.AddRoute = nativeAddRoute
		}
		if cfg.DeleteRoute == nil {
			cfg.DeleteRoute = nativeDeleteRoute
		}
		if cfg.SetDNS == nil {
			cfg.SetDNS = nativeSetDNS
		}
		if cfg.FlushDNS == nil {
			cfg.FlushDNS = nativeFlushDNS
		}
	}
	if cfg.ListAdapters == nil {
		cfg.ListAdapters = netbind.AdapterNames
	}
	if cfg.AdapterExists == nil {
		list := cfg.ListAdapters
		cfg.AdapterExists = func(name string) bool {
			names, err := list()
			return err == nil && slices.Contains(names, name)
		}
	}
	if cfg.RemoveAdapter == nil {
		run := cfg.Run
		cfg.RemoveAdapter = func(name string) error { return run(removeAdapterCommand(name)) }
	}
}

// runHidden runs a system command without a console window; a non-zero exit is a failure with its output.
func runHidden(command []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW, HideWindow: true}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s failed: %s", strings.Join(command[:min(len(command), 4)], " "), strings.TrimSpace(out.String()+" "+err.Error()))
	}
	return nil
}

// removeAdapterCommand removes Wintun adapters named like name ("skipi0", "skipi0 1", ...).
func removeAdapterCommand(name string) []string {
	return powershell("Get-NetAdapter -ErrorAction SilentlyContinue | " +
		"Where-Object { $_.InterfaceDescription -like 'Wintun*' -and ($_.Name -eq '" + name + "' -or $_.Name -like '" + name + " *') } | " +
		"ForEach-Object { pnputil /remove-device $_.PnPDeviceID | Out-Null }")
}
