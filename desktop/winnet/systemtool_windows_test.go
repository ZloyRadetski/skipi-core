// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build windows

package winnet

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Core may run elevated: the system tools it starts must come from the Windows directory, never
// from whatever directory PATH happens to list first.

func TestSystemToolsAreStartedFromTheWindowsDirectory(t *testing.T) {
	root := filepath.Clean(os.Getenv("SystemRoot"))
	for name, want := range map[string]string{
		"netsh":          filepath.Join(root, "System32", "netsh.exe"),
		"powershell.exe": filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
	} {
		got := systemTool(name)
		if !strings.EqualFold(got, want) {
			t.Errorf("systemTool(%q) = %q, want %q", name, got, want)
		}
		if _, err := os.Stat(got); err != nil {
			t.Errorf("%q does not exist: %v", got, err)
		}
	}
}

func TestAToolOutsideTheKnownSetIsLeftAlone(t *testing.T) {
	if got := systemTool("ping"); got != "ping" {
		t.Fatalf("systemTool(ping) = %q; only netsh and powershell are pinned", got)
	}
}

func TestAPathThatPointsToTheToolDirectlyIsKept(t *testing.T) {
	p := `C:\custom\netsh.exe`
	if got := systemTool(p); got != p {
		t.Fatalf("systemTool(%q) = %q", p, got)
	}
}

func TestACommandWithoutArgumentsDoesNotPanic(t *testing.T) {
	if err := runHidden(nil); err == nil {
		t.Fatal("an empty command must be an error")
	}
}
