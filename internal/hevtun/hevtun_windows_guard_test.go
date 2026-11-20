// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build windows

package hevtun

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// C4: Core runs hev with its own rights (elevated for the Wintun adapter), so it runs only the hev
// that ships next to the Core library, keeps it in a job that dies with Core, and writes its
// config where only Core can change it.

func TestWindowsRefusesARelativeExecutable(t *testing.T) {
	isolate(t)
	err := Start("mode: run\n", Options{Executable: `hev\hev-socks5-tunnel.exe`})
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("err = %v", err)
	}
}

func TestWindowsRefusesAnExecutableOutsideCoresDirectory(t *testing.T) {
	tmp, _ := isolate(t)
	elsewhere := filepath.Join(tmp, "hev.exe")
	if err := os.WriteFile(elsewhere, []byte("MZ"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := Start("mode: run\n", Options{Executable: elsewhere})
	if err == nil || !strings.Contains(err.Error(), "outside") || !strings.Contains(err.Error(), elsewhere) {
		t.Fatalf("err = %v", err)
	}
	// A path that only looks inside by its text is not inside.
	root := filepath.Dir(fakeHev(t))
	rel, err := filepath.Rel(filepath.Dir(root), elsewhere)
	if err != nil {
		t.Fatal(err)
	}
	sneaky := root + `\..\` + rel
	if err := Start("mode: run\n", Options{Executable: sneaky}); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("sneaky err = %v", err)
	}
}

func TestWindowsHevDiesWithItsJob(t *testing.T) {
	isolate(t)
	if err := Start("mode: run\n", Options{Executable: fakeHev(t)}); err != nil {
		t.Fatal(err)
	}
	p := current()
	if p == nil || p.job == 0 {
		t.Fatal("the process must be in a job")
	}
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(p.cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(proc)
	var inJob int32
	isProcessInJob := windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")
	if ok, _, err := isProcessInJob.Call(uintptr(proc), uintptr(p.job), uintptr(unsafe.Pointer(&inJob))); ok == 0 || inJob == 0 {
		t.Fatalf("in job = %v, %v", inJob, err)
	}
	// The job is closed when Core's process ends; hev must end with it.
	p.closeJob()
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		t.Fatal("hev outlived its job")
	}
}

func TestWindowsConfigIsWritableOnlyBySystemAdministratorsAndTheOwner(t *testing.T) {
	tmp, _ := isolate(t)
	if err := Start("mode: run\n", Options{Executable: fakeHev(t)}); err != nil {
		t.Fatal(err)
	}
	files := configFiles(t, tmp)
	if len(files) != 1 {
		t.Fatalf("config files = %v", files)
	}
	sd, err := windows.GetNamedSecurityInfo(files[0], windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	sddl := sd.String()
	if !strings.HasPrefix(sddl, "D:P") {
		t.Fatalf("the DACL must not inherit the temp directory's entries: %s", sddl)
	}
	for _, broad := range []string{";BU)", ";AU)", ";WD)", ";IU)"} {
		if strings.Contains(sddl, broad) {
			t.Fatalf("a broad group can reach the config: %s", sddl)
		}
	}
}
