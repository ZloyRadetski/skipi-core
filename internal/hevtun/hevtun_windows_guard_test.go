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

	"github.com/ZloyRadetski/skipi-core/internal/hevpayload"
	"golang.org/x/sys/windows"
)

// C4: Core runs hev with its own rights (elevated for the Wintun adapter), so it runs only the hev
// that ships next to the Core library, keeps it in a job that dies with Core, and writes its
// config where only Core can change it.

// Core runs only the hev it carries, from a directory it owns: the plan has no executable to name,
// so nothing a host (or anything that can edit a plan) offers can be run with Core's rights.
func TestWindowsRunsTheCarriedHevFromTheInstallDirectory(t *testing.T) {
	tmp, _ := isolate(t)
	if err := Start("mode: run\n", Options{}); err != nil {
		t.Fatal(err)
	}
	got := current().cmd.Path
	if !strings.HasPrefix(got, filepath.Join(tmp, "install")) || filepath.Base(got) != hevExecutableName {
		t.Fatalf("ran %s, want the carried hev under the install directory", got)
	}
}

func TestWindowsInstallsTheWholeRuntimeBesideTheExecutable(t *testing.T) {
	tmp, _ := isolate(t)
	base := payloadFiles
	payloadFiles = func() ([]hevpayload.File, error) {
		files, err := base()
		return append(files, hevpayload.File{Name: "wintun.dll", Data: []byte("driver")}), err
	}
	if err := Start("mode: run\n", Options{}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(current().cmd.Path)
	if b, err := os.ReadFile(filepath.Join(dir, "wintun.dll")); err != nil || string(b) != "driver" {
		t.Fatalf("wintun.dll = %q, %v", b, err)
	}
	if !strings.HasPrefix(dir, filepath.Join(tmp, "install")) {
		t.Fatalf("installed into %s", dir)
	}
}

// A file of the install directory that no longer matches what Core carries is written again
// before hev runs: an edited hev.exe or DLL is never executed.
func TestWindowsRestoresAChangedRuntimeFile(t *testing.T) {
	isolate(t)
	if err := Start("mode: run\n", Options{}); err != nil {
		t.Fatal(err)
	}
	exe := current().cmd.Path
	want, _ := os.ReadFile(exe)
	if err := Stop(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, []byte("tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Start("mode: run\n", Options{}); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(exe); string(got) != string(want) {
		t.Fatalf("the changed hev.exe was run as it was (%d bytes, want %d)", len(got), len(want))
	}
}

func TestWindowsHevDiesWithItsJob(t *testing.T) {
	isolate(t)
	if err := Start("mode: run\n", Options{}); err != nil {
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
	if err := Start("mode: run\n", Options{}); err != nil {
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
