// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build windows

package hevtun

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/ZloyRadetski/skipi-core/internal/hevpayload"
	"golang.org/x/sys/windows"
)

// Windows runs hev as a supervised child process. Its MSYS build cannot be loaded into the Core
// DLL, and hev creates and configures the Wintun adapter itself, so no TUN descriptor is used
// (tunFd is ignored). The executable runs from its own directory, where wintun.dll and the MSYS
// runtime DLLs sit next to it.
//
// There is no ready callback across processes. hev prints nothing when it is up, and a start that
// cannot work (a missing DLL, a bad config) ends within a few tens of milliseconds, so Start
// waits startupGrace and treats a process still alive after it as up; WaitReady then only
// reports whether the process is still alive. hev's own counters are not reachable from another
// process either: Stats reports zeros.

const (
	startupGrace = 150 * time.Millisecond
	// maxStartOutput bounds the process output quoted in a start failure.
	maxStartOutput = 4096
)

var (
	// stopTimeout is how long Stop waits for the process to end after terminating it.
	stopTimeout = 5 * time.Second
	// logf receives the process output, line by line.
	logf = log.Printf
)

// NeedsTunFd is false: hev creates the Wintun adapter itself.
func NeedsTunFd() bool { return false }

type process struct {
	cmd    *exec.Cmd
	config string
	done   chan struct{} // closed when the process exited and its output was drained
	exit   int
	out    *outputWriter
	// job holds the process; it kills everything in it when its last handle closes, so hev (and
	// with it the Wintun adapter) ends with Core even when Core crashes.
	job     windows.Handle
	jobOnce sync.Once
}

func (p *process) closeJob() {
	p.jobOnce.Do(func() {
		if p.job != 0 {
			_ = windows.CloseHandle(p.job)
		}
	})
}

// hevExecutableName is the hev executable inside the install directory.
const hevExecutableName = "hev-socks5-tunnel.exe"

// Seams: the embedded runtime and where it is installed. Tests replace them.
var (
	payloadFiles = hevpayload.Files
	installRoot  = coreHevDirectory
)

// moduleAnchor lives in this module's data, so its address names the module.
var moduleAnchor uint16

// coreHevDirectory is the hev directory next to the module (the Core DLL) that holds this code.
// It sits in the application's install directory, where only an administrator can write, which is
// also where Core runs elevated for the Wintun adapter.
func coreHevDirectory() (string, error) {
	var module windows.Handle
	if err := windows.GetModuleHandleEx(
		windows.GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|windows.GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		&moduleAnchor, &module); err != nil {
		return "", fmt.Errorf("locate the Core library: %w", err)
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetModuleFileName(module, &buf[0], uint32(len(buf)))
	if err != nil {
		return "", fmt.Errorf("locate the Core library: %w", err)
	}
	return filepath.Join(filepath.Dir(windows.UTF16ToString(buf[:n])), "hev"), nil
}

// prepareExecutable installs the runtime this Core carries (hev, Wintun, the MSYS DLLs) into the
// install directory and returns the hev executable. The executable never comes from the plan: Core
// runs only bytes it carries itself. A file already there that differs is written again, so an
// edited hev.exe or DLL is never executed. hev needs its DLLs beside it, hence one directory.
func prepareExecutable() (string, error) {
	files, err := payloadFiles()
	if err != nil {
		if errors.Is(err, hevpayload.ErrNotBundled) {
			return "", fmt.Errorf("HEV TUN is not available: %w", err)
		}
		return "", err
	}
	dir, err := installRoot()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("HEV TUN install directory %s: %w", dir, err)
	}
	hasExecutable := false
	for _, f := range files {
		if f.Name == hevExecutableName {
			hasExecutable = true
		}
		if err := installFile(filepath.Join(dir, f.Name), f); err != nil {
			return "", fmt.Errorf("HEV TUN install %s: %w", f.Name, err)
		}
	}
	if !hasExecutable {
		return "", fmt.Errorf("HEV TUN is not available: the runtime this SKIPI Core carries has no %s", hevExecutableName)
	}
	return filepath.Join(dir, hevExecutableName), nil
}

// installFile makes path hold exactly f: left alone when it already does, otherwise written next to
// it and renamed over it.
func installFile(path string, f hevpayload.File) error {
	if current, err := os.ReadFile(path); err == nil && sha256.Sum256(current) == sha256.Sum256(f.Data) {
		return nil
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, f.Data, 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// configSecurity lets only SYSTEM, Administrators and the file's owner reach the config, with no
// entries inherited from the temp directory: when Core runs elevated, a process of the user that
// is not cannot rewrite the YAML between Core writing it and hev reading it.
const configSecurity = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)"

// writeConfig creates a new config file in the temp directory with configSecurity and writes yaml.
func writeConfig(yaml string) (string, error) {
	sd, err := windows.SecurityDescriptorFromString(configSecurity)
	if err != nil {
		return "", err
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	var random [8]byte
	_, _ = rand.Read(random[:])
	path := filepath.Join(os.TempDir(), "skipi-hev-"+hex.EncodeToString(random[:])+".yml")
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(h), path)
	_, werr := f.WriteString(yaml)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(path)
		return "", werr
	}
	return path, nil
}

// newKillOnCloseJob is a job object that kills its processes when its last handle closes.
func newKillOnCloseJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE},
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		_ = windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

func assignToJob(job windows.Handle, pid int) error {
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.AssignProcessToJobObject(job, h)
}

var (
	mu     sync.Mutex
	active *process
)

// outputWriter forwards the process output to the Core log line by line and keeps the first
// maxStartOutput bytes for a start failure.
type outputWriter struct {
	mu      sync.Mutex
	head    bytes.Buffer
	pending []byte
}

func (w *outputWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if room := maxStartOutput - w.head.Len(); room > 0 {
		w.head.Write(p[:min(room, len(p))])
	}
	w.pending = append(w.pending, p...)
	for {
		i := bytes.IndexByte(w.pending, '\n')
		if i < 0 {
			break
		}
		w.emit(w.pending[:i])
		w.pending = w.pending[i+1:]
	}
	return len(p), nil
}

func (w *outputWriter) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.pending) > 0 {
		w.emit(w.pending)
		w.pending = nil
	}
}

func (w *outputWriter) emit(line []byte) {
	if s := strings.TrimRight(string(line), "\r"); s != "" {
		logf("HEV TUN: %s", s)
	}
}

func (w *outputWriter) first() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return strings.TrimSpace(w.head.String())
}

// current returns the known process, forgetting (and cleaning up after) one that already exited.
func current() *process {
	mu.Lock()
	defer mu.Unlock()
	if active != nil {
		select {
		case <-active.done:
			_ = os.Remove(active.config)
			active.closeJob()
			active = nil
		default:
		}
	}
	return active
}

// Start installs the runtime Core carries, writes the YAML to a temporary file only SYSTEM,
// Administrators and its owner can reach and runs "<hev> <config>" from the install directory,
// inside a job that ends it with Core. A process that exits within the startup grace is a failed start; the
// error carries its first 4 KB of output. tunFd is ignored.
func Start(configYAML string, opts Options) error {
	if configYAML == "" {
		return errors.New("HEV TUN config is empty")
	}
	// opts.Executable is ignored: Core runs the hev it carries.
	if current() != nil {
		return errors.New("HEV TUN is already running")
	}
	executable, err := prepareExecutable()
	if err != nil {
		return err
	}

	cfgPath, err := writeConfig(configYAML)
	if err != nil {
		return fmt.Errorf("HEV TUN config file: %w", err)
	}
	job, err := newKillOnCloseJob()
	if err != nil {
		_ = os.Remove(cfgPath)
		return fmt.Errorf("HEV TUN job object: %w", err)
	}

	out := &outputWriter{}
	cmd := exec.Command(executable, cfgPath)
	cmd.Dir = filepath.Dir(executable)
	// hev is a console program and Core lives in a GUI process: without this flag every tunnel
	// start opens a console window. Its output is piped to Core's log, so nothing is lost.
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW, HideWindow: true}
	cmd.Stdout = out
	cmd.Stderr = out
	cmd.WaitDelay = 2 * time.Second // a grandchild holding the pipe must not hang Wait
	if err := cmd.Start(); err != nil {
		_ = windows.CloseHandle(job)
		_ = os.Remove(cfgPath)
		return fmt.Errorf("HEV TUN executable %s did not start: %w", executable, err)
	}
	if err := assignToJob(job, cmd.Process.Pid); err != nil {
		// A hev that could outlive Core would keep the adapter and its routes alive.
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = windows.CloseHandle(job)
		_ = os.Remove(cfgPath)
		return fmt.Errorf("HEV TUN could not be tied to Core's lifetime: %w", err)
	}
	p := &process{cmd: cmd, config: cfgPath, done: make(chan struct{}), out: out, job: job}
	go func() {
		_ = cmd.Wait()
		out.flush()
		p.exit = cmd.ProcessState.ExitCode()
		close(p.done)
	}()
	mu.Lock()
	active = p
	mu.Unlock()

	select {
	case <-p.done:
		mu.Lock()
		if active == p {
			active = nil
		}
		mu.Unlock()
		_ = os.Remove(cfgPath)
		p.closeJob()
		msg := fmt.Sprintf("HEV TUN exited during start (code %d)", p.exit)
		if text := out.first(); text != "" {
			msg += ": " + text
		}
		return errors.New(msg)
	case <-time.After(startupGrace):
		return nil
	}
}

// WaitReady reports whether the process is still alive; see the package comment above. There is
// nothing further to wait for, so timeout is not used.
func WaitReady(timeout time.Duration) error {
	p := current()
	if p == nil {
		return errors.New("HEV TUN is not running")
	}
	select {
	case <-p.done:
		return fmt.Errorf("%w (code %d)", ErrExited, p.exit)
	default:
		return nil
	}
}

// Stop terminates the process and waits (at most stopTimeout) for it to end. A process that is
// still alive afterwards stays known, so a later Stop or ForceStop can end it. Stopping a tunnel
// that is not running is a no-op.
func Stop() error {
	p := current()
	if p == nil {
		return nil
	}
	_ = p.cmd.Process.Kill() // TerminateProcess; an error just means it is already gone
	select {
	case <-p.done:
	case <-time.After(stopTimeout):
		return fmt.Errorf("HEV TUN process did not stop within %v", stopTimeout)
	}
	mu.Lock()
	if active == p {
		active = nil
	}
	mu.Unlock()
	_ = os.Remove(p.config)
	p.closeJob()
	return nil
}

// Stats reports zeros: hev's counters live in another process.
func Stats() (txPackets, txBytes, rxPackets, rxBytes uint64) { return 0, 0, 0, 0 }

// Running reports whether the hev process is alive.
func Running() bool { return current() != nil }

// Exited is closed when the running hev process ends; nil when none runs.
func Exited() <-chan struct{} {
	if p := current(); p != nil {
		return p.done
	}
	return nil
}

var (
	psapi                    = windows.NewLazySystemDLL("psapi.dll")
	procGetProcessMemoryInfo = psapi.NewProc("GetProcessMemoryInfo")
)

// processMemoryCounters is PROCESS_MEMORY_COUNTERS_EX.
type processMemoryCounters struct {
	cb                         uint32
	pageFaultCount             uint32
	peakWorkingSetSize         uintptr
	workingSetSize             uintptr
	quotaPeakPagedPoolUsage    uintptr
	quotaPagedPoolUsage        uintptr
	quotaPeakNonPagedPoolUsage uintptr
	quotaNonPagedPoolUsage     uintptr
	pagefileUsage              uintptr
	peakPagefileUsage          uintptr
	privateUsage               uintptr
}

// MemoryBytes is the private memory of the hev process, which the Go runtime's figures never
// include. It is zero when hev is not running or cannot be read.
func MemoryBytes() int64 {
	p := current()
	if p == nil || p.cmd.Process == nil {
		return 0
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(p.cmd.Process.Pid))
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(h)
	var c processMemoryCounters
	c.cb = uint32(unsafe.Sizeof(c))
	if r, _, _ := procGetProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&c)), uintptr(c.cb)); r == 0 {
		return 0
	}
	return int64(c.privateUsage)
}
