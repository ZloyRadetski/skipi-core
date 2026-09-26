// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

// Package desktopbridge owns the single in-process SKIPI Core session exposed
// to a desktop host. It deliberately contains no cgo so its lifecycle rules can
// be unit tested without a native toolchain.
package desktopbridge

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	skipicore "github.com/ZloyRadetski/skipi-core"
)

// Handle identifies a controller owned by a Runtime. It is opaque to callers.
type Handle uint64

var (
	// ErrAssetsNotInitialized means the desktop host did not install and register
	// its filesystem assets before requesting core startup.
	ErrAssetsNotInitialized = errors.New("SKIPI Core desktop assets are not initialized")
	// ErrControllerNotFound means a caller used an unknown or destroyed handle.
	ErrControllerNotFound = errors.New("SKIPI Core desktop controller was not found")
	// ErrAnotherControllerActive protects Xray's process-global environment and
	// file reader from concurrent desktop sessions.
	ErrAnotherControllerActive = errors.New("another SKIPI Core desktop controller is active")
)

// coreProcessState guards state that SKIPI Core itself stores at process scope:
// Xray asset environment variables, the file reader, and the active Xray
// instance. Runtime methods must take this mutex before their own mutex.
var coreProcessState struct {
	sync.Mutex
	assetRuntime   *Runtime
	assetDirectory string
	activeRuntime  *Runtime
	activeHandle   Handle
}

// Runtime serializes access to SKIPI Core's process-global state. A desktop
// application may retain multiple handles for UI ownership, but exactly one may
// run a core instance at any time.
type Runtime struct {
	mu          sync.Mutex
	controllers map[Handle]*skipicore.CoreController
	nextHandle  Handle
	active      Handle
	assetDir    string
}

// NewRuntime creates an uninitialized desktop runtime.
func NewRuntime() *Runtime {
	return &Runtime{
		controllers: make(map[Handle]*skipicore.CoreController),
	}
}

// InitializeAssets configures the directory containing desktop geo and other
// Xray resources. It must finish before Start and cannot replace assets while a
// controller is active.
func (r *Runtime) InitializeAssets(directory string) error {
	normalized, err := normalizeAssetDirectory(directory)
	if err != nil {
		return err
	}

	coreProcessState.Lock()
	defer coreProcessState.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	if coreProcessState.activeRuntime != nil {
		return fmt.Errorf(
			"cannot replace SKIPI Core desktop assets while controller %d is active",
			coreProcessState.activeHandle,
		)
	}

	skipicore.InitCoreEnv(normalized, "")
	r.assetDir = normalized
	coreProcessState.assetRuntime = r
	coreProcessState.assetDirectory = normalized
	return nil
}

// AssetDirectory returns the normalized resource directory, or an empty string
// before InitializeAssets succeeds.
func (r *Runtime) AssetDirectory() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.assetDir
}

// CreateController allocates an idle core controller and returns its opaque handle.
func (r *Runtime) CreateController() Handle {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.nextHandle++
	if r.nextHandle == 0 {
		r.nextHandle++
	}
	handle := r.nextHandle
	r.controllers[handle] = skipicore.NewCoreController(nil)
	return handle
}

// DestroyController stops an active controller before releasing its handle.
func (r *Runtime) DestroyController(handle Handle) error {
	coreProcessState.Lock()
	defer coreProcessState.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()

	controller, err := r.controllerLocked(handle)
	if err != nil {
		return err
	}
	if controller.IsRunning() {
		if err := controller.StopLoop(); err != nil {
			delete(r.controllers, handle)
			if r.active == handle {
				r.active = 0
			}
			clearProcessActiveLocked(r, handle)
			return fmt.Errorf("stop SKIPI Core desktop controller %d during destroy: %w", handle, err)
		}
	}
	delete(r.controllers, handle)
	if r.active == handle {
		r.active = 0
	}
	clearProcessActiveLocked(r, handle)
	return nil
}

// Start starts a controller with an Xray JSON configuration and an optional TUN
// descriptor. Desktop local-proxy mode passes zero; a negative descriptor is invalid.
func (r *Runtime) Start(handle Handle, configJSON string, tunFD int64) error {
	if strings.TrimSpace(configJSON) == "" {
		return errors.New("SKIPI Core desktop configuration must not be blank")
	}
	if tunFD < 0 {
		return fmt.Errorf("SKIPI Core desktop TUN descriptor must not be negative: %d", tunFD)
	}

	coreProcessState.Lock()
	defer coreProcessState.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	if coreProcessState.assetRuntime != r || coreProcessState.assetDirectory == "" {
		return fmt.Errorf("%w: initialize this runtime before start", ErrAssetsNotInitialized)
	}
	controller, err := r.controllerLocked(handle)
	if err != nil {
		return err
	}
	if coreProcessState.activeRuntime != nil &&
		(coreProcessState.activeRuntime != r || coreProcessState.activeHandle != handle) {
		return fmt.Errorf("%w: controller %d", ErrAnotherControllerActive, coreProcessState.activeHandle)
	}
	if r.active != 0 && r.active != handle {
		return fmt.Errorf("%w: controller %d", ErrAnotherControllerActive, r.active)
	}
	if controller.IsRunning() {
		return fmt.Errorf("SKIPI Core desktop controller %d is already running", handle)
	}

	if err := controller.StartLoop(configJSON, tunFD); err != nil {
		return fmt.Errorf("start SKIPI Core desktop controller %d: %w", handle, err)
	}
	r.active = handle
	coreProcessState.activeRuntime = r
	coreProcessState.activeHandle = handle
	return nil
}

// Stop stops a controller and releases the active-session lease even when Xray
// reports a close error, because its instance is no longer usable afterward.
func (r *Runtime) Stop(handle Handle) error {
	coreProcessState.Lock()
	defer coreProcessState.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()

	controller, err := r.controllerLocked(handle)
	if err != nil {
		return err
	}
	err = controller.StopLoop()
	if r.active == handle {
		r.active = 0
	}
	clearProcessActiveLocked(r, handle)
	if err != nil {
		return fmt.Errorf("stop SKIPI Core desktop controller %d: %w", handle, err)
	}
	return nil
}

// IsRunning reports whether an allocated controller owns a running core instance.
func (r *Runtime) IsRunning(handle Handle) (bool, error) {
	coreProcessState.Lock()
	defer coreProcessState.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()

	controller, err := r.controllerLocked(handle)
	if err != nil {
		return false, err
	}
	running := controller.IsRunning()
	if !running && r.active == handle {
		r.active = 0
	}
	if !running {
		clearProcessActiveLocked(r, handle)
	}
	return running, nil
}

// QueryTrafficStats returns the core's cumulative structured traffic snapshot.
func (r *Runtime) QueryTrafficStats(handle Handle) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	controller, err := r.controllerLocked(handle)
	if err != nil {
		return "", err
	}
	return controller.QueryTrafficStats(), nil
}

// MeasureDelay performs the existing in-process delay probe through a running
// controller. The target URL is validated by SKIPI Core itself.
func (r *Runtime) MeasureDelay(handle Handle, targetURL string) (int64, error) {
	if strings.TrimSpace(targetURL) == "" {
		return -1, errors.New("SKIPI Core desktop delay target must not be blank")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	controller, err := r.controllerLocked(handle)
	if err != nil {
		return -1, err
	}
	delayMillis, err := controller.MeasureDelay(targetURL)
	if err != nil {
		return -1, fmt.Errorf("measure SKIPI Core desktop delay: %w", err)
	}
	return delayMillis, nil
}

// ReadMemoryStats delegates to the process-wide SKIPI Core memory snapshot.
func (r *Runtime) ReadMemoryStats() string {
	return skipicore.ReadMemoryStats()
}

// ForceFreeMemory asks Go to release unused core memory back to the host OS.
func (r *Runtime) ForceFreeMemory() {
	skipicore.ForceFreeMemory()
}

// CoreVersion returns the embedded Xray-core version.
func (r *Runtime) CoreVersion() string {
	return skipicore.CoreVersion()
}

// ActiveHandle returns the currently running controller, or zero.
func (r *Runtime) ActiveHandle() Handle {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.active
}

func (r *Runtime) controllerLocked(handle Handle) (*skipicore.CoreController, error) {
	controller, ok := r.controllers[handle]
	if !ok || handle == 0 {
		return nil, fmt.Errorf("%w: %d", ErrControllerNotFound, handle)
	}
	return controller, nil
}

func clearProcessActiveLocked(runtime *Runtime, handle Handle) {
	if coreProcessState.activeRuntime == runtime && coreProcessState.activeHandle == handle {
		coreProcessState.activeRuntime = nil
		coreProcessState.activeHandle = 0
	}
}

func normalizeAssetDirectory(directory string) (string, error) {
	cleaned := strings.TrimSpace(directory)
	if cleaned == "" {
		return "", errors.New("SKIPI Core desktop asset directory must not be blank")
	}
	absolute, err := filepath.Abs(cleaned)
	if err != nil {
		return "", fmt.Errorf("resolve SKIPI Core desktop asset directory: %w", err)
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return "", fmt.Errorf("read SKIPI Core desktop asset directory: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("SKIPI Core desktop asset path is not a directory: %s", absolute)
	}
	return filepath.Clean(absolute), nil
}
