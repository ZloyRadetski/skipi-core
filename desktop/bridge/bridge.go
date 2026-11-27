// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

// Package desktopbridge owns the single in-process SKIPI Core session exposed
// to a desktop host. It deliberately contains no cgo so its lifecycle rules can
// be unit tested without a native toolchain.
package desktopbridge

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	skipicore "github.com/ZloyRadetski/skipi-core"
	"github.com/ZloyRadetski/skipi-core/desktop/egress"
	"github.com/ZloyRadetski/skipi-core/desktop/sysproxy"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
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

// Seams for the slow starts, so tests can hold one in flight.
var (
	startLoop       = (*skipicore.CoreController).StartLoop
	startSession    = (*skipicore.CoreController).StartSession
	setAwgProtector = skipicore.SetAmneziaWgSocketProtector
)

// awgProtector pins AmneziaWG's peer sockets to the physical interface (see SetSocketProtector).
var awgProtector atomic.Pointer[skipicore.SocketProtector]

// SetSocketProtector sets what AmneziaWG's peer sockets go through on the desktop: the TUN host's
// interface binding, so they never enter the tunnel. nil leaves them unprotected.
func SetSocketProtector(p skipicore.SocketProtector) {
	if p == nil {
		awgProtector.Store(nil)
		return
	}
	awgProtector.Store(&p)
}

func installAwgProtector() {
	var p skipicore.SocketProtector
	if stored := awgProtector.Load(); stored != nil {
		p = *stored
	}
	setAwgProtector(p)
}

// Runtime serializes access to SKIPI Core's process-global state. A desktop
// application may retain multiple handles for UI ownership, but exactly one may
// run a core instance at any time.
type Runtime struct {
	mu          sync.Mutex
	controllers map[Handle]*skipicore.CoreController
	nextHandle  Handle
	active      Handle
	starting    map[Handle]bool // handles whose start is in flight; they hold the lease
	assetDir    string

	systemProxy    *sysproxy.Manager                        // set by SystemProxy("configure")
	newSystemProxy func(directory string) *sysproxy.Manager // a seam for tests; nil means sysproxy.NewDefault
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

// DestroyController stops an active controller before releasing its handle. The handle leaves
// the table at once, so nothing can start it again; the stop itself runs without the runtime
// locks, which keep answering state reads while the instance closes.
func (r *Runtime) DestroyController(handle Handle) error {
	coreProcessState.Lock()
	r.mu.Lock()
	controller, err := r.controllerLocked(handle)
	if err != nil {
		r.mu.Unlock()
		coreProcessState.Unlock()
		return err
	}
	delete(r.controllers, handle)
	running := controller.IsRunning()
	if !running {
		if r.active == handle {
			r.active = 0
		}
		clearProcessActiveLocked(r, handle)
	}
	r.mu.Unlock()
	coreProcessState.Unlock()
	if !running {
		return nil
	}

	// The session lease (r.active and the process-wide active handle) stays held until the
	// instance is closed, so no other controller starts while this one is still shutting down.
	stopErr := controller.StopLoopWithTimeout(0)
	r.releaseActive(handle)
	if stopErr != nil {
		return fmt.Errorf("stop SKIPI Core desktop controller %d during destroy: %w", handle, stopErr)
	}
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

	return r.startWithLease(handle, func(c *skipicore.CoreController) error {
		if err := startLoop(c, configJSON, tunFD); err != nil {
			return fmt.Errorf("start SKIPI Core desktop controller %d: %w", handle, err)
		}
		return nil
	})
}

// startWithLease takes the session lease for handle under the runtime locks and then runs start
// without them, so ForceStop, Stop and the state reads never wait for a slow start (a hung Xray,
// the macOS administrator prompt). The lease keeps any other controller from starting meanwhile
// and is given up again when start fails.
func (r *Runtime) startWithLease(handle Handle, start func(*skipicore.CoreController) error) error {
	controller, err := r.takeLease(handle)
	if err != nil {
		return err
	}
	err = start(controller)

	coreProcessState.Lock()
	defer coreProcessState.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.starting, handle)
	if err != nil {
		if r.active == handle {
			r.active = 0
		}
		clearProcessActiveLocked(r, handle)
	}
	return err
}

// takeLease checks that handle may start and takes the session lease for it.
func (r *Runtime) takeLease(handle Handle) (*skipicore.CoreController, error) {
	coreProcessState.Lock()
	defer coreProcessState.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	if coreProcessState.assetRuntime != r || coreProcessState.assetDirectory == "" {
		return nil, fmt.Errorf("%w: initialize this runtime before start", ErrAssetsNotInitialized)
	}
	controller, err := r.controllerLocked(handle)
	if err != nil {
		return nil, err
	}
	if coreProcessState.activeRuntime != nil &&
		(coreProcessState.activeRuntime != r || coreProcessState.activeHandle != handle) {
		return nil, fmt.Errorf("%w: controller %d", ErrAnotherControllerActive, coreProcessState.activeHandle)
	}
	if r.active != 0 && r.active != handle {
		return nil, fmt.Errorf("%w: controller %d", ErrAnotherControllerActive, r.active)
	}
	if r.starting[handle] {
		return nil, fmt.Errorf("SKIPI Core desktop controller %d is already starting", handle)
	}
	if controller.IsRunning() {
		return nil, fmt.Errorf("SKIPI Core desktop controller %d is already running", handle)
	}
	if r.starting == nil {
		r.starting = make(map[Handle]bool)
	}
	r.starting[handle] = true
	r.active = handle
	coreProcessState.activeRuntime = r
	coreProcessState.activeHandle = handle
	return controller, nil
}

// Stop stops a controller and releases the active-session lease even when Xray
// reports a close error, because its instance is no longer usable afterward. Closing can take
// seconds, so it runs without the runtime locks: state reads stay responsive, while the lease
// keeps any other controller from starting until the instance is gone.
func (r *Runtime) Stop(handle Handle) error {
	return r.StopWithTimeout(handle, 0)
}

// StopWithTimeout is Stop with an explicit close deadline in milliseconds (non-positive: the
// default of 5 s). When Xray does not close in time the controller is detached anyway, the lease
// is released, and the error wraps skipicore.ErrStopTimedOut; AbandonedInstances then counts it.
func (r *Runtime) StopWithTimeout(handle Handle, timeoutMillis int64) error {
	controller, err := r.controller(handle)
	if err != nil {
		return err
	}
	err = controller.StopLoopWithTimeout(timeoutMillis)
	r.releaseActive(handle)
	if err != nil {
		return fmt.Errorf("stop SKIPI Core desktop controller %d: %w", handle, err)
	}
	return nil
}

// ForceStop is the emergency stop: it never waits on a hung start or stop, works in every state,
// also stops AmneziaWG, and releases the lease. The error wraps skipicore.ErrStopTimedOut when
// something had to be abandoned.
func (r *Runtime) ForceStop(handle Handle) error {
	controller, err := r.controller(handle)
	if err != nil {
		return err
	}
	err = controller.ForceStop()
	r.releaseActive(handle)
	if err != nil {
		return fmt.Errorf("force stop SKIPI Core desktop controller %d: %w", handle, err)
	}
	return nil
}

// AbandonedInstances reports how many Xray instances or AmneziaWG runners had their stop given up
// on and have not finished closing. A non-zero value means the process should be restarted.
func (r *Runtime) AbandonedInstances() int64 {
	return skipicore.AbandonedInstances()
}

// releaseActive gives up the session lease held by handle, unless its start is still in flight.
func (r *Runtime) releaseActive(handle Handle) {
	coreProcessState.Lock()
	defer coreProcessState.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.starting[handle] {
		return // the start in flight gives the lease up itself when it fails
	}
	if r.active == handle {
		r.active = 0
	}
	clearProcessActiveLocked(r, handle)
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
	if !running && !r.starting[handle] {
		if r.active == handle {
			r.active = 0
		}
		clearProcessActiveLocked(r, handle)
	}
	return running, nil
}

// QueryTrafficStats returns the core's cumulative structured traffic snapshot.
func (r *Runtime) QueryTrafficStats(handle Handle) (string, error) {
	controller, err := r.controller(handle)
	if err != nil {
		return "", err
	}
	return controller.QueryTrafficStats(), nil
}

// QueryTunnelStats returns the HEV TUN interface counters as JSON
// ({"txPackets","txBytes","rxPackets","rxBytes"}). Zeros when no HEV TUN runs, and always zeros
// where hev runs as a separate process (Windows): its counters are not reachable from Core.
func (r *Runtime) QueryTunnelStats(handle Handle) (string, error) {
	controller, err := r.controller(handle)
	if err != nil {
		return "", err
	}
	return controller.QueryTunnelStats(), nil
}

// SetConnectionLogEnabled switches the connection log of a controller.
func (r *Runtime) SetConnectionLogEnabled(handle Handle, enabled bool) error {
	controller, err := r.controller(handle)
	if err != nil {
		return err
	}
	controller.SetConnectionLogEnabled(enabled)
	return nil
}

// ReadConnectionLog returns the routed connections newer than afterSeq as JSON.
func (r *Runtime) ReadConnectionLog(handle Handle, afterSeq int64) (string, error) {
	controller, err := r.controller(handle)
	if err != nil {
		return "", err
	}
	return controller.ReadConnectionLog(afterSeq), nil
}

// MeasureDelay performs the existing in-process delay probe through a running
// controller. The target URL is validated by SKIPI Core itself. The probe can take
// seconds, so it runs without holding the runtime locks: state reads and Stop
// must stay responsive while it is in flight.
func (r *Runtime) MeasureDelay(handle Handle, targetURL string) (int64, error) {
	if strings.TrimSpace(targetURL) == "" {
		return -1, errors.New("SKIPI Core desktop delay target must not be blank")
	}

	controller, err := r.controller(handle)
	if err != nil {
		return -1, err
	}
	delayMillis, err := controller.MeasureDelay(targetURL)
	if err != nil {
		return -1, fmt.Errorf("measure SKIPI Core desktop delay: %w", err)
	}
	return delayMillis, nil
}

// MeasureOutboundDelay measures the latency of one outbound through an isolated Core
// instance, without a controller and without touching the running session. The probe can
// take seconds and holds no runtime lock.
// MeasureOutboundDelays measures every outbound in candidateTags (comma separated) of one config
// through a single isolated instance; see skipicore.MeasureOutboundDelays for the JSON it returns.
func (r *Runtime) MeasureOutboundDelays(configJSON, candidateTags, targetURL string, timeoutMillis int64) (string, error) {
	if strings.TrimSpace(configJSON) == "" {
		return "", errors.New("SKIPI Core desktop probe configuration must not be blank")
	}
	if strings.TrimSpace(targetURL) == "" {
		return "", errors.New("SKIPI Core desktop delay target must not be blank")
	}
	return skipicore.MeasureOutboundDelays(configJSON, candidateTags, targetURL, timeoutMillis), nil
}

func (r *Runtime) MeasureOutboundDelay(configJSON string, targetURL string) (int64, error) {
	if strings.TrimSpace(configJSON) == "" {
		return -1, errors.New("SKIPI Core desktop probe configuration must not be blank")
	}
	if strings.TrimSpace(targetURL) == "" {
		return -1, errors.New("SKIPI Core desktop delay target must not be blank")
	}
	delayMillis, err := skipicore.MeasureOutboundDelay(configJSON, targetURL)
	if err != nil {
		return -1, fmt.Errorf("measure SKIPI Core outbound delay: %w", err)
	}
	return delayMillis, nil
}

// MeasureTcpDelay measures one TCP connect to host:port, in milliseconds. It dials the way Core's
// own outbound sockets do, so while a tunnel is up the registered dialer controllers pin it to the
// physical interface: the number is the path to the server, not the tunnel's own answer.
func (r *Runtime) MeasureTcpDelay(host string, port int, timeoutMillis int) (int64, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return -1, errors.New("SKIPI Core desktop TCP probe host must not be blank")
	}
	if port < 1 || port > 65535 {
		return -1, fmt.Errorf("SKIPI Core desktop TCP probe port %d is out of range", port)
	}
	if timeoutMillis < 1 {
		return -1, errors.New("SKIPI Core desktop TCP probe timeout must be positive")
	}
	// One link every time: with link merging on, connects would otherwise alternate between the links' paths.
	ctx, cancel := context.WithTimeout(egress.WithoutMerging(context.Background()), time.Duration(timeoutMillis)*time.Millisecond)
	defer cancel()

	started := time.Now()
	conn, err := internet.DialSystem(ctx, xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(port)), nil)
	if err != nil {
		return -1, fmt.Errorf("connect to %s:%d: %w", host, port, err)
	}
	elapsed := time.Since(started).Milliseconds()
	_ = conn.Close()
	return elapsed, nil
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

// StartAmneziaWg starts the process-wide AmneziaWG runner and its private loopback
// SOCKS listener on socksPort. The host points a SOCKS outbound at that port and
// starts Core afterwards. The peer sockets go through the desktop protector (see
// SetSocketProtector), which pins them to the physical interface while a TUN is up.
func (r *Runtime) StartAmneziaWg(configJSON string, socksPort int) error {
	if socksPort <= 0 {
		return errors.New("AmneziaWG SOCKS port must be positive")
	}
	installAwgProtector()
	return skipicore.StartAmneziaWg(configJSON, socksPort)
}

// StopAmneziaWg stops the AmneziaWG runner. Stopping a stopped runner is not an error.
func (r *Runtime) StopAmneziaWg() error {
	return skipicore.StopAmneziaWg()
}

// IsAmneziaWgRunning reports whether the AmneziaWG runner is active.
func (r *Runtime) IsAmneziaWgRunning() bool {
	return skipicore.IsAmneziaWgRunning()
}

// ActiveHandle returns the currently running controller, or zero.
func (r *Runtime) ActiveHandle() Handle {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.active
}

// controller looks a handle up under the runtime lock and releases it before the caller
// uses the controller, which synchronizes itself.
func (r *Runtime) controller(handle Handle) (*skipicore.CoreController, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.controllerLocked(handle)
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

// StartSession starts a controller from a session plan JSON (see skipicore.CoreController.StartSession):
// Xray and, when the plan has it, AmneziaWG with its SOCKS readiness wait and HEV TUN (in process
// on Linux with the TUN descriptor tunFD, a supervised process on Windows). It takes the same
// session lease as Start. AmneziaWG's peer sockets go through the desktop protector (see
// SetSocketProtector).
func (r *Runtime) StartSession(handle Handle, planJSON string, tunFD int64) error {
	if strings.TrimSpace(planJSON) == "" {
		return errors.New("SKIPI Core desktop session plan must not be blank")
	}
	if tunFD < 0 {
		return fmt.Errorf("SKIPI Core desktop TUN descriptor must not be negative: %d", tunFD)
	}

	return r.startWithLease(handle, func(c *skipicore.CoreController) error {
		installAwgProtector()
		if err := startSession(c, planJSON, tunFD); err != nil {
			return fmt.Errorf("start SKIPI Core desktop session %d: %w", handle, err)
		}
		return nil
	})
}

// SessionState returns the controller's session state (skipicore.SessionIdle and friends). It
// never waits on a slow start or stop.
func (r *Runtime) SessionState(handle Handle) (int, error) {
	controller, err := r.controller(handle)
	if err != nil {
		return 0, err
	}
	return controller.State(), nil
}
