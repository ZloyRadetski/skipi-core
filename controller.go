// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/core"
	corestats "github.com/xtls/xray-core/features/stats"
	coreserial "github.com/xtls/xray-core/infra/conf/serial"

	"github.com/ZloyRadetski/skipi-core/internal/connlog"
	"github.com/ZloyRadetski/skipi-core/internal/lifecycle"
	"github.com/ZloyRadetski/skipi-core/internal/runtimetuning"
	"github.com/ZloyRadetski/skipi-core/internal/xraylog"
)

// CoreController manages the lifecycle, stats, and real-time monitoring of an Xray-core instance.
type CoreController struct {
	// mu only guards the lifecycle fields below and is held for short swaps. Config loading,
	// core.New, Start and Close all run without it, so reads and the stop methods never wait on them.
	mu                 sync.Mutex
	state              lifecycleState
	gen                uint64 // bumped by every start and by ForceStop of a start in flight
	abandonedStarts    map[uint64]struct{}
	stop               *lifecycle.StopOp
	instance           coreInstance
	statsManager       corestats.Manager
	trafficStatsTotals map[string]int64
	callback           CoreCallbackHandler
	isRunning          atomic.Bool                 // readable without c.mu, which a slow start or stop holds
	connLog            atomic.Pointer[connlog.Log] // read without c.mu: a slow start or stop must not hold a poll back
	connLogEnabled     atomic.Bool
	ownsAwg            bool                        // the running session started AmneziaWG; guarded by mu
	ownsHev            bool                        // the running session started HEV TUN; guarded by mu
	stateListener      atomic.Pointer[listenerBox] // see SetStateListener

	// Transitions are queued under mu in the order they happen and handed to the listener in
	// that order by one goroutine at a time (see deliverStates).
	eventsMu   sync.Mutex
	events     []queuedState
	delivering bool
}

// NewCoreController creates a new CoreController with the provided callback handler.
func NewCoreController(handler CoreCallbackHandler) *CoreController {
	// Xray keeps a single global registry: register our console writer exactly
	// once per process instead of on every controller creation.
	xraylog.RegisterConsoleHandler()

	return &CoreController{
		callback: handler,
	}
}

// lifecycleState is where a controller is between StartLoop and StopLoop. It only changes under
// CoreController.mu, which is never held across a slow Xray call.
type lifecycleState int

const (
	stateIdle lifecycleState = iota
	stateStarting
	stateRunning
	stateStopping
)

// coreInstance is what the controller needs from a running Xray instance. *core.Instance
// satisfies it; tests substitute a fake whose Close or Start can hang.
type coreInstance interface {
	Close() error
}

// Seams for the slow Xray calls. Production behaviour is the real config loader, core.New and Start.
var (
	loadXrayConfig = func(configJSON string) (*core.Config, error) {
		return coreserial.LoadJSONConfig(strings.NewReader(configJSON))
	}
	createCoreInstance = func(config *core.Config) (coreInstance, error) {
		inst, err := core.New(config)
		if err != nil {
			return nil, err
		}
		return inst, nil
	}
	startCoreInstance = func(inst coreInstance) error {
		real, ok := inst.(*core.Instance)
		if !ok {
			return errors.New("unsupported core instance")
		}
		return real.Start()
	}
)

// Test hooks; nil in production.
var (
	// testHookAfterStopUnlock runs once a stop has made the controller idle again.
	// Atomic, because goroutines of an earlier test may still pass through them.
	testHookAfterStopUnlock atomic.Pointer[func()]
	// testHookBeforeDeliver runs before the state listener hears a transition.
	testHookBeforeDeliver atomic.Pointer[func(state int)]
)

// ErrStopTimedOut marks a stop that gave up waiting for Xray (or AmneziaWG) to close. The
// controller or runner is detached anyway and counted by AbandonedInstances until its Close
// returns, so the host can decide that the process is dirty and must be restarted.
var ErrStopTimedOut = errors.New("SKIPI Core stop timed out")

var (
	// defaultStopTimeout bounds StopLoop and applies to a non-positive timeout argument.
	defaultStopTimeout = 5 * time.Second
	// forceStopTimeout is how long ForceStop lets a running instance close before detaching it.
	forceStopTimeout = time.Second
)

// AbandonedInstances reports how many Xray instances or AmneziaWG runners had their stop given up
// on and whose Close has not returned yet. A non-zero value means the process holds leaked
// sockets or goroutines and should be restarted.
func AbandonedInstances() int64 {
	return lifecycle.Abandoned()
}

// errStartAborted is returned by a StartLoop that ForceStop gave up on.
var errStartAborted = errors.New("core start was aborted by ForceStop")

// StartLoop initializes and starts the Xray core instance with given JSON config and optional TUN file descriptor.
//
// The controller lock is only held for short state swaps: loading the config, core.New and
// Start run unlocked, so IsRunning, the stats readers and ForceStop never wait on a slow start.
func (c *CoreController) StartLoop(configJSON string, tunFd int64) error {
	myGen, err := c.beginStart()
	if err != nil {
		return err
	}
	// If ForceStop gave up on this start, its abandoned mark ends when we return.
	defer c.reapAbandonedStart(myGen)
	return c.runStart(myGen, func() (*core.Config, error) { return loadXrayConfig(configJSON) }, tunFd, false, nil, nil, false)
}

// beginStart moves an idle controller to starting and returns the generation of this attempt.
func (c *CoreController) beginStart() (uint64, error) {
	c.mu.Lock()
	switch c.state {
	case stateRunning:
		c.mu.Unlock()
		return 0, errors.New("core instance is already running")
	case stateStarting:
		c.mu.Unlock()
		return 0, errors.New("core instance is already starting")
	case stateStopping:
		c.mu.Unlock()
		return 0, errors.New("core instance is still stopping")
	}
	c.state = stateStarting
	c.gen++
	myGen := c.gen
	c.statsManager = nil
	c.trafficStatsTotals = make(map[string]int64)
	c.ownsAwg = false
	c.ownsHev = false
	c.queueStateLocked(stateStarting, "")
	c.mu.Unlock()
	c.deliverStates()
	return myGen, nil
}

// runStart is the Xray part of a start attempt that beginStart opened. ownsAwg marks the session
// as the owner of the AmneziaWG runner, so its stop stops it too. beforeFail, when set, runs on
// every failure before the controller returns to idle. afterXray, when set, runs once Xray
// started and before the session is reported running (it starts HEV TUN); when it fails, Xray is
// closed again and the start fails with its error. ownsHev marks the session as the owner of HEV TUN.
// load returns the parsed Xray config; StartSession hands in one that was parsed while
// AmneziaWG came up.
func (c *CoreController) runStart(myGen uint64, load func() (*core.Config, error), tunFd int64, ownsAwg bool, beforeFail func(), afterXray func() error, ownsHev bool) error {
	fail := func(err error) bool {
		if beforeFail != nil {
			beforeFail()
		}
		return c.failStart(myGen, err.Error())
	}

	// Loading routing/geo data is a one-off allocation burst: keep the GC out of its way, then
	// collect the leftovers once in the background.
	resumeGC := runtimetuning.PauseGCForStartup()
	defer func() {
		resumeGC()
		go releaseMemory()
	}()

	config, err := load()
	if err != nil {
		err = fmt.Errorf("failed to load xray config: %w", err)
		fail(err)
		return err
	}

	// Publish the TUN descriptor only after the config validated successfully so
	// a failed start can never leave a stale/global fd visible to other
	// instances created later in this process (env vars are process-wide).
	// Must happen before core.New: features read the fd during construction.
	ownedFd := tunFd
	if tunFd > 0 {
		dup, err := dupTunFd(tunFd)
		if err != nil {
			err = fmt.Errorf("failed to duplicate the TUN descriptor: %w", err)
			fail(err)
			return err
		}
		ownedFd = dup
	}
	c.mu.Lock()
	if c.gen != myGen {
		c.mu.Unlock()
		if tunFd > 0 {
			closeTunFd(ownedFd)
		}
		return errStartAborted
	}
	if tunFd > 0 {
		fdStr := strconv.FormatInt(ownedFd, 10)
		setEnvVariable(tunFdKey, fdStr)
		setEnvVariable(v2rayTunFdKey, fdStr)
	} else {
		unsetEnvVariable(tunFdKey)
		unsetEnvVariable(v2rayTunFdKey)
	}
	c.mu.Unlock()

	server, err := createCoreInstance(config)
	if err != nil {
		if tunFd > 0 {
			closeTunFd(ownedFd)
		}
		err = fmt.Errorf("failed to create xray instance: %w", err)
		fail(err)
		return err
	}
	if c.superseded(myGen) {
		lifecycle.CloseInBackground(server)
		return errStartAborted
	}

	// Every session counts connections from zero.
	connLog := connlog.New(c.connLogEnabled.Load())
	var statsManager corestats.Manager
	if real, ok := server.(*core.Instance); ok {
		connlog.Install(real, connLog)
		if mgr := real.GetFeature(corestats.ManagerType()); mgr != nil {
			if sm, ok := mgr.(corestats.Manager); ok {
				statsManager = sm
			}
		}
	}

	if err := startCoreInstance(server); err != nil {
		// Xray does not roll back features that started before the failing one, so
		// inbounds already listening would keep their ports until the process exits.
		// A Close that hangs is abandoned rather than allowed to hang this start.
		_, _ = lifecycle.RunBounded(server.Close, defaultStopTimeout, nil)
		connlog.Clear(connLog)
		err = fmt.Errorf("failed to start xray instance: %w", err)
		fail(err)
		return err
	}

	if afterXray != nil {
		if err := afterXray(); err != nil {
			// The hook already stopped what it started; undo Xray the same bounded way.
			_, _ = lifecycle.RunBounded(server.Close, defaultStopTimeout, nil)
			connlog.Clear(connLog)
			if errors.Is(err, errStartAborted) {
				return err // ForceStop already reset the controller; the caller stops AmneziaWG
			}
			fail(err)
			return err
		}
	}

	c.mu.Lock()
	if c.gen != myGen {
		// ForceStop aborted this start while Xray was still coming up: do not install it.
		c.mu.Unlock()
		connlog.Clear(connLog)
		lifecycle.CloseInBackground(server)
		if ownsHev {
			_ = stopHevIfOwned(c, myGen, defaultStopTimeout)
		}
		return errStartAborted
	}
	c.instance = server
	c.statsManager = statsManager
	c.connLog.Store(connLog)
	// A toggle that raced the start saw no log yet; apply the latest value now it is visible.
	connLog.SetEnabled(c.connLogEnabled.Load())
	c.state = stateRunning
	c.ownsAwg = ownsAwg
	c.ownsHev = ownsHev
	c.isRunning.Store(true)
	c.queueStateLocked(stateRunning, "")
	c.mu.Unlock()
	c.deliverStates()
	if ownsHev {
		go c.watchHev(myGen, hevTun, hevWatchInterval)
	}

	if c.callback != nil {
		c.callback.Startup()
		c.callback.OnEmitStatus(0, "Started successfully, running")
	}

	return nil
}

// superseded reports whether a ForceStop (or a newer start) replaced start attempt gen.
func (c *CoreController) superseded(gen uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gen != gen
}

// failStart returns the controller to idle after start attempt gen failed and tells the state
// listener why. It reports whether that attempt was still the current one. The TUN descriptor it
// may have published is dropped before the controller is idle, so a next start's is never touched.
func (c *CoreController) failStart(gen uint64, detail string) bool {
	c.mu.Lock()
	if c.gen != gen || c.state != stateStarting {
		c.mu.Unlock()
		return false
	}
	clearTunFdEnv()
	c.state = stateIdle
	c.statsManager = nil
	c.trafficStatsTotals = nil
	c.queueStateLocked(stateIdle, detail)
	c.mu.Unlock()
	c.deliverStates()
	return true
}

// reapAbandonedStart ends the abandoned mark ForceStop put on start attempt gen.
func (c *CoreController) reapAbandonedStart(gen uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.abandonedStarts[gen]; ok {
		delete(c.abandonedStarts, gen)
		lifecycle.UnmarkAbandoned()
	}
}

// StopLoop gracefully shuts down the running Xray instance, giving up after the default timeout.
func (c *CoreController) StopLoop() error {
	return c.StopLoopWithTimeout(0)
}

// StopLoopWithTimeout closes the running Xray instance and waits at most timeoutMillis for it
// (non-positive: 5000 ms). If Close hangs, the controller is detached anyway, left not running,
// counted in AbandonedInstances until Close returns, and the error wraps ErrStopTimedOut.
func (c *CoreController) StopLoopWithTimeout(timeoutMillis int64) error {
	d := defaultStopTimeout
	if timeoutMillis > 0 {
		d = time.Duration(timeoutMillis) * time.Millisecond
	}
	return c.stopWithin(d)
}

func (c *CoreController) stopWithin(d time.Duration) error {
	return c.stopWithinReason(d, "")
}

// stopWithinReason is stopWithin with a reason that leads the Idle detail the listener gets,
// for a stop Core started by itself.
func (c *CoreController) stopWithinReason(d time.Duration, reason string) error {
	c.mu.Lock()
	switch c.state {
	case stateIdle:
		c.mu.Unlock()
		return nil
	case stateStarting:
		c.mu.Unlock()
		return errors.New("core instance is still starting; use ForceStop to abort it")
	case stateStopping:
		op := c.stop
		c.mu.Unlock()
		return op.Wait(d)
	}
	op := lifecycle.NewStopOp()
	gen := c.gen
	inst := c.instance
	ownsAwg := c.ownsAwg
	ownsHev := c.ownsHev
	c.stop = op
	c.state = stateStopping
	c.queueStateLocked(stateStopping, "")
	c.mu.Unlock()
	c.deliverStates()

	// Reverse of the start order: HEV TUN, then Xray, then AmneziaWG, each bounded by d.
	var hevErr error
	if ownsHev {
		hevErr = stopHevBounded(c, gen, d, op.Force())
	}
	closeErr, timedOut := lifecycle.RunBounded(inst.Close, d, op.Force())
	var awgErr error
	if ownsAwg {
		awgErr = stopAnyAmneziaWg(d.Milliseconds())
	}

	stopErr := closeErr
	if timedOut {
		stopErr = fmt.Errorf("%w: xray instance did not close within %v", ErrStopTimedOut, d)
	}
	stopErr = errors.Join(hevErr, stopErr, awgErr)
	detail := reason
	if stopErr != nil {
		if detail != "" {
			detail += ": "
		}
		detail += stopErr.Error()
	}

	c.mu.Lock()
	connlog.Clear(c.connLog.Load())
	c.connLog.Store(nil)
	c.instance = nil
	c.statsManager = nil
	c.trafficStatsTotals = nil
	c.isRunning.Store(false)
	c.stop = nil
	c.ownsAwg = false
	c.ownsHev = false
	// Drop the TUN descriptor env vars so later instances (latency probes, URL-test racers) never
	// observe an already-closed file descriptor. This happens before the controller is idle: a
	// start can only begin after it, so its own descriptor is never cleared here.
	clearTunFdEnv()
	c.state = stateIdle
	c.queueStateLocked(stateIdle, detail)
	c.mu.Unlock()
	if hook := testHookAfterStopUnlock.Load(); hook != nil {
		(*hook)()
	}
	op.Finish(stopErr)
	c.deliverStates()

	if c.callback != nil {
		c.callback.Shutdown()
		c.callback.OnEmitStatus(0, "Core stopped")
	}
	go releaseMemory()

	return stopErr
}

// ForceStop is the emergency stop. It never waits on a hung start or stop and works in every
// state: a running instance gets a short deadline, a start in flight is aborted (its StartLoop
// returns an error and closes whatever it built), and a stop that is already hung is detached.
// HEV TUN and AmneziaWG are stopped too. The error wraps ErrStopTimedOut when anything had to be abandoned.
func (c *CoreController) ForceStop() error {
	var xrayErr, hevErr error
	hevStopped := false
	c.mu.Lock()
	gen := c.gen
	switch c.state {
	case stateStarting:
		if c.abandonedStarts == nil {
			c.abandonedStarts = make(map[uint64]struct{})
		}
		c.abandonedStarts[c.gen] = struct{}{}
		lifecycle.MarkAbandoned()
		c.gen++
		c.state = stateIdle
		c.statsManager = nil
		c.trafficStatsTotals = nil
		c.ownsAwg = false
		c.ownsHev = false
		clearTunFdEnv()
		xrayErr = fmt.Errorf("%w: the start in flight was abandoned", ErrStopTimedOut)
		c.queueStateLocked(stateIdle, xrayErr.Error())
		c.mu.Unlock()
		c.deliverStates()
	case stateStopping:
		op := c.stop
		c.mu.Unlock()
		op.ForceNow()
		<-op.Done()
		xrayErr = op.Err()
		hevStopped = true
	case stateRunning:
		c.mu.Unlock()
		xrayErr = c.stopWithin(forceStopTimeout)
		hevStopped = true
	default:
		c.mu.Unlock()
	}
	// HEV TUN is a process singleton Core owns: unless the stop above already covered it, make sure
	// it is stopped (a no-op when it is not running).
	if !hevStopped {
		hevErr = stopHevBounded(c, gen, forceStopTimeout, nil)
	}
	return errors.Join(xrayErr, hevErr, stopAnyAmneziaWg(forceStopTimeout.Milliseconds()))
}

// IsRunning returns whether the core instance is currently running.
func (c *CoreController) IsRunning() bool {
	return c.isRunning.Load()
}

// Seams for the TUN descriptor Xray takes ownership of; see tunfd_linux.go.
var (
	dupTunFd   = platformDupTunFd
	closeTunFd = platformCloseTunFd
)
