// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/apernet/quic-go"
	coreapplog "github.com/xtls/xray-core/app/log"
	corecommlog "github.com/xtls/xray-core/common/log"
	corenet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	corestats "github.com/xtls/xray-core/features/stats"
	coreserial "github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
	browser_dialer "github.com/xtls/xray-core/transport/internet/browser_dialer"
)

// Constants for environment variables and core identification
const (
	coreAsset            = "xray.location.asset"
	coreCert             = "xray.location.cert"
	v2rayAsset           = "v2ray.location.asset"
	xudpBaseKey          = "xray.xudp.basekey"
	tunFdKey             = "xray.tun.fd"
	v2rayTunFdKey        = "v2ray.tun.fd"
	browserDialerAddress = "xray.browser.dialer"
	coreLibVersion       = 1
)

// Mobile-first runtime profile applied before any core starts:
//   - GOGC 50 keeps the live heap tighter than the Go default (100), which
//     matters on Android where a fat Go heap invites the low-memory killer.
//     Proxy forwarding is I/O bound, so the extra minor-cycle CPU cost is
//     negligible next to the stability gain.
//   - A soft memory limit acts purely as a safety net: it only starts forcing
//     GC once total runtime memory approaches the ceiling, preventing runaway
//     growth under connection bursts from turning into an OOM kill.
//
// Both values can be overridden per install via SKIPI_GOGC and
// SKIPI_GOMEMLIMIT (bytes) environment variables.
func init() {
	gcPercent := 50
	if raw := os.Getenv("SKIPI_GOGC"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 0 {
			gcPercent = parsed
		}
	}
	debug.SetGCPercent(gcPercent)

	const defaultMemoryLimitBytes = 256 << 20 // 256 MiB soft ceiling
	memoryLimit := int64(defaultMemoryLimitBytes)
	if raw := os.Getenv("SKIPI_GOMEMLIMIT"); raw != "" {
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil && parsed > 0 {
			memoryLimit = parsed
		}
	}
	debug.SetMemoryLimit(memoryLimit)
	applyMaxProcs()
}

// CoreCallbackHandler handles lifecycle and logging events from the core.
type CoreCallbackHandler interface {
	Startup() int64
	Shutdown() int64
	OnEmitStatus(code int64, message string) int64
}

// ProcessFinder is an interface for Android process-based routing (Split Tunneling).
type ProcessFinder interface {
	FindProcessByConnection(network, srcIP string, srcPort int, destIP string, destPort int) int
}

// consoleLogWriter implements a lightweight log writer without redundant timestamps,
// as the Android Logcat system already timestamps all log entries.
type consoleLogWriter struct {
	logger *log.Logger
}

func (w *consoleLogWriter) Write(s string) error {
	w.logger.Print(s)
	return nil
}

func (w *consoleLogWriter) Close() error {
	return nil
}

func createStdoutLogWriter() corecommlog.WriterCreator {
	return func() corecommlog.Writer {
		return &consoleLogWriter{
			logger: log.New(os.Stdout, "", 0),
		}
	}
}

// setEnvVariable safely sets an environment variable.
func setEnvVariable(key, value string) {
	if err := os.Setenv(key, value); err != nil {
		log.Printf("Failed to set environment variable %s: %v", key, err)
	}
}

// unsetEnvVariable safely unsets an environment variable.
func unsetEnvVariable(key string) {
	_ = os.Unsetenv(key)
}

// CoreController manages the lifecycle, stats, and real-time monitoring of an Xray-core instance.
type CoreController struct {
	// mu only guards the lifecycle fields below and is held for short swaps. Config loading,
	// core.New, Start and Close all run without it, so reads and the stop methods never wait on them.
	mu                 sync.Mutex
	state              lifecycleState
	gen                uint64 // bumped by every start and by ForceStop of a start in flight
	abandonedStarts    map[uint64]struct{}
	stop               *stopOp
	instance           coreInstance
	statsManager       corestats.Manager
	trafficStatsTotals map[string]int64
	callback           CoreCallbackHandler
	isRunning          atomic.Bool // readable without c.mu, which a slow start or stop holds
	connLog            atomic.Pointer[connectionLog] // read without c.mu: a slow start or stop must not hold a poll back
	connLogEnabled     atomic.Bool
}

// trafficStatsBytes is deliberately kept private: the mobile binding only
// exposes the compact JSON snapshot returned by QueryTrafficStats.
type trafficStatsBytes struct {
	Uplink   int64 `json:"uplink"`
	Downlink int64 `json:"downlink"`
}

type trafficStatsSnapshot struct {
	Inbound  map[string]trafficStatsBytes `json:"inbound"`
	Outbound map[string]trafficStatsBytes `json:"outbound"`
}

var registerConsoleLogHandlerOnce sync.Once

// NewCoreController creates a new CoreController with the provided callback handler.
func NewCoreController(handler CoreCallbackHandler) *CoreController {
	// Xray keeps a single global registry: register our console writer exactly
	// once per process instead of on every controller creation.
	registerConsoleLogHandlerOnce.Do(func() {
		_ = coreapplog.RegisterHandlerCreator(
			coreapplog.LogType_Console,
			func(lt coreapplog.LogType, options coreapplog.HandlerCreatorOptions) (corecommlog.Handler, error) {
				return corecommlog.NewLogger(createStdoutLogWriter()), nil
			},
		)
	})

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

// Seams for the slow Xray calls. Production behaviour is the real core.New and Start.
var (
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

// ErrStopTimedOut marks a stop that gave up waiting for Xray (or AmneziaWG) to close. The
// controller or runner is detached anyway and counted by AbandonedInstances until its Close
// returns, so the host can decide that the process is dirty and must be restarted.
var ErrStopTimedOut = errors.New("SKIPI Core stop timed out")

var (
	// defaultStopTimeout bounds StopLoop and applies to a non-positive timeout argument.
	defaultStopTimeout = 5 * time.Second
	// forceStopTimeout is how long ForceStop lets a running instance close before detaching it.
	forceStopTimeout = time.Second

	abandonedInstances atomic.Int64
)

// AbandonedInstances reports how many Xray instances or AmneziaWG runners had their stop given up
// on and whose Close has not returned yet. A non-zero value means the process holds leaked
// sockets or goroutines and should be restarted.
func AbandonedInstances() int64 {
	return abandonedInstances.Load()
}

// runBounded runs fn in its own goroutine and waits up to d (or until cancel closes). When it
// gives up, the call is counted in AbandonedInstances until fn returns, and timedOut is true.
func runBounded(fn func() error, d time.Duration, cancel <-chan struct{}) (error, bool) {
	const (
		running = iota
		finished
		abandoned
	)
	var (
		state  atomic.Int32
		result error
	)
	done := make(chan struct{})
	go func() {
		result = fn()
		if !state.CompareAndSwap(running, finished) {
			abandonedInstances.Add(-1) // the waiter gave up on us; we are no longer leaked
		}
		close(done)
	}()

	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-done:
		return result, false
	case <-timer.C:
	case <-cancel:
	}
	// Count first, then claim: the goroutine can never decrement before this increment.
	abandonedInstances.Add(1)
	if !state.CompareAndSwap(running, abandoned) {
		abandonedInstances.Add(-1) // it finished in the meantime
		<-done
		return result, false
	}
	return nil, true
}

// closeInBackground closes inst without waiting; the Close is counted as abandoned while it runs.
func closeInBackground(inst coreInstance) {
	abandonedInstances.Add(1)
	go func() {
		defer abandonedInstances.Add(-1)
		_ = inst.Close()
	}()
}

// stopOp is one in-flight stop. force makes its waiter give up at once.
type stopOp struct {
	finished  chan struct{}
	force     chan struct{}
	forceOnce sync.Once
	err       error // valid once finished is closed
}

func (o *stopOp) forceNow() { o.forceOnce.Do(func() { close(o.force) }) }

// wait lets a second caller share an in-flight stop; its own deadline detaches the instance too.
func (o *stopOp) wait(d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-o.finished:
	case <-timer.C:
		o.forceNow()
		<-o.finished
	}
	return o.err
}

// errStartAborted is returned by a StartLoop that ForceStop gave up on.
var errStartAborted = errors.New("core start was aborted by ForceStop")

// StartLoop initializes and starts the Xray core instance with given JSON config and optional TUN file descriptor.
//
// The controller lock is only held for short state swaps: loading the config, core.New and
// Start run unlocked, so IsRunning, the stats readers and ForceStop never wait on a slow start.
func (c *CoreController) StartLoop(configJSON string, tunFd int64) error {
	c.mu.Lock()
	switch c.state {
	case stateRunning:
		c.mu.Unlock()
		return errors.New("core instance is already running")
	case stateStarting:
		c.mu.Unlock()
		return errors.New("core instance is already starting")
	case stateStopping:
		c.mu.Unlock()
		return errors.New("core instance is still stopping")
	}
	c.state = stateStarting
	c.gen++
	myGen := c.gen
	c.statsManager = nil
	c.trafficStatsTotals = make(map[string]int64)
	c.mu.Unlock()

	// If ForceStop gave up on this start, its abandoned mark ends when we return.
	defer c.reapAbandonedStart(myGen)

	// Loading routing/geo data is a one-off allocation burst: keep the GC out of its way, then
	// collect the leftovers once in the background.
	resumeGC := pauseGCForStartup()
	defer func() {
		resumeGC()
		go runtime.GC()
	}()

	config, err := coreserial.LoadJSONConfig(strings.NewReader(configJSON))
	if err != nil {
		c.failStart(myGen)
		return fmt.Errorf("failed to load xray config: %w", err)
	}

	// Publish the TUN descriptor only after the config validated successfully so
	// a failed start can never leave a stale/global fd visible to other
	// instances created later in this process (env vars are process-wide).
	// Must happen before core.New: features read the fd during construction.
	c.mu.Lock()
	if c.gen != myGen {
		c.mu.Unlock()
		return errStartAborted
	}
	if tunFd > 0 {
		fdStr := strconv.FormatInt(tunFd, 10)
		setEnvVariable(tunFdKey, fdStr)
		setEnvVariable(v2rayTunFdKey, fdStr)
	} else {
		unsetEnvVariable(tunFdKey)
		unsetEnvVariable(v2rayTunFdKey)
	}
	c.mu.Unlock()

	server, err := createCoreInstance(config)
	if err != nil {
		if c.failStart(myGen) {
			clearTunFdEnv()
		}
		return fmt.Errorf("failed to create xray instance: %w", err)
	}
	if c.superseded(myGen) {
		closeInBackground(server)
		return errStartAborted
	}

	// Every session counts connections from zero.
	connLog := newConnectionLog(c.connLogEnabled.Load())
	var statsManager corestats.Manager
	if real, ok := server.(*core.Instance); ok {
		installConnectionLog(real, connLog)
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
		_, _ = runBounded(server.Close, defaultStopTimeout, nil)
		clearConnectionLog(connLog)
		if c.failStart(myGen) {
			clearTunFdEnv()
		}
		return fmt.Errorf("failed to start xray instance: %w", err)
	}

	c.mu.Lock()
	if c.gen != myGen {
		// ForceStop aborted this start while Xray was still coming up: do not install it.
		c.mu.Unlock()
		clearConnectionLog(connLog)
		closeInBackground(server)
		return errStartAborted
	}
	c.instance = server
	c.statsManager = statsManager
	c.connLog.Store(connLog)
	// A toggle that raced the start saw no log yet; apply the latest value now it is visible.
	connLog.enabled.Store(c.connLogEnabled.Load())
	c.state = stateRunning
	c.isRunning.Store(true)
	c.mu.Unlock()

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

// failStart returns the controller to idle after start attempt gen failed. It reports whether
// that attempt was still the current one, i.e. whether it owns the process-wide env vars.
func (c *CoreController) failStart(gen uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gen != gen || c.state != stateStarting {
		return false
	}
	c.state = stateIdle
	c.statsManager = nil
	c.trafficStatsTotals = nil
	return true
}

// reapAbandonedStart ends the abandoned mark ForceStop put on start attempt gen.
func (c *CoreController) reapAbandonedStart(gen uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.abandonedStarts[gen]; ok {
		delete(c.abandonedStarts, gen)
		abandonedInstances.Add(-1)
	}
}

// clearTunFdEnv removes the process-wide TUN descriptor published for a core start.
func clearTunFdEnv() {
	unsetEnvVariable(tunFdKey)
	unsetEnvVariable(v2rayTunFdKey)
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
		return op.wait(d)
	}
	op := &stopOp{finished: make(chan struct{}), force: make(chan struct{})}
	inst := c.instance
	c.stop = op
	c.state = stateStopping
	c.mu.Unlock()

	closeErr, timedOut := runBounded(inst.Close, d, op.force)

	c.mu.Lock()
	clearConnectionLog(c.connLog.Load())
	c.connLog.Store(nil)
	c.instance = nil
	c.statsManager = nil
	c.trafficStatsTotals = nil
	c.isRunning.Store(false)
	c.stop = nil
	c.state = stateIdle
	c.mu.Unlock()

	// Drop the TUN descriptor env vars so later instances (latency probes,
	// URL-test racers) never observe an already-closed file descriptor.
	clearTunFdEnv()

	if timedOut {
		op.err = fmt.Errorf("%w: xray instance did not close within %v", ErrStopTimedOut, d)
	} else {
		op.err = closeErr
	}
	close(op.finished)

	if c.callback != nil {
		c.callback.Shutdown()
		c.callback.OnEmitStatus(0, "Core stopped")
	}

	return op.err
}

// ForceStop is the emergency stop. It never waits on a hung start or stop and works in every
// state: a running instance gets a short deadline, a start in flight is aborted (its StartLoop
// returns an error and closes whatever it built), and a stop that is already hung is detached.
// AmneziaWG is stopped too. The error wraps ErrStopTimedOut when anything had to be abandoned.
func (c *CoreController) ForceStop() error {
	var xrayErr error
	c.mu.Lock()
	switch c.state {
	case stateStarting:
		if c.abandonedStarts == nil {
			c.abandonedStarts = make(map[uint64]struct{})
		}
		c.abandonedStarts[c.gen] = struct{}{}
		abandonedInstances.Add(1)
		c.gen++
		c.state = stateIdle
		c.statsManager = nil
		c.trafficStatsTotals = nil
		clearTunFdEnv()
		c.mu.Unlock()
		xrayErr = fmt.Errorf("%w: the start in flight was abandoned", ErrStopTimedOut)
	case stateStopping:
		op := c.stop
		c.mu.Unlock()
		op.forceNow()
		<-op.finished
		xrayErr = op.err
	case stateRunning:
		c.mu.Unlock()
		xrayErr = c.stopWithin(forceStopTimeout)
	default:
		c.mu.Unlock()
	}
	return errors.Join(xrayErr, StopAmneziaWgWithTimeout(forceStopTimeout.Milliseconds()))
}

// SetConnectionLogEnabled switches the connection log of this and later sessions. It takes no
// controller lock either.
func (c *CoreController) SetConnectionLogEnabled(enabled bool) {
	c.connLogEnabled.Store(enabled)
	if l := c.connLog.Load(); l != nil {
		l.enabled.Store(enabled)
	}
}

// ReadConnectionLog returns the routed connections newer than afterSeq as JSON. It takes no
// controller lock, so neither a slow probe nor a slow start or stop can hold a poll back.
func (c *CoreController) ReadConnectionLog(afterSeq int64) string {
	l := c.connLog.Load()
	if l == nil {
		return `{"seq":0,"entries":[]}`
	}
	return l.snapshot(afterSeq)
}

// IsRunning returns whether the core instance is currently running.
func (c *CoreController) IsRunning() bool {
	return c.isRunning.Load()
}

// MeasureDelay measures network latency to a target URL through the currently running core instance.
func (c *CoreController) MeasureDelay(targetURL string) (int64, error) {
	c.mu.Lock()
	inst, _ := c.instance.(*core.Instance)
	c.mu.Unlock()

	if inst == nil {
		return -1, errors.New("core instance is not running")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	return measureInstanceDelay(ctx, inst, targetURL)
}

// QueryTrafficStats atomically drains Xray's in-memory counters into a
// process-private cumulative snapshot. It never opens an Xray API listener.
//
// Multiple Android UI consumers may call this safely: every call receives the
// same totals accumulated since this CoreController was started, rather than
// stealing a delta from another consumer.
func (c *CoreController) QueryTrafficStats() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	snapshot := c.collectTrafficStatsLocked()
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return emptyTrafficStatsSnapshotJSON
	}
	return string(encoded)
}

// QueryAllOutboundTrafficStats is retained for binary compatibility with
// older callers. New callers should use QueryTrafficStats, which includes
// inbound counters and is safe for concurrent readers.
// It retains the legacy delta semantics: each reported counter is reset after
// it is read. Returns a compact string: "tag,direction,value;tag,direction,value;".
func (c *CoreController) QueryAllOutboundTrafficStats() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	snapshot := trafficStatsSnapshotFromTotals(c.drainTrafficStatsLocked())
	var b strings.Builder
	b.Grow(512)
	for _, tag := range sortedTrafficStatTags(snapshot.Outbound) {
		bytes := snapshot.Outbound[tag]
		for _, entry := range []struct {
			direction string
			value     int64
		}{
			{direction: "uplink", value: bytes.Uplink},
			{direction: "downlink", value: bytes.Downlink},
		} {
			if entry.value <= 0 {
				continue
			}
			b.WriteString(tag)
			b.WriteByte(',')
			b.WriteString(entry.direction)
			b.WriteByte(',')
			b.WriteString(strconv.FormatInt(entry.value, 10))
			b.WriteByte(';')
		}
	}
	return b.String()
}

func (c *CoreController) collectTrafficStatsLocked() trafficStatsSnapshot {
	c.drainTrafficStatsLocked()
	return trafficStatsSnapshotFromTotals(c.trafficStatsTotals)
}

// drainTrafficStatsLocked moves the new Xray counter values into the
// cumulative process-private totals and returns just this drain's deltas. The
// caller must hold c.mu.
func (c *CoreController) drainTrafficStatsLocked() map[string]int64 {
	deltas := make(map[string]int64)
	if c.statsManager == nil {
		return deltas
	}
	if c.trafficStatsTotals == nil {
		c.trafficStatsTotals = make(map[string]int64)
	}

	c.statsManager.VisitCounters(func(name string, counter corestats.Counter) bool {
		if !isTrafficStatCounter(name) {
			return true
		}
		if value := counter.Set(0); value > 0 {
			c.trafficStatsTotals[name] += value
			deltas[name] = value
		}
		return true
	})
	return deltas
}

func trafficStatsSnapshotFromTotals(totals map[string]int64) trafficStatsSnapshot {
	snapshot := newTrafficStatsSnapshot()
	for name, value := range totals {
		if value <= 0 {
			continue
		}
		kind, tag, direction, ok := parseTrafficStatCounterName(name)
		if !ok {
			continue
		}
		stats := snapshot.Outbound
		if kind == "inbound" {
			stats = snapshot.Inbound
		}
		bytes := stats[tag]
		if direction == "uplink" {
			bytes.Uplink += value
		} else {
			bytes.Downlink += value
		}
		stats[tag] = bytes
	}
	return snapshot
}

func newTrafficStatsSnapshot() trafficStatsSnapshot {
	return trafficStatsSnapshot{
		Inbound:  make(map[string]trafficStatsBytes),
		Outbound: make(map[string]trafficStatsBytes),
	}
}

func isTrafficStatCounter(name string) bool {
	_, _, _, ok := parseTrafficStatCounterName(name)
	return ok
}

func parseTrafficStatCounterName(name string) (kind, tag, direction string, ok bool) {
	parts := strings.Split(name, ">>>")
	if len(parts) != 4 || (parts[0] != "inbound" && parts[0] != "outbound") || parts[2] != "traffic" {
		return "", "", "", false
	}
	if parts[1] == "" || (parts[3] != "uplink" && parts[3] != "downlink") {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[3], true
}

func sortedTrafficStatTags(stats map[string]trafficStatsBytes) []string {
	tags := make([]string, 0, len(stats))
	for tag := range stats {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	return tags
}

const emptyTrafficStatsSnapshotJSON = `{"inbound":{},"outbound":{}}`

// InitCoreEnv configures environment variables (assets and certificate path) and installs
// the host-appropriate Xray asset reader. Android may fall back to APK assets; desktop
// hosts intentionally use only the configured filesystem directory.
func InitCoreEnv(dataDir string, assetKey string) {
	if len(dataDir) > 0 {
		setEnvVariable(coreAsset, dataDir)
		setEnvVariable(coreCert, dataDir)
		setEnvVariable(v2rayAsset, dataDir)
	}
	if len(assetKey) > 0 {
		setEnvVariable(xudpBaseKey, assetKey)
	}
	configureCoreAssetReader()
}

// CoreVersion returns the version of the underlying Xray-core engine.
func CoreVersion() string {
	return core.Version()
}

// CheckVersionX returns the SKIPI core wrapper version along with the underlying Xray-core engine version.
func CheckVersionX() string {
	return fmt.Sprintf("SkipiCore v%d, Xray-core v%s", coreLibVersion, core.Version())
}

// ReconcileBrowserDialer updates the browser dialer address and reloads its configuration.
func ReconcileBrowserDialer(dialerAddr string) {
	setEnvVariable(browserDialerAddress, dialerAddr)
	browser_dialer.Reload()
}

// MeasureOutboundDelay tests the latency of an outbound proxy configuration against a target URL.
// It optimizes performance by stripping inbounds and non-essential app modules.
func MeasureOutboundDelay(configJSON string, targetURL string) (int64, error) {
	server, err := startOutboundTestInstance(configJSON)
	if err != nil {
		return -1, err
	}
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	return measureInstanceDelay(ctx, server, targetURL)
}

// outboundDownloadResult is deliberately encoded as JSON at the mobile
// boundary. Returning a string keeps the gomobile surface stable and lets the
// Android UI add fields without coupling itself to a generated Go object.
type outboundDownloadResult struct {
	BytesDownloaded int64 `json:"bytesDownloaded"`
	ElapsedMillis   int64 `json:"elapsedMillis"`
	TtfbMillis      int64 `json:"ttfbMillis"`
	StatusCode      int   `json:"statusCode"`
}

var outboundDownloadCancels sync.Map // map[string]context.CancelFunc

const (
	maxOutboundDownloadBytes         int64 = 100 << 20
	minOutboundDownloadTimeoutMillis int64 = 10_000
	maxOutboundDownloadTimeoutMillis int64 = 10 * 60 * 1000
)

// MeasureOutboundDownload downloads exactly maxBytes through an isolated
// outbound configuration and returns a JSON result containing the measured
// payload, elapsed time, first-byte time and HTTP status. requestID is optional
// but, when supplied, allows CancelOutboundDownload to stop a running request.
func MeasureOutboundDownload(
	configJSON string,
	targetURL string,
	maxBytes int64,
	timeoutMillis int64,
	requestID string,
) (string, error) {
	if maxBytes <= 0 || maxBytes > maxOutboundDownloadBytes {
		return "", fmt.Errorf("download byte limit must be between 1 and %d", maxOutboundDownloadBytes)
	}
	if timeoutMillis < minOutboundDownloadTimeoutMillis || timeoutMillis > maxOutboundDownloadTimeoutMillis {
		return "", fmt.Errorf(
			"download timeout must be between %d and %d ms",
			minOutboundDownloadTimeoutMillis,
			maxOutboundDownloadTimeoutMillis,
		)
	}
	if strings.TrimSpace(targetURL) == "" {
		return "", errors.New("download target URL is empty")
	}

	server, err := startOutboundTestInstance(configJSON)
	if err != nil {
		return "", err
	}
	defer server.Close()

	ctx, cancel := context.WithTimeout(
		context.Background(),
		time.Duration(timeoutMillis)*time.Millisecond,
	)
	defer cancel()
	if requestID != "" {
		outboundDownloadCancels.Store(requestID, context.CancelFunc(cancel))
		defer outboundDownloadCancels.Delete(requestID)
	}

	result, err := measureInstanceDownload(ctx, server, targetURL, maxBytes)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("failed to encode download result: %w", err)
	}
	return string(encoded), nil
}

// CancelOutboundDownload cancels an isolated download test previously started
// with the same requestID. It is safe to call for an already-finished or
// unknown request.
func CancelOutboundDownload(requestID string) {
	if requestID == "" {
		return
	}
	if cancel, ok := outboundDownloadCancels.Load(requestID); ok {
		cancel.(context.CancelFunc)()
	}
}

// startOutboundTestInstance strips a normal app configuration down to the
// dispatcher and outbound pieces required by an isolated test instance.
func startOutboundTestInstance(configJSON string) (*core.Instance, error) {
	config, err := coreserial.LoadJSONConfig(strings.NewReader(configJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to parse test config: %w", err)
	}

	// Optimize test instance by removing inbounds and non-essential apps
	config.Inbound = nil
	var essentialApps []*serial.TypedMessage
	for _, app := range config.App {
		if app.Type == "xray.app.proxyman.OutboundConfig" ||
			app.Type == "xray.app.dispatcher.Config" ||
			app.Type == "xray.app.log.Config" {
			essentialApps = append(essentialApps, app)
		}
	}
	config.App = essentialApps

	server, err := core.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create test instance: %w", err)
	}
	restoreConnectionLog()

	if err := server.Start(); err != nil {
		_ = server.Close()
		return nil, fmt.Errorf("failed to start test instance: %w", err)
	}
	return server, nil
}

// measureInstanceDelay measures network latency for an instance to a given target URL with 2 attempts and jitter reduction.
func measureInstanceDelay(ctx context.Context, inst *core.Instance, targetURL string) (int64, error) {
	if inst == nil {
		return -1, errors.New("core instance is nil")
	}

	if targetURL == "" {
		targetURL = "https://www.google.com/generate_204"
	}

	tr := &http.Transport{
		TLSHandshakeTimeout: 6 * time.Second,
		DisableKeepAlives:   false,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dest, err := corenet.ParseDestination(fmt.Sprintf("%s:%s", network, addr))
			if err != nil {
				return nil, err
			}
			return core.Dial(ctx, inst, dest)
		},
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{
		Transport: tr,
		Timeout:   12 * time.Second,
	}

	var minDuration int64 = -1
	success := false
	var lastErr error

	const attempts = 2
	for i := 0; i < attempts; i++ {
		select {
		case <-ctx.Done():
			if !success {
				return -1, ctx.Err()
			}
			return minDuration, nil
		default:
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if err != nil {
			lastErr = fmt.Errorf("failed to create HTTP request: %w", err)
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		_, err = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
			lastErr = fmt.Errorf("invalid status code: %s", resp.Status)
			continue
		}

		if err != nil {
			lastErr = fmt.Errorf("failed to read response body: %w", err)
			continue
		}

		duration := time.Since(start).Milliseconds()
		if !success || duration < minDuration {
			minDuration = duration
		}
		success = true
	}

	if !success {
		return -1, lastErr
	}
	return minDuration, nil
}

// measureInstanceDownload reads exactly maxBytes from targetURL through the
// supplied Xray instance. The body is deliberately not drained beyond that
// limit: test size is a hard network budget, not merely a reporting hint.
func measureInstanceDownload(
	ctx context.Context,
	inst *core.Instance,
	targetURL string,
	maxBytes int64,
) (outboundDownloadResult, error) {
	if inst == nil {
		return outboundDownloadResult{}, errors.New("core instance is nil")
	}

	tr := &http.Transport{
		TLSHandshakeTimeout: 6 * time.Second,
		DisableKeepAlives:   true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dest, err := corenet.ParseDestination(fmt.Sprintf("%s:%s", network, addr))
			if err != nil {
				return nil, err
			}
			return core.Dial(ctx, inst, dest)
		},
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{Transport: tr}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return outboundDownloadResult{}, fmt.Errorf("failed to create download request: %w", err)
	}
	req.Header.Set("User-Agent", "SKIPI-SpeedTest/1.0")
	req.Header.Set("Cache-Control", "no-cache")
	// The byte budget must apply to the actual response body. Asking for an
	// identity response avoids a transport transparently decompressing a
	// smaller on-wire payload into maxBytes of decoded data.
	req.Header.Set("Accept-Encoding", "identity")

	startedAt := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return outboundDownloadResult{}, fmt.Errorf("download request failed: %w", err)
	}
	defer resp.Body.Close()

	ttfbMillis := time.Since(startedAt).Milliseconds()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return outboundDownloadResult{}, fmt.Errorf("invalid download status code: %s", resp.Status)
	}

	bytesDownloaded, err := io.CopyN(io.Discard, resp.Body, maxBytes)
	if err != nil {
		return outboundDownloadResult{}, fmt.Errorf(
			"download ended before %d bytes (%d bytes received): %w",
			maxBytes,
			bytesDownloaded,
			err,
		)
	}

	return outboundDownloadResult{
		BytesDownloaded: bytesDownloaded,
		ElapsedMillis:   time.Since(startedAt).Milliseconds(),
		TtfbMillis:      ttfbMillis,
		StatusCode:      resp.StatusCode,
	}, nil
}

type certSha256Request struct {
	Address    string `json:"address"`
	Port       int    `json:"port"`
	ServerName string `json:"serverName"`
	TimeoutMs  int64  `json:"timeoutMs"`
}

type certSha256Result struct {
	Sha256 string `json:"sha256,omitempty"`
	Error  string `json:"error,omitempty"`
}

// FetchTlsCertSha256 extracts the SHA-256 fingerprint of a remote server's TLS certificate.
func FetchTlsCertSha256(requestJSON string) string {
	return fetchCertSha256(requestJSON, fetchTLSCertSha256)
}

// FetchQuicCertSha256 extracts the SHA-256 fingerprint of a remote server's QUIC/HTTP3 certificate.
func FetchQuicCertSha256(requestJSON string) string {
	return fetchCertSha256(requestJSON, fetchQUICCertSha256)
}

func fetchCertSha256(
	requestJSON string,
	fetcher func(certSha256Request) (string, error),
) string {
	var request certSha256Request
	if err := json.Unmarshal([]byte(requestJSON), &request); err != nil {
		return marshalCertSha256Result(certSha256Result{Error: err.Error()})
	}

	sha256Value, err := fetcher(request)
	if err != nil {
		return marshalCertSha256Result(certSha256Result{Error: err.Error()})
	}

	return marshalCertSha256Result(certSha256Result{Sha256: sha256Value})
}

func fetchTLSCertSha256(request certSha256Request) (string, error) {
	address, serverName, timeout, err := normalizeCertRequest(request)
	if err != nil {
		return "", err
	}

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: timeout},
		"tcp",
		address,
		&tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", errors.New("peer certificate is empty")
	}

	sum := sha256.Sum256(state.PeerCertificates[0].Raw)
	return hex.EncodeToString(sum[:]), nil
}

func fetchQUICCertSha256(request certSha256Request) (string, error) {
	address, serverName, timeout, err := normalizeCertRequest(request)
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := quic.DialAddr(
		ctx,
		address,
		&tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			NextProtos:         []string{"h3"},
		},
		&quic.Config{
			HandshakeIdleTimeout: timeout,
			MaxIdleTimeout:       timeout,
		},
	)
	if err != nil {
		return "", err
	}
	defer conn.CloseWithError(0, "")

	state := conn.ConnectionState()
	if len(state.TLS.PeerCertificates) == 0 {
		return "", errors.New("peer certificate is empty")
	}

	sum := sha256.Sum256(state.TLS.PeerCertificates[0].Raw)
	return hex.EncodeToString(sum[:]), nil
}

func normalizeCertRequest(req certSha256Request) (string, string, time.Duration, error) {
	if req.Address == "" {
		return "", "", 0, errors.New("address is empty")
	}

	port := req.Port
	if port <= 0 {
		port = 443
	}

	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	return net.JoinHostPort(req.Address, strconv.Itoa(port)), req.ServerName, timeout, nil
}

func marshalCertSha256Result(result certSha256Result) string {
	data, err := json.Marshal(result)
	if err != nil {
		return `{"error":"failed to marshal result"}`
	}
	return string(data)
}

// MemoryStats holds detailed metrics on Go runtime and core memory usage.
type MemoryStats struct {
	AllocBytes    int64  `json:"allocBytes"`
	AllocMb       string `json:"allocMb"`
	TotalAlloc    int64  `json:"totalAlloc"`
	SysBytes      int64  `json:"sysBytes"`
	SysMb         string `json:"sysMb"`
	HeapInuse     int64  `json:"heapInuse"`
	HeapIdle      int64  `json:"heapIdle"`
	HeapReleased  int64  `json:"heapReleased"`
	NumGoroutines int    `json:"numGoroutines"`
	NumGC         uint32 `json:"numGc"`
}

// ReadMemoryStats returns the current memory usage of the Go runtime and tunnel core as a JSON string.
//
// Reads go through the runtime/metrics package, which is effectively
// lock-free: runtime.ReadMemStats would stop the whole Go world on every call,
// and this endpoint is polled periodically by the UI while the tunnel is
// forwarding traffic. A MemStats fallback keeps the JSON contract intact on
// runtimes where a metric is unavailable.
func ReadMemoryStats() string {
	stats := readMemoryStatsFromMetrics()
	if stats == nil {
		stats = readMemoryStatsFromMemStats()
	}
	data, err := json.Marshal(stats)
	if err != nil {
		return `{"error":"failed to marshal memory stats"}`
	}
	return string(data)
}

func readMemoryStatsFromMetrics() *MemoryStats {
	samples := []metrics.Sample{
		{Name: "/memory/classes/heap/objects:bytes"},  // live heap objects -> AllocBytes
		{Name: "/gc/heap/allocs:bytes"},               // cumulative allocated  -> TotalAlloc
		{Name: "/memory/classes/total:bytes"},         // total runtime memory   -> SysBytes
		{Name: "/memory/classes/heap/free:bytes"},     // idle, not yet returned -> HeapIdle part
		{Name: "/memory/classes/heap/released:bytes"}, // returned to the OS     -> HeapReleased
		{Name: "/gc/cycles/total:gc-cycles"},
		{Name: "/sched/goroutines:goroutines"},
	}
	metrics.Read(samples)
	// Every metric above is a uint64 counter or gauge; anything else (including KindBad for a
	// name this runtime does not know) sends the caller to the MemStats fallback.
	for _, sample := range samples {
		if sample.Value.Kind() != metrics.KindUint64 {
			return nil
		}
	}

	const mb = 1024 * 1024
	heapObjects := int64(samples[0].Value.Uint64())
	totalAlloc := int64(samples[1].Value.Uint64())
	sysBytes := int64(samples[2].Value.Uint64())
	heapFree := int64(samples[3].Value.Uint64())
	heapReleased := int64(samples[4].Value.Uint64())

	return &MemoryStats{
		AllocBytes:    heapObjects,
		AllocMb:       fmt.Sprintf("%.2f MB", float64(heapObjects)/mb),
		TotalAlloc:    totalAlloc,
		SysBytes:      sysBytes,
		SysMb:         fmt.Sprintf("%.2f MB", float64(sysBytes)/mb),
		HeapInuse:     heapObjects,
		HeapIdle:      heapFree + heapReleased,
		HeapReleased:  heapReleased,
		NumGoroutines: int(samples[6].Value.Uint64()),
		NumGC:         uint32(samples[5].Value.Uint64()),
	}
}

func readMemoryStatsFromMemStats() *MemoryStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	const mb = 1024 * 1024
	return &MemoryStats{
		AllocBytes:    int64(m.Alloc),
		AllocMb:       fmt.Sprintf("%.2f MB", float64(m.Alloc)/mb),
		TotalAlloc:    int64(m.TotalAlloc),
		SysBytes:      int64(m.Sys),
		SysMb:         fmt.Sprintf("%.2f MB", float64(m.Sys)/mb),
		HeapInuse:     int64(m.HeapInuse),
		HeapIdle:      int64(m.HeapIdle),
		HeapReleased:  int64(m.HeapReleased),
		NumGoroutines: runtime.NumGoroutine(),
		NumGC:         m.NumGC,
	}
}

// ForceFreeMemory triggers a garbage collection cycle and releases unused memory back to the OS.
func ForceFreeMemory() {
	debug.FreeOSMemory()
}

// FastSelectBestOutbound concurrently tests candidate outbounds against a probe URL (defaulting to
// http://connectivitycheck.gstatic.com/generate_204) and returns the tag of the fastest responsive node.
// It uses early-return racing with a tight per-node timeout to avoid blocking on dead nodes.
func FastSelectBestOutbound(configJSON string, candidateTags string, probeURL string, timeoutMs int64) string {
	if configJSON == "" || candidateTags == "" {
		return ""
	}

	tags := strings.Split(candidateTags, ",")
	candidates := make([]string, 0, len(tags))
	for _, t := range tags {
		trimmed := strings.TrimSpace(t)
		if trimmed != "" {
			candidates = append(candidates, trimmed)
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	if len(candidates) == 1 {
		return candidates[0]
	}

	if probeURL == "" {
		probeURL = "http://connectivitycheck.gstatic.com/generate_204"
	}
	if timeoutMs <= 0 {
		timeoutMs = 1200
	}

	// Same stripped-down instance as the other probes: no inbounds, routing, geo data or
	// observatory, only what a forced-outbound dial needs.
	server, err := startOutboundTestInstance(configJSON)
	if err != nil {
		return candidates[0]
	}
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()

	type probeResult struct {
		tag     string
		latency int64
		err     error
	}

	resultCh := make(chan probeResult, len(candidates))

	for _, tag := range candidates {
		go func(outboundTag string) {
			tr := &http.Transport{
				TLSHandshakeTimeout: time.Duration(timeoutMs) * time.Millisecond,
				DisableKeepAlives:   true,
				DialContext: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
					d, err := corenet.ParseDestination(fmt.Sprintf("%s:%s", network, addr))
					if err != nil {
						return nil, err
					}
					taggedCtx := session.SetForcedOutboundTagToContext(dialCtx, outboundTag)
					return core.Dial(taggedCtx, server, d)
				},
			}
			defer tr.CloseIdleConnections()

			client := &http.Client{
				Transport: tr,
				Timeout:   time.Duration(timeoutMs) * time.Millisecond,
			}

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
			if err != nil {
				resultCh <- probeResult{tag: outboundTag, latency: -1, err: err}
				return
			}

			start := time.Now()
			resp, err := client.Do(req)
			if err != nil {
				resultCh <- probeResult{tag: outboundTag, latency: -1, err: err}
				return
			}
			_ = resp.Body.Close()

			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
				dur := time.Since(start).Milliseconds()
				resultCh <- probeResult{tag: outboundTag, latency: dur, err: nil}
			} else {
				resultCh <- probeResult{tag: outboundTag, latency: -1, err: fmt.Errorf("bad status: %d", resp.StatusCode)}
			}
		}(tag)
	}

	var fastestTag string
	var lowestLatency int64 = 999999

	received := 0
	for received < len(candidates) {
		select {
		case res := <-resultCh:
			received++
			if res.err == nil && res.latency >= 0 {
				if fastestTag == "" {
					fastestTag = res.tag
					lowestLatency = res.latency
					if res.latency < 350 {
						return fastestTag
					}
				} else if res.latency < lowestLatency {
					fastestTag = res.tag
					lowestLatency = res.latency
				}
			}
		case <-ctx.Done():
			if fastestTag != "" {
				return fastestTag
			}
			return candidates[0]
		}
		if fastestTag != "" && (received >= (len(candidates)+1)/2 || received >= 3) {
			return fastestTag
		}
	}

	if fastestTag != "" {
		return fastestTag
	}
	return candidates[0]
}
