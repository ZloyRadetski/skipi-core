// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package desktopbridge

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	skipicore "github.com/ZloyRadetski/skipi-core"
	"github.com/ZloyRadetski/skipi-core/internal/hevpayload"
	"github.com/xtls/xray-core/transport/internet"
)

func TestRuntimeRequiresAssetsBeforeStart(t *testing.T) {
	runtime := NewRuntime()
	handle := runtime.CreateController()

	err := runtime.Start(handle, testXrayConfig(t), 0)
	if !errors.Is(err, ErrAssetsNotInitialized) {
		t.Fatalf("expected uninitialized-assets error, got %v", err)
	}
}

func TestRuntimeRejectsInvalidAssetDirectory(t *testing.T) {
	runtime := NewRuntime()
	if err := runtime.InitializeAssets(" "); err == nil {
		t.Fatal("expected blank asset directory to be rejected")
	}
	if err := runtime.InitializeAssets(t.TempDir() + "/missing"); err == nil {
		t.Fatal("expected missing asset directory to be rejected")
	}
}

func TestRuntimeStartQueryAndStop(t *testing.T) {
	runtime := initializedRuntime(t)
	handle := runtime.CreateController()
	t.Cleanup(func() {
		_ = runtime.DestroyController(handle)
	})

	if err := runtime.Start(handle, testXrayConfig(t), 0); err != nil {
		t.Fatalf("start core: %v", err)
	}
	if runtime.ActiveHandle() != handle {
		t.Fatalf("active handle = %d, want %d", runtime.ActiveHandle(), handle)
	}
	running, err := runtime.IsRunning(handle)
	if err != nil {
		t.Fatalf("read running state: %v", err)
	}
	if !running {
		t.Fatal("expected started core to be running")
	}

	stats, err := runtime.QueryTrafficStats(handle)
	if err != nil {
		t.Fatalf("query traffic stats: %v", err)
	}
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stats), &parsed); err != nil {
		t.Fatalf("traffic stats are not JSON: %v; value=%q", err, stats)
	}
	if parsed["inbound"] == nil || parsed["outbound"] == nil {
		t.Fatalf("unexpected traffic stats shape: %s", stats)
	}

	if err := runtime.Stop(handle); err != nil {
		t.Fatalf("stop core: %v", err)
	}
	running, err = runtime.IsRunning(handle)
	if err != nil {
		t.Fatalf("read stopped state: %v", err)
	}
	if running {
		t.Fatal("expected stopped core to be inactive")
	}
	if runtime.ActiveHandle() != 0 {
		t.Fatalf("active handle = %d after stop, want 0", runtime.ActiveHandle())
	}
}

func TestRuntimeAllowsOnlyOneActiveController(t *testing.T) {
	runtime := initializedRuntime(t)
	first := runtime.CreateController()
	second := runtime.CreateController()
	t.Cleanup(func() {
		_ = runtime.DestroyController(first)
		_ = runtime.DestroyController(second)
	})

	if err := runtime.Start(first, testXrayConfig(t), 0); err != nil {
		t.Fatalf("start first controller: %v", err)
	}
	err := runtime.Start(second, testXrayConfig(t), 0)
	if !errors.Is(err, ErrAnotherControllerActive) {
		t.Fatalf("expected active-controller error, got %v", err)
	}
}

func TestRuntimeProcessLeaseIsSharedAcrossRuntimeInstances(t *testing.T) {
	firstRuntime := initializedRuntime(t)
	first := firstRuntime.CreateController()
	secondRuntime := NewRuntime()
	second := secondRuntime.CreateController()
	t.Cleanup(func() {
		_ = firstRuntime.DestroyController(first)
		_ = secondRuntime.DestroyController(second)
	})

	if err := firstRuntime.Start(first, testXrayConfig(t), 0); err != nil {
		t.Fatalf("start first runtime: %v", err)
	}
	if err := secondRuntime.InitializeAssets(t.TempDir()); err == nil {
		t.Fatal("expected asset replacement while another runtime is active to fail")
	}
	err := secondRuntime.Start(second, testXrayConfig(t), 0)
	if !errors.Is(err, ErrAssetsNotInitialized) {
		t.Fatalf("expected second runtime to require its own assets, got %v", err)
	}

	if err := firstRuntime.Stop(first); err != nil {
		t.Fatalf("stop first runtime: %v", err)
	}
	if err := secondRuntime.InitializeAssets(t.TempDir()); err != nil {
		t.Fatalf("initialize second runtime after handover: %v", err)
	}
	if err := secondRuntime.Start(second, testXrayConfig(t), 0); err != nil {
		t.Fatalf("start second runtime after handover: %v", err)
	}
}

func TestDestroyControllerStopsActiveCore(t *testing.T) {
	runtime := initializedRuntime(t)
	handle := runtime.CreateController()
	if err := runtime.Start(handle, testXrayConfig(t), 0); err != nil {
		t.Fatalf("start controller: %v", err)
	}
	if err := runtime.DestroyController(handle); err != nil {
		t.Fatalf("destroy active controller: %v", err)
	}
	if runtime.ActiveHandle() != 0 {
		t.Fatalf("active handle = %d after destroy, want 0", runtime.ActiveHandle())
	}
	if _, err := runtime.IsRunning(handle); !errors.Is(err, ErrControllerNotFound) {
		t.Fatalf("expected destroyed handle error, got %v", err)
	}
}

// A delay probe can take seconds; the UI must still be able to read the state and disconnect meanwhile.
func TestStopAndStateAreNotBlockedByARunningDelayProbe(t *testing.T) {
	runtime := initializedRuntime(t)
	handle := runtime.CreateController()
	t.Cleanup(func() {
		_ = runtime.DestroyController(handle)
	})
	if err := runtime.Start(handle, testXrayConfig(t), 0); err != nil {
		t.Fatalf("start core: %v", err)
	}

	probeStarted := make(chan struct{})
	releaseProbe := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case probeStarted <- struct{}{}:
		default:
		}
		<-releaseProbe
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	defer close(releaseProbe)

	go func() { _, _ = runtime.MeasureDelay(handle, server.URL) }()
	select {
	case <-probeStarted:
	case <-time.After(10 * time.Second):
		t.Fatal("the delay probe never reached the test server")
	}

	stopped := make(chan error, 1)
	go func() {
		if _, err := runtime.IsRunning(handle); err != nil {
			stopped <- err
			return
		}
		stopped <- runtime.Stop(handle)
	}()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("state read / stop during a probe: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("IsRunning/Stop are blocked while a delay probe is in flight")
	}
}

func initializedRuntime(t *testing.T) *Runtime {
	t.Helper()
	runtime := NewRuntime()
	if err := runtime.InitializeAssets(t.TempDir()); err != nil {
		t.Fatalf("initialize assets: %v", err)
	}
	return runtime
}

func testXrayConfig(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve local port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("release local port: %v", err)
	}
	return fmt.Sprintf(
		"{\"log\":{\"loglevel\":\"none\"},\"inbounds\":[{\"listen\":\"127.0.0.1\",\"port\":%d,\"protocol\":\"http\",\"settings\":{}}],\"outbounds\":[{\"protocol\":\"freedom\",\"tag\":\"direct\"}]}",
		port,
	)
}

const testAmneziaWgConfig = `{
	"secretKey": "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZhbGlkIGtleSE=",
	"address": ["10.8.0.2/32"],
	"dnsServers": ["1.1.1.1"],
	"peers": [
		{
			"publicKey": "YW5vdGhlciB2YWxpZCBrZXkgZm9yIHRlc3Rpbmcgb2s=",
			"endpoint": "127.0.0.1:59999",
			"allowedIPs": ["0.0.0.0/0"]
		}
	],
	"jc": 3,
	"jmin": 40,
	"jmax": 70,
	"s1": 15,
	"s2": 25,
	"h1": "12345"
}`

func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func TestAmneziaWgBridgeStartsServesSocksAndStops(t *testing.T) {
	runtime := NewRuntime()
	port := freeLoopbackPort(t)
	t.Cleanup(func() { _ = runtime.StopAmneziaWg() })

	if runtime.IsAmneziaWgRunning() {
		t.Fatal("AmneziaWG must not be running before it is started")
	}
	if err := runtime.StartAmneziaWg(testAmneziaWgConfig, port); err != nil {
		t.Fatalf("StartAmneziaWg failed: %v", err)
	}
	if !runtime.IsAmneziaWgRunning() {
		t.Fatal("AmneziaWG should be running after a successful start")
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("the SOCKS listener must accept connections: %v", err)
	}
	_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
	reply := make([]byte, 2)
	_, _ = conn.Read(reply)
	conn.Close()
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("unexpected SOCKS handshake reply: %v", reply)
	}

	if err := runtime.StopAmneziaWg(); err != nil {
		t.Fatalf("StopAmneziaWg failed: %v", err)
	}
	if runtime.IsAmneziaWgRunning() {
		t.Fatal("AmneziaWG should be stopped")
	}
	if err := runtime.StopAmneziaWg(); err != nil {
		t.Fatalf("stopping a stopped AmneziaWG must not fail: %v", err)
	}
}

func TestAmneziaWgBridgeRejectsBadConfigAndStaysStopped(t *testing.T) {
	runtime := NewRuntime()
	t.Cleanup(func() { _ = runtime.StopAmneziaWg() })

	if err := runtime.StartAmneziaWg("{not json", freeLoopbackPort(t)); err == nil {
		t.Fatal("an invalid configuration must be rejected")
	}
	if err := runtime.StartAmneziaWg(testAmneziaWgConfig, 0); err == nil {
		t.Fatal("a missing SOCKS port must be rejected")
	}
	if runtime.IsAmneziaWgRunning() {
		t.Fatal("a rejected start must leave AmneziaWG stopped")
	}
}

func TestMeasureOutboundDelayReachesTheTargetThroughTheGivenOutbound(t *testing.T) {
	runtime := NewRuntime()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	delay, err := runtime.MeasureOutboundDelay(
		`{"log":{"loglevel":"none"},"outbounds":[{"tag":"probe","protocol":"freedom"}]}`,
		server.URL,
	)
	if err != nil {
		t.Fatalf("MeasureOutboundDelay failed: %v", err)
	}
	if delay < 0 {
		t.Fatalf("expected a non-negative delay, got %d", delay)
	}
}

func TestMeasureOutboundDelayRejectsBlankInputAndBadConfig(t *testing.T) {
	runtime := NewRuntime()

	if _, err := runtime.MeasureOutboundDelay("{}", " "); err == nil {
		t.Fatal("a blank target must be rejected")
	}
	if _, err := runtime.MeasureOutboundDelay(" ", "http://127.0.0.1:1/"); err == nil {
		t.Fatal("a blank configuration must be rejected")
	}
	if _, err := runtime.MeasureOutboundDelay("{not json", "http://127.0.0.1:1/"); err == nil {
		t.Fatal("an invalid configuration must be rejected")
	}
}

// dialedAddresses records every destination Core's own dialer was asked for. Xray's controller
// registry is a process-wide slice that its dialers read without a lock and that cannot be undone,
// so the one recorder is registered in TestMain, before any test (and any goroutine a test leaves
// dialing in the background) exists. Registering it from inside a test raced with such dials.
var (
	dialedMu        sync.Mutex
	dialedAddresses []string
)

func TestMain(m *testing.M) {
	if err := internet.RegisterDialerController(func(network, address string, c syscall.RawConn) error {
		dialedMu.Lock()
		dialedAddresses = append(dialedAddresses, address)
		dialedMu.Unlock()
		return nil
	}); err != nil {
		fmt.Fprintf(os.Stderr, "register dialer controller: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func recordedDials(t *testing.T) func() []string {
	t.Helper()
	return func() []string {
		dialedMu.Lock()
		defer dialedMu.Unlock()
		return append([]string(nil), dialedAddresses...)
	}
}

func TestMeasureTcpDelayConnectsToAListeningPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	delay, err := NewRuntime().MeasureTcpDelay("127.0.0.1", port, 2000)
	if err != nil {
		t.Fatalf("MeasureTcpDelay failed: %v", err)
	}
	if delay < 0 || delay > 2000 {
		t.Fatalf("delay = %d ms, want within the timeout", delay)
	}
}

func TestMeasureTcpDelayDialsThroughTheControllersThatKeepSocketsOffTheTunnel(t *testing.T) {
	dialed := recordedDials(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	address := listener.Addr().String()
	port := listener.Addr().(*net.TCPAddr).Port

	if _, err := NewRuntime().MeasureTcpDelay("127.0.0.1", port, 2000); err != nil {
		t.Fatalf("MeasureTcpDelay failed: %v", err)
	}

	for _, seen := range dialed() {
		if seen == address {
			return
		}
	}
	t.Fatalf("the probe never reached the dialer controllers (the physical-interface binding); saw %v", dialed())
}

func TestMeasureTcpDelayReportsAnUnreachablePortAsAnError(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	delay, err := NewRuntime().MeasureTcpDelay("127.0.0.1", port, 2000)
	if err == nil || delay != -1 {
		t.Fatalf("closed port: delay=%d err=%v, want -1 and an error", delay, err)
	}
}

func TestMeasureTcpDelayRejectsInvalidInput(t *testing.T) {
	runtime := NewRuntime()
	for name, call := range map[string]func() (int64, error){
		"blank host":        func() (int64, error) { return runtime.MeasureTcpDelay("  ", 443, 1000) },
		"port zero":         func() (int64, error) { return runtime.MeasureTcpDelay("example.org", 0, 1000) },
		"port out of range": func() (int64, error) { return runtime.MeasureTcpDelay("example.org", 70000, 1000) },
		"no timeout":        func() (int64, error) { return runtime.MeasureTcpDelay("example.org", 443, 0) },
	} {
		if delay, err := call(); err == nil || delay != -1 {
			t.Errorf("%s: delay=%d err=%v, want -1 and an error", name, delay, err)
		}
	}
}

func TestConnectionLogIsReachableThroughAHandleOnly(t *testing.T) {
	runtime := NewRuntime()
	handle := runtime.CreateController()

	if err := runtime.SetConnectionLogEnabled(handle, true); err != nil {
		t.Fatalf("enable connection log: %v", err)
	}
	snapshot, err := runtime.ReadConnectionLog(handle, 0)
	if err != nil {
		t.Fatalf("read connection log: %v", err)
	}
	if snapshot != `{"seq":0,"entries":[]}` {
		t.Fatalf("unexpected snapshot: %s", snapshot)
	}

	unknown := handle + 1000
	if err := runtime.SetConnectionLogEnabled(unknown, true); !errors.Is(err, ErrControllerNotFound) {
		t.Fatalf("expected ErrControllerNotFound, got %v", err)
	}
	if _, err := runtime.ReadConnectionLog(unknown, 0); !errors.Is(err, ErrControllerNotFound) {
		t.Fatalf("expected ErrControllerNotFound, got %v", err)
	}
}

func TestRuntimeStopWithTimeoutStopsAndReleasesLease(t *testing.T) {
	runtime := initializedRuntime(t)
	handle := runtime.CreateController()
	t.Cleanup(func() { _ = runtime.DestroyController(handle) })

	if err := runtime.Start(handle, testXrayConfig(t), 0); err != nil {
		t.Fatalf("start core: %v", err)
	}
	if err := runtime.StopWithTimeout(handle, 5000); err != nil {
		t.Fatalf("stop with timeout: %v", err)
	}
	if running, _ := runtime.IsRunning(handle); running {
		t.Fatal("expected stopped core to be inactive")
	}
	if runtime.ActiveHandle() != 0 {
		t.Fatalf("active handle = %d after stop, want 0", runtime.ActiveHandle())
	}
	if got := runtime.AbandonedInstances(); got != 0 {
		t.Fatalf("abandoned instances = %d, want 0", got)
	}
}

func TestRuntimeStopWithTimeoutRejectsUnknownHandle(t *testing.T) {
	runtime := initializedRuntime(t)
	if err := runtime.StopWithTimeout(9999, 100); !errors.Is(err, ErrControllerNotFound) {
		t.Fatalf("expected controller-not-found, got %v", err)
	}
}

func TestRuntimeForceStopStopsRunningControllerAndFreesLease(t *testing.T) {
	runtime := initializedRuntime(t)
	first := runtime.CreateController()
	second := runtime.CreateController()
	t.Cleanup(func() {
		_ = runtime.DestroyController(first)
		_ = runtime.DestroyController(second)
	})

	if err := runtime.Start(first, testXrayConfig(t), 0); err != nil {
		t.Fatalf("start core: %v", err)
	}
	if err := runtime.ForceStop(first); err != nil {
		t.Fatalf("force stop: %v", err)
	}
	if running, _ := runtime.IsRunning(first); running {
		t.Fatal("expected force-stopped core to be inactive")
	}
	if runtime.ActiveHandle() != 0 {
		t.Fatalf("active handle = %d after force stop, want 0", runtime.ActiveHandle())
	}
	// The lease is free again: another controller can start.
	if err := runtime.Start(second, testXrayConfig(t), 0); err != nil {
		t.Fatalf("start after force stop: %v", err)
	}
}

func TestRuntimeForceStopIdleControllerAndUnknownHandle(t *testing.T) {
	runtime := initializedRuntime(t)
	handle := runtime.CreateController()
	t.Cleanup(func() { _ = runtime.DestroyController(handle) })

	if err := runtime.ForceStop(handle); err != nil {
		t.Fatalf("force stop of an idle controller: %v", err)
	}
	if err := runtime.ForceStop(9999); !errors.Is(err, ErrControllerNotFound) {
		t.Fatalf("expected controller-not-found, got %v", err)
	}
}

func TestRuntimeAbandonedInstancesStartsAtZero(t *testing.T) {
	if got := NewRuntime().AbandonedInstances(); got != 0 {
		t.Fatalf("abandoned instances = %d, want 0", got)
	}
}

func TestRuntimeStartSessionRunsXrayAndReportsState(t *testing.T) {
	runtime := initializedRuntime(t)
	handle := runtime.CreateController()
	t.Cleanup(func() { _ = runtime.DestroyController(handle) })

	if state, err := runtime.SessionState(handle); err != nil || state != skipicore.SessionIdle {
		t.Fatalf("initial state = %d, %v", state, err)
	}
	plan, _ := json.Marshal(map[string]any{"xrayConfig": testXrayConfig(t)})
	if err := runtime.StartSession(handle, string(plan), 0); err != nil {
		t.Fatalf("start session: %v", err)
	}
	if state, _ := runtime.SessionState(handle); state != skipicore.SessionRunning {
		t.Fatalf("state = %d, want Running", state)
	}
	if runtime.ActiveHandle() != handle {
		t.Fatalf("active handle = %d, want %d", runtime.ActiveHandle(), handle)
	}
	if err := runtime.Stop(handle); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if state, _ := runtime.SessionState(handle); state != skipicore.SessionIdle {
		t.Fatalf("state after stop = %d, want Idle", state)
	}
}

func TestRuntimeStartSessionWithAwgIsStoppedByStop(t *testing.T) {
	runtime := initializedRuntime(t)
	handle := runtime.CreateController()
	t.Cleanup(func() {
		_ = runtime.DestroyController(handle)
		_ = runtime.StopAmneziaWg()
	})
	port := freeLoopbackPort(t)
	plan, _ := json.Marshal(map[string]any{
		"xrayConfig": testXrayConfig(t),
		"amneziaWg":  map[string]any{"config": testAmneziaWgConfig, "socksPort": port},
	})
	if err := runtime.StartSession(handle, string(plan), 0); err != nil {
		t.Fatalf("start session: %v", err)
	}
	if !runtime.IsAmneziaWgRunning() {
		t.Fatal("the session must have started AmneziaWG")
	}
	if err := runtime.Stop(handle); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if runtime.IsAmneziaWgRunning() {
		t.Fatal("Stop must also stop the session's AmneziaWG")
	}
}

func TestRuntimeStartSessionRejectsBadInputAndLeavesLeaseFree(t *testing.T) {
	runtime := initializedRuntime(t)
	handle := runtime.CreateController()
	t.Cleanup(func() { _ = runtime.DestroyController(handle) })

	if err := runtime.StartSession(handle, " ", 0); err == nil {
		t.Fatal("blank plan must be rejected")
	}
	if err := runtime.StartSession(handle, `{"amneziaWg":null}`, 0); err == nil {
		t.Fatal("plan without xrayConfig must be rejected")
	}
	if err := runtime.StartSession(handle, `{"xrayConfig":"{}"}`, -1); err == nil {
		t.Fatal("negative TUN descriptor must be rejected")
	}
	if err := runtime.StartSession(9999, `{"xrayConfig":"{}"}`, 0); !errors.Is(err, ErrControllerNotFound) {
		t.Fatalf("unknown handle: %v", err)
	}
	if runtime.ActiveHandle() != 0 {
		t.Fatalf("a failed start must not take the lease, active = %d", runtime.ActiveHandle())
	}
}

func TestRuntimeSessionStateRejectsUnknownHandle(t *testing.T) {
	if _, err := NewRuntime().SessionState(9999); !errors.Is(err, ErrControllerNotFound) {
		t.Fatalf("expected controller-not-found, got %v", err)
	}
}

func TestRuntimeQueryTunnelStatsIsZeroWithoutATunnelAndRejectsUnknownHandle(t *testing.T) {
	runtime := initializedRuntime(t)
	handle := runtime.CreateController()
	t.Cleanup(func() { _ = runtime.DestroyController(handle) })

	got, err := runtime.QueryTunnelStats(handle)
	if err != nil {
		t.Fatalf("QueryTunnelStats: %v", err)
	}
	if want := `{"txPackets":0,"txBytes":0,"rxPackets":0,"rxBytes":0}`; got != want {
		t.Fatalf("stats = %s, want %s", got, want)
	}
	if _, err := runtime.QueryTunnelStats(handle + 100); !errors.Is(err, ErrControllerNotFound) {
		t.Fatalf("unknown handle: err = %v, want ErrControllerNotFound", err)
	}
}

func TestRuntimeStartSessionAcceptsTheHevBlockAndReportsAFailedTunnelStart(t *testing.T) {
	// A library that carries a hev runtime (the release build on Windows and macOS) would really
	// start it here, which is not a unit test; the release itself checks those builds.
	if files, err := hevpayload.Files(); err == nil && len(files) > 0 && goruntime.GOOS != "linux" {
		t.Skip("this build carries a HEV TUN runtime")
	}
	runtime := initializedRuntime(t)
	handle := runtime.CreateController()
	t.Cleanup(func() { _ = runtime.DestroyController(handle) })

	// Without a runtime in the build (or with an invalid descriptor on Linux) the plan is parsed,
	// HEV TUN is attempted after Xray, its failure is reported by name, and the session lease is
	// released again. An executable in the plan is an old host's and is ignored.
	hev := map[string]any{
		"configYaml": "tunnel:\n  mtu: 1500\n",
		"tunFd":      -1,
		"executable": filepath.Join(t.TempDir(), "missing-hev.exe"),
	}
	plan, _ := json.Marshal(map[string]any{"xrayConfig": testXrayConfig(t), "hev": hev})
	err := runtime.StartSession(handle, string(plan), 0)
	if err == nil {
		_ = runtime.Stop(handle)
		t.Fatal("start must fail: there is no usable HEV TUN")
	}
	if !strings.Contains(err.Error(), "HEV TUN") && !strings.Contains(err.Error(), "tunFd") {
		t.Fatalf("error %q does not name HEV TUN", err)
	}
	if runtime.ActiveHandle() != 0 {
		t.Fatalf("lease still held by %d", runtime.ActiveHandle())
	}
}

// H1: a start that hangs (a slow Xray, the macOS password prompt) must not block the calls that
// are meant to end or watch it.
func TestAHangingStartBlocksNeitherForceStopNorStateReads(t *testing.T) {
	for _, viaSession := range []bool{false, true} {
		runtime := initializedRuntime(t)
		handle := runtime.CreateController()
		other := runtime.CreateController()
		entered := make(chan struct{})
		release := make(chan struct{})
		hang := func(*skipicore.CoreController, string, int64) error {
			close(entered)
			<-release
			return errors.New("aborted")
		}
		origLoop, origSession := startLoop, startSession
		startLoop, startSession = hang, hang
		t.Cleanup(func() { startLoop, startSession = origLoop, origSession })

		startErr := make(chan error, 1)
		go func() {
			if viaSession {
				startErr <- runtime.StartSession(handle, `{"xrayConfig":"{}"}`, 0)
			} else {
				startErr <- runtime.Start(handle, testXrayConfig(t), 0)
			}
		}()
		<-entered

		within := func(name string, f func()) {
			t.Helper()
			done := make(chan struct{})
			go func() { f(); close(done) }()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatalf("%s waited for the hanging start", name)
			}
		}
		within("SessionState", func() { _, _ = runtime.SessionState(handle) })
		within("IsRunning", func() { _, _ = runtime.IsRunning(handle) })
		within("ActiveHandle", func() { _ = runtime.ActiveHandle() })
		within("another Start", func() {
			if err := runtime.Start(other, testXrayConfig(t), 0); !errors.Is(err, ErrAnotherControllerActive) {
				t.Errorf("a second controller must not start while the first is starting: %v", err)
			}
		})
		within("Stop", func() { _ = runtime.Stop(handle) })
		within("ForceStop", func() { _ = runtime.ForceStop(handle) })
		within("a start after the stops", func() {
			if err := runtime.Start(other, testXrayConfig(t), 0); !errors.Is(err, ErrAnotherControllerActive) {
				t.Errorf("the lease belongs to the start in flight until it returns: %v", err)
			}
		})

		close(release)
		if err := <-startErr; err == nil {
			t.Fatal("the aborted start must fail")
		}
		if runtime.ActiveHandle() != 0 {
			t.Fatalf("a failed start must free the lease, active = %d", runtime.ActiveHandle())
		}
	}
}

type recordingProtector struct{}

func (recordingProtector) Protect(int) bool { return true }

// C6: AmneziaWG's peer sockets on the desktop are pinned to the physical interface like Xray's,
// so a session with AmneziaWG and TUN does not loop its own packets back into the tunnel.
func TestSessionAndAwgStartsInstallTheDesktopSocketProtector(t *testing.T) {
	var installed []skipicore.SocketProtector
	origSet, origSession := setAwgProtector, startSession
	setAwgProtector = func(p skipicore.SocketProtector) { installed = append(installed, p) }
	startSession = func(*skipicore.CoreController, string, int64) error { return errors.New("not today") }
	t.Cleanup(func() { setAwgProtector, startSession = origSet, origSession })
	SetSocketProtector(recordingProtector{})
	t.Cleanup(func() { SetSocketProtector(nil) })

	runtime := initializedRuntime(t)
	_ = runtime.StartSession(runtime.CreateController(), `{"xrayConfig":"{}"}`, 0)
	if len(installed) != 1 || installed[0] != (recordingProtector{}) {
		t.Fatalf("installed = %v", installed)
	}
}

func TestMeasureOutboundDelaysReportsEveryTag(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer ts.Close()
	runtime := NewRuntime()
	out, err := runtime.MeasureOutboundDelays(`{"outbounds":[{"protocol":"freedom","tag":"a"},{"protocol":"blackhole","tag":"b"}]}`, "a,b", ts.URL, 3000)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]int64
	if err := json.Unmarshal([]byte(out), &got); err != nil || got["a"] < 0 || got["b"] != -1 {
		t.Fatalf("got %s (%v)", out, err)
	}
	if _, err := runtime.MeasureOutboundDelays(" ", "a", ts.URL, 0); err == nil {
		t.Fatal("a blank config must be rejected")
	}
}
