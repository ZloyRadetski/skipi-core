// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/core"

	"github.com/ZloyRadetski/skipi-core/internal/hevtun"
)

type callLog struct {
	mu     sync.Mutex
	events []string
}

func (l *callLog) add(s string) {
	l.mu.Lock()
	l.events = append(l.events, s)
	l.mu.Unlock()
}

func (l *callLog) list() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.events...)
}

func (l *callLog) String() string { return strings.Join(l.list(), ",") }

func (l *callLog) count(s string) int {
	n := 0
	for _, e := range l.list() {
		if e == s {
			n++
		}
	}
	return n
}

// fakeHev stands in for the cgo HEV TUN. stopRelease, when non-nil, makes Stop hang.
type fakeHev struct {
	log         *callLog
	startErr    error
	readyErr    error // returned by every WaitReady slice
	stopRelease chan struct{}
	stopEntered chan struct{}
	// firstWaitGate, when set, holds the first WaitReady until it is closed; that call then
	// reports not ready yet. Later calls are not held.
	firstWaitGate chan struct{}
	waits         atomic.Int32
	// exited, when set, is what Exited returns: closed when hev ended. nil makes the session poll.
	exited chan struct{}
	running     atomic.Bool
	stats       [4]uint64
	gotCfg      atomic.Value
	gotFd       atomic.Int64
	gotExe      atomic.Value
	noFd        bool // a process-mode target: no TUN descriptor is needed
	mac         bool // the macOS target: takes the interface plan, no descriptor
	readyBudget time.Duration
	gotOpts     atomic.Value // hevtun.Options
}

func (f *fakeHev) NeedsTunFd() bool { return !f.noFd && !f.mac }

func (f *fakeHev) NeedsMacInterface() bool { return f.mac }

func (f *fakeHev) ReadyTimeout() time.Duration { return f.readyBudget }

func (f *fakeHev) Start(cfg string, opts hevtun.Options) error {
	f.log.add("hev.start")
	f.gotExe.Store(opts.Executable)
	f.gotCfg.Store(cfg)
	f.gotFd.Store(int64(opts.TunFd))
	f.gotOpts.Store(opts)
	if f.startErr != nil {
		return f.startErr
	}
	f.running.Store(true)
	return nil
}

func (f *fakeHev) WaitReady(timeout time.Duration) error {
	f.log.add("hev.waitReady")
	if f.firstWaitGate != nil && f.waits.Add(1) == 1 {
		<-f.firstWaitGate
		return hevtun.ErrReadyTimeout
	}
	if f.readyErr != nil {
		time.Sleep(min(timeout, 10*time.Millisecond))
		return f.readyErr
	}
	return nil
}

func (f *fakeHev) Stop() error {
	if !f.running.Load() {
		return nil
	}
	f.log.add("hev.stop")
	if f.stopEntered != nil {
		f.stopEntered <- struct{}{}
	}
	if f.stopRelease != nil {
		<-f.stopRelease
	}
	f.running.Store(false)
	return nil
}

func (f *fakeHev) Stats() (uint64, uint64, uint64, uint64) {
	return f.stats[0], f.stats[1], f.stats[2], f.stats[3]
}

func (f *fakeHev) Running() bool { return f.running.Load() }

func (f *fakeHev) Exited() <-chan struct{} {
	if f.exited == nil {
		return nil
	}
	return f.exited
}

type recCore struct {
	log *callLog
}

func (r *recCore) Close() error {
	r.log.add("xray.close")
	return nil
}

// installOrderedFakes fakes AmneziaWG, Xray and HEV TUN, all logging into one call log.
func installOrderedFakes(t *testing.T, hev *fakeHev) *callLog {
	t.Helper()
	log := &callLog{}
	hev.log = log

	installFakeAwg(t, 0)
	awgStart, awgStopOrig := startAmneziaWgFn, awgStop
	startAmneziaWgFn = func(cfg string, port int) error { log.add("awg.start"); return awgStart(cfg, port) }
	awgStop = func(r *AmneziaWgRunner) error { log.add("awg.stop"); return awgStopOrig(r) }

	origCreate, origStart := createCoreInstance, startCoreInstance
	createCoreInstance = func(*core.Config) (coreInstance, error) { return &recCore{log: log}, nil }
	startCoreInstance = func(coreInstance) error { log.add("xray.start"); return nil }

	origHev, origReady := hevTun, hevReadyTimeout
	hevTun = hev
	t.Cleanup(func() {
		createCoreInstance, startCoreInstance = origCreate, origStart
		hevTun, hevReadyTimeout = origHev, origReady
		waitAbandonedZero(t)
	})
	return log
}

const hevTestYAML = "tunnel:\n  mtu: 8500\nsocks5:\n  port: 10808\n"

func hevPlan(t *testing.T, port int, withAwg bool) string {
	t.Helper()
	base := buildPlan(t, port, withAwg)
	yaml, _ := json.Marshal(hevTestYAML)
	return strings.TrimSuffix(base, "}") + fmt.Sprintf(`,"hev":{"configYaml":%s,"tunFd":42}}`, yaml)
}

const winExe = `C:\Program Files\Skipi\hev.exe`

func useHevTarget(t *testing.T, h hevTunnel) {
	t.Helper()
	orig := hevTun
	hevTun = h
	t.Cleanup(func() { hevTun = orig })
}

func hevPlanWith(t *testing.T, hev string) string {
	t.Helper()
	return strings.TrimSuffix(buildPlan(t, 0, false), "}") + `,"hev":` + hev + `}`
}

func TestParseSessionPlanHevTunFdDependsOnTheTarget(t *testing.T) {
	// In-process targets (Android, Linux) need the descriptor Core was given.
	useHevTarget(t, &fakeHev{})
	for _, fd := range []string{"0", "-1"} {
		if _, err := parseSessionPlan(hevPlanWith(t, `{"configYaml":"tunnel: {mtu: 1500}","tunFd":`+fd+`}`)); err == nil ||
			!strings.Contains(err.Error(), "tunFd") {
			t.Errorf("in-process tunFd %s: err = %v, want a tunFd error", fd, err)
		}
	}
	// A process-mode target (Windows) creates the interface itself: 0, -1 and absent are fine.
	useHevTarget(t, &fakeHev{noFd: true})
	exe, _ := json.Marshal(winExe)
	for _, hev := range []string{
		`{"configYaml":"tunnel: {mtu: 1500}","tunFd":-1,"executable":` + string(exe) + `}`,
		`{"configYaml":"tunnel: {mtu: 1500}","tunFd":0,"executable":` + string(exe) + `}`,
		`{"configYaml":"tunnel: {mtu: 1500}","executable":` + string(exe) + `}`,
	} {
		p, err := parseSessionPlan(hevPlanWith(t, hev))
		if err != nil {
			t.Errorf("process mode %s: %v", hev, err)
			continue
		}
		if p.Hev.Executable != winExe {
			t.Errorf("executable = %q", p.Hev.Executable)
		}
	}
	// Blank YAML is rejected everywhere.
	if _, err := parseSessionPlan(hevPlanWith(t, `{"configYaml":" ","tunFd":-1}`)); err == nil {
		t.Error("blank yaml must be rejected")
	}
}

func TestSessionPassesHevExecutableAndRunsProcessModeWithoutFd(t *testing.T) {
	hev := &fakeHev{noFd: true}
	installOrderedFakes(t, hev)
	c := NewCoreController(nil)
	yaml, _ := json.Marshal(hevTestYAML)
	exe, _ := json.Marshal(winExe)
	plan := strings.TrimSuffix(buildPlan(t, reserveLocalPort(t), true), "}") +
		fmt.Sprintf(`,"hev":{"configYaml":%s,"executable":%s}}`, yaml, exe)
	if err := c.StartSession(plan, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.StopLoop() })
	if got := hev.gotExe.Load(); got != winExe {
		t.Fatalf("hev got executable %v", got)
	}
}

func TestParseSessionPlanHev(t *testing.T) {
	useHevTarget(t, &fakeHev{})
	p, err := parseSessionPlan(buildPlan(t, 0, false))
	if err != nil || p.Hev != nil {
		t.Fatalf("plan without hev: hev=%v err=%v", p.Hev, err)
	}
	p, err = parseSessionPlan(hevPlan(t, 0, false))
	if err != nil {
		t.Fatal(err)
	}
	if p.Hev == nil || p.Hev.ConfigYAML != hevTestYAML || p.Hev.TunFd != 42 {
		t.Fatalf("hev = %+v", p.Hev)
	}
	for name, hev := range map[string]string{
		"blank yaml": `{"configYaml":"  ","tunFd":42}`,
		"no fd":      `{"configYaml":"tunnel: {mtu: 1500}","tunFd":0}`,
	} {
		plan := strings.TrimSuffix(buildPlan(t, 0, false), "}") + `,"hev":` + hev + `}`
		if _, err := parseSessionPlan(plan); err == nil || !strings.Contains(err.Error(), "hev") {
			t.Errorf("%s: err = %v, want an error naming hev", name, err)
		}
	}
}

func TestSessionStartAndStopOrderWithHev(t *testing.T) {
	hev := &fakeHev{}
	log := installOrderedFakes(t, hev)
	c := NewCoreController(nil)
	if err := c.StartSession(hevPlan(t, reserveLocalPort(t), true), 0); err != nil {
		t.Fatal(err)
	}
	if got, want := log.String(), "awg.start,xray.start,hev.start,hev.waitReady"; got != want {
		t.Fatalf("start order = %s, want %s", got, want)
	}
	if hev.gotCfg.Load() != hevTestYAML || hev.gotFd.Load() != 42 {
		t.Fatalf("hev got cfg=%v fd=%d", hev.gotCfg.Load(), hev.gotFd.Load())
	}
	if c.State() != SessionRunning || !c.IsRunning() {
		t.Fatalf("state = %d, want running", c.State())
	}
	if err := c.StopLoop(); err != nil {
		t.Fatal(err)
	}
	if got, want := log.String(), "awg.start,xray.start,hev.start,hev.waitReady,hev.stop,xray.close,awg.stop"; got != want {
		t.Fatalf("order = %s, want %s", got, want)
	}
	if hev.Running() || c.State() != SessionIdle {
		t.Fatal("everything must be stopped")
	}
}

func TestSessionWithoutHevNeverTouchesHev(t *testing.T) {
	hev := &fakeHev{}
	log := installOrderedFakes(t, hev)
	c := NewCoreController(nil)
	if err := c.StartSession(buildPlan(t, reserveLocalPort(t), true), 0); err != nil {
		t.Fatal(err)
	}
	if err := c.StopLoop(); err != nil {
		t.Fatal(err)
	}
	if got, want := log.String(), "awg.start,xray.start,xray.close,awg.stop"; got != want {
		t.Fatalf("order = %s, want %s", got, want)
	}
}

func TestSessionHevNotReadyRollsBackEverything(t *testing.T) {
	hev := &fakeHev{readyErr: hevtun.ErrReadyTimeout}
	log := installOrderedFakes(t, hev)
	hevReadyTimeout = 80 * time.Millisecond
	c := NewCoreController(nil)
	err := c.StartSession(hevPlan(t, reserveLocalPort(t), true), 0)
	if err == nil || !strings.Contains(err.Error(), "HEV TUN") || !strings.Contains(err.Error(), "ready") {
		t.Fatalf("err = %v, want a HEV TUN readiness error", err)
	}
	ev := log.list()
	if len(ev) < 3 || strings.Join(ev[len(ev)-3:], ",") != "hev.stop,xray.close,awg.stop" {
		t.Fatalf("rollback must run in reverse: %v", ev)
	}
	if c.State() != SessionIdle || c.IsRunning() || hev.Running() {
		t.Fatalf("state=%d running=%v hev=%v, want all idle", c.State(), c.IsRunning(), hev.Running())
	}
	if IsAmneziaWgRunning() {
		t.Fatal("AmneziaWG must be stopped")
	}
}

func TestSessionHevStartErrorRollsBack(t *testing.T) {
	hev := &fakeHev{startErr: errors.New("config rejected")}
	log := installOrderedFakes(t, hev)
	c := NewCoreController(nil)
	err := c.StartSession(hevPlan(t, reserveLocalPort(t), true), 0)
	if err == nil || !strings.Contains(err.Error(), "HEV TUN") || !strings.Contains(err.Error(), "config rejected") {
		t.Fatalf("err = %v", err)
	}
	if got, want := log.String(), "awg.start,xray.start,hev.start,xray.close,awg.stop"; got != want {
		t.Fatalf("order = %s, want %s", got, want)
	}
	if c.State() != SessionIdle {
		t.Fatalf("state = %d", c.State())
	}
}

func TestSessionHevExitedEarlyFailsStart(t *testing.T) {
	hev := &fakeHev{readyErr: hevtun.ErrExited}
	installOrderedFakes(t, hev)
	c := NewCoreController(nil)
	err := c.StartSession(hevPlan(t, 0, false), 0)
	if err == nil || !strings.Contains(err.Error(), "HEV TUN") {
		t.Fatalf("err = %v", err)
	}
	if c.State() != SessionIdle {
		t.Fatal("must be idle")
	}
}

func TestSessionStopHevHangIsBoundedAndCounted(t *testing.T) {
	hev := &fakeHev{stopRelease: make(chan struct{}), stopEntered: make(chan struct{}, 2)}
	log := installOrderedFakes(t, hev)
	c := NewCoreController(nil)
	if err := c.StartSession(hevPlan(t, reserveLocalPort(t), true), 0); err != nil {
		t.Fatal(err)
	}
	var err error
	within(t, 3*time.Second, "StopLoopWithTimeout", func() { err = c.StopLoopWithTimeout(100) })
	if !errors.Is(err, ErrStopTimedOut) || !strings.Contains(err.Error(), "HEV TUN") {
		t.Fatalf("err = %v, want ErrStopTimedOut naming HEV TUN", err)
	}
	waitSignal(t, hev.stopEntered, "hev Stop")
	if AbandonedInstances() != 1 {
		t.Fatalf("abandoned = %d, want 1", AbandonedInstances())
	}
	if log.count("xray.close") != 1 || log.count("awg.stop") != 1 {
		t.Fatalf("xray and awg must still be stopped: %s", log)
	}
	if c.State() != SessionIdle {
		t.Fatal("controller must be idle")
	}
	close(hev.stopRelease)
	waitAbandonedZero(t)
}

func TestForceStopCoversHev(t *testing.T) {
	hev := &fakeHev{}
	log := installOrderedFakes(t, hev)
	c := NewCoreController(nil)
	if err := c.StartSession(hevPlan(t, reserveLocalPort(t), true), 0); err != nil {
		t.Fatal(err)
	}
	if err := c.ForceStop(); err != nil {
		t.Fatal(err)
	}
	if got, want := log.String(), "awg.start,xray.start,hev.start,hev.waitReady,hev.stop,xray.close,awg.stop"; got != want {
		t.Fatalf("order = %s, want %s", got, want)
	}
}

func TestForceStopWithHungHevReturnsInTime(t *testing.T) {
	hev := &fakeHev{stopRelease: make(chan struct{}), stopEntered: make(chan struct{}, 2)}
	installOrderedFakes(t, hev)
	origForce := forceStopTimeout
	forceStopTimeout = 100 * time.Millisecond
	t.Cleanup(func() { forceStopTimeout = origForce })
	c := NewCoreController(nil)
	if err := c.StartSession(hevPlan(t, 0, false), 0); err != nil {
		t.Fatal(err)
	}
	var err error
	within(t, 3*time.Second, "ForceStop", func() { err = c.ForceStop() })
	if !errors.Is(err, ErrStopTimedOut) {
		t.Fatalf("err = %v, want ErrStopTimedOut", err)
	}
	waitSignal(t, hev.stopEntered, "hev Stop")
	close(hev.stopRelease)
	waitAbandonedZero(t)
}

func TestForceStopDuringHevReadinessAbortsStart(t *testing.T) {
	hev := &fakeHev{readyErr: hevtun.ErrReadyTimeout}
	log := installOrderedFakes(t, hev)
	hevReadyTimeout = 10 * time.Second
	c := NewCoreController(nil)
	startErr := make(chan error, 1)
	go func() { startErr <- c.StartSession(hevPlan(t, reserveLocalPort(t), true), 0) }()
	deadline := time.Now().Add(3 * time.Second)
	for log.count("hev.waitReady") == 0 {
		if time.Now().After(deadline) {
			t.Fatal("hev readiness wait never began")
		}
		time.Sleep(2 * time.Millisecond)
	}
	within(t, 3*time.Second, "ForceStop", func() { _ = c.ForceStop() })
	select {
	case err := <-startErr:
		if err == nil {
			t.Fatal("aborted start must return an error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("StartSession did not return after ForceStop")
	}
	if hev.Running() || IsAmneziaWgRunning() || log.count("xray.close") != 1 {
		t.Fatalf("nothing may be left running: hev=%v log=%s", hev.Running(), log)
	}
}

func TestQueryTunnelStatsJSON(t *testing.T) {
	hev := &fakeHev{stats: [4]uint64{1, 2, 3, 4}}
	installOrderedFakes(t, hev)
	c := NewCoreController(nil)

	var zero map[string]uint64
	if err := json.Unmarshal([]byte(c.QueryTunnelStats()), &zero); err != nil {
		t.Fatal(err)
	}
	if len(zero) != 4 || zero["txPackets"]|zero["txBytes"]|zero["rxPackets"]|zero["rxBytes"] != 0 {
		t.Fatalf("idle stats = %v, want four zeros", zero)
	}

	if err := c.StartSession(hevPlan(t, 0, false), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.StopLoop() })
	got := c.QueryTunnelStats()
	if want := `{"txPackets":1,"txBytes":2,"rxPackets":3,"rxBytes":4}`; got != want {
		t.Fatalf("QueryTunnelStats = %s, want %s", got, want)
	}
}

// A HEV TUN that dies under a running session leaves a tunnel that drops every packet; the
// session must notice, stop Xray and AmneziaWG, and report Idle with the reason.
func TestSessionStopsItselfWhenHevExits(t *testing.T) {
	hev := &fakeHev{}
	log := installOrderedFakes(t, hev)
	origWatch := hevWatchInterval
	hevWatchInterval = 10 * time.Millisecond
	t.Cleanup(func() { hevWatchInterval = origWatch })

	listener := &recordingListener{}
	c := NewCoreController(nil)
	c.SetStateListener(listener)
	if err := c.StartSession(hevPlan(t, reserveLocalPort(t), true), 0); err != nil {
		t.Fatal(err)
	}

	hev.running.Store(false) // hev main returned on its own

	deadline := time.Now().Add(2 * time.Second)
	for c.State() != SessionIdle {
		if time.Now().After(deadline) {
			t.Fatalf("state = %d, want idle after hev exited", c.State())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if log.count("xray.close") != 1 || log.count("awg.stop") != 1 {
		t.Fatalf("Xray and AmneziaWG must be stopped once, log = %s", log)
	}
	events := listener.snapshot()
	last := events[len(events)-1]
	if last.state != SessionIdle || !strings.Contains(last.detail, "HEV TUN exited") {
		t.Fatalf("last event = %+v, want idle with the HEV TUN exit reason", last)
	}
}

// A normal stop must not race the watcher into a second stop.
func TestHevWatcherIgnoresANormalStop(t *testing.T) {
	hev := &fakeHev{}
	log := installOrderedFakes(t, hev)
	origWatch := hevWatchInterval
	hevWatchInterval = 5 * time.Millisecond
	t.Cleanup(func() { hevWatchInterval = origWatch })

	c := NewCoreController(nil)
	if err := c.StartSession(hevPlan(t, reserveLocalPort(t), true), 0); err != nil {
		t.Fatal(err)
	}
	if err := c.StopLoop(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if log.count("xray.close") != 1 {
		t.Fatalf("xray closed %d times, want 1 (log %s)", log.count("xray.close"), log)
	}
}

const macRunDir = "/Users/u/SKIPI/run"
const macExe = "/Applications/SKIPI.app/Contents/Resources/hev/hev-socks5-tunnel"

func macHevBlock(t *testing.T, mut func(m map[string]any)) string {
	t.Helper()
	hev := map[string]any{
		"configYaml":   hevTestYAML,
		"executable":   macExe,
		"runDirectory": macRunDir,
		"macInterface": map[string]any{
			"name": "utun9", "mtu": 1500,
			"addresses": []string{"198.18.0.1/15", "fc00::1/64"},
			"routes":    []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"},
			"dns":       []string{"1.1.1.1"},
		},
	}
	if mut != nil {
		mut(hev)
	}
	b, err := json.Marshal(hev)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParseSessionPlanMacOSHevBlock(t *testing.T) {
	useHevTarget(t, &fakeHev{mac: true})
	// No tunFd at all is fine on macOS.
	p, err := parseSessionPlan(hevPlanWith(t, macHevBlock(t, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if p.Hev.Executable != macExe || p.Hev.RunDirectory != macRunDir {
		t.Fatalf("hev = %+v", p.Hev)
	}
	m := p.Hev.MacInterface
	if m == nil || m.Name != "utun9" || m.MTU != 1500 || len(m.Addresses) != 2 || len(m.Routes) != 4 || len(m.DNS) != 1 {
		t.Fatalf("macInterface = %+v", m)
	}
}

func TestParseSessionPlanMacOSRejectsAnInvalidBlockBeforeAnythingStarts(t *testing.T) {
	useHevTarget(t, &fakeHev{mac: true})
	iface := func(m map[string]any) map[string]any { return m["macInterface"].(map[string]any) }
	cases := map[string]func(m map[string]any){
		"executable":   func(m map[string]any) { delete(m, "executable") },
		"runDirectory": func(m map[string]any) { m["runDirectory"] = " " },
		"macInterface": func(m map[string]any) { delete(m, "macInterface") },
		"name":         func(m map[string]any) { iface(m)["name"] = "" },
		"IPv4":         func(m map[string]any) { iface(m)["addresses"] = []string{"fc00::1/64"} },
		"mtu":          func(m map[string]any) { iface(m)["mtu"] = 0 },
		"route":        func(m map[string]any) { iface(m)["routes"] = []string{"0.0.0.0/1; reboot"} },
		"no routes":    func(m map[string]any) { iface(m)["routes"] = []string{} },
	}
	for name, mut := range cases {
		if _, err := parseSessionPlan(hevPlanWith(t, macHevBlock(t, mut))); err == nil {
			t.Errorf("%s: invalid plan accepted", name)
		}
	}
}

func TestMacOSPlanFieldsReachTheTunnelAndNoDescriptorIsNeeded(t *testing.T) {
	hev := &fakeHev{mac: true}
	installOrderedFakes(t, hev)
	c := NewCoreController(nil)
	plan := hevPlanWith(t, macHevBlock(t, nil))
	if err := c.StartSession(plan, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.StopLoop() })
	opts, _ := hev.gotOpts.Load().(hevtun.Options)
	if opts.Executable != macExe || opts.RunDirectory != macRunDir || opts.TunFd != 0 {
		t.Fatalf("opts = %+v", opts)
	}
	if opts.MacInterface == nil || opts.MacInterface.Name != "utun9" || opts.MacInterface.MTU != 1500 ||
		len(opts.MacInterface.Routes) != 4 {
		t.Fatalf("macInterface = %+v", opts.MacInterface)
	}
}

// The macOS supervisor may need longer than the session's default readiness wait (the prompt is
// answered before Start returns, hev and the routes follow): the target's own budget extends it.
func TestSessionWaitsForTheTargetsOwnReadyBudget(t *testing.T) {
	hev := &fakeHev{mac: true, readyBudget: 2 * time.Second, readyErr: hevtun.ErrReadyTimeout}
	installOrderedFakes(t, hev)
	orig := hevReadyTimeout
	hevReadyTimeout = 50 * time.Millisecond
	t.Cleanup(func() { hevReadyTimeout = orig })
	c := NewCoreController(nil)
	done := make(chan error, 1)
	go func() { done <- c.StartSession(hevPlanWith(t, macHevBlock(t, nil)), 0) }()
	time.Sleep(300 * time.Millisecond) // well past the session default, within the target budget
	hev.readyErr = nil
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("StartSession = %v; the start must wait for the target's budget", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("StartSession did not return")
	}
	t.Cleanup(func() { _ = c.StopLoop() })
}

// On macOS Running() turns false when the supervisor's ready file is gone; the session stops itself.
func TestMacOSSessionStopsItselfWhenTheSupervisorIsGone(t *testing.T) {
	hev := &fakeHev{mac: true}
	installOrderedFakes(t, hev)
	origWatch := hevWatchInterval
	hevWatchInterval = 10 * time.Millisecond
	t.Cleanup(func() { hevWatchInterval = origWatch })
	listener := &recordingListener{}
	c := NewCoreController(nil)
	c.SetStateListener(listener)
	if err := c.StartSession(hevPlanWith(t, macHevBlock(t, nil)), 0); err != nil {
		t.Fatal(err)
	}
	hev.running.Store(false)
	deadline := time.Now().Add(2 * time.Second)
	for c.State() != SessionIdle {
		if time.Now().After(deadline) {
			t.Fatalf("state = %d, want idle", c.State())
		}
		time.Sleep(5 * time.Millisecond)
	}
	events := listener.snapshot()
	if last := events[len(events)-1]; !strings.Contains(last.detail, "HEV TUN exited") {
		t.Fatalf("last event = %+v", last)
	}
}

// C2: hev scripts and pid-file never reach hev, and a privileged hev never sees a log-file path.
func TestSessionPlanRefusesHevKeysThatRunOrWriteAnything(t *testing.T) {
	for _, target := range []*fakeHev{{}, {noFd: true}} {
		useHevTarget(t, target)
		for _, yaml := range []string{
			"tunnel:\n  mtu: 1500\n  post-up-script: /tmp/x\n",
			"tunnel:\n  pre-down-script: /tmp/x\n",
			"misc:\n  pid-file: /etc/sudoers\n",
		} {
			y, _ := json.Marshal(yaml)
			_, err := parseSessionPlan(hevPlanWith(t, `{"configYaml":`+string(y)+`,"tunFd":42,"executable":"/opt/hev"}`))
			if err == nil || !strings.Contains(err.Error(), "not allowed") {
				t.Errorf("%q: err = %v", yaml, err)
			}
		}
	}
}

func TestProcessModeHevGetsNoLogFile(t *testing.T) {
	hev := &fakeHev{noFd: true}
	installOrderedFakes(t, hev)
	c := NewCoreController(nil)
	yaml, _ := json.Marshal(hevTestYAML + "misc:\n  log-file: /etc/sudoers\n  log-level: warn\n")
	exe, _ := json.Marshal(winExe)
	plan := strings.TrimSuffix(buildPlan(t, reserveLocalPort(t), true), "}") +
		fmt.Sprintf(`,"hev":{"configYaml":%s,"executable":%s}}`, yaml, exe)
	if err := c.StartSession(plan, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.StopLoop() })
	got, _ := hev.gotCfg.Load().(string)
	if strings.Contains(got, "log-file") || !strings.Contains(got, "log-level: warn") {
		t.Fatalf("hev got:\n%s", got)
	}
}

// Perf 8: where the target reports hev's exit on a channel, the session waits on it: no wake-up
// every second, and the stop follows the exit at once.
func TestSessionWaitsOnTheHevExitInsteadOfPolling(t *testing.T) {
	hev := &fakeHev{exited: make(chan struct{})}
	installOrderedFakes(t, hev)
	origWatch := hevWatchInterval
	hevWatchInterval = time.Hour // a poll would never notice in time
	t.Cleanup(func() { hevWatchInterval = origWatch })

	c := NewCoreController(nil)
	if err := c.StartSession(hevPlan(t, reserveLocalPort(t), false), 0); err != nil {
		t.Fatal(err)
	}
	hev.running.Store(false)
	close(hev.exited)
	deadline := time.Now().Add(2 * time.Second)
	for c.State() != SessionIdle {
		if time.Now().After(deadline) {
			t.Fatalf("state = %d, want idle right after hev exited", c.State())
		}
		time.Sleep(5 * time.Millisecond)
	}
}
