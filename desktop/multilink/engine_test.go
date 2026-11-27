// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package multilink

import (
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/ZloyRadetski/skipi-core/desktop/multilink/nics"
)

type fakeHost struct {
	mu       sync.Mutex
	nics     []nics.Nic
	skipped  []nics.Skip
	attached *Scheduler
	attaches int
}

func (h *fakeHost) discover() ([]nics.Nic, []nics.Skip, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]nics.Nic(nil), h.nics...), h.skipped, nil
}

func (h *fakeHost) attach(s *Scheduler) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.attached = s
	h.attaches++
}

func (h *fakeHost) current() *Scheduler {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.attached
}

func homeLinks() *fakeHost {
	return &fakeHost{
		nics: []nics.Nic{
			{ID: "{eth}", Name: "Ethernet 2", Index: 19, IP: net.ParseIP("192.168.1.200"), Weight: 1},
			{ID: "{wifi}", Name: "Wi-Fi", Index: 15, IP: net.ParseIP("192.168.168.111"), Weight: 1},
		},
		skipped: []nics.Skip{{Name: "Radmin VPN", Reason: "virtual/VPN adapter"}},
	}
}

func newTestEngine(h *fakeHost) *Engine {
	return NewEngine(EngineConfig{Discover: h.discover, Attach: h.attach, NoLoops: true})
}

func apply(t *testing.T, e *Engine, settings string) {
	t.Helper()
	if err := e.ApplyJSON(settings); err != nil {
		t.Fatalf("ApplyJSON(%s) = %v", settings, err)
	}
}

func TestOffAttachesNothing(t *testing.T) {
	h := homeLinks()
	e := newTestEngine(h)
	apply(t, e, `{"enabled":false}`)
	if h.current() != nil {
		t.Fatal("a scheduler is attached while merging is off")
	}
	if e.Running() {
		t.Fatal("the engine runs while off")
	}
}

func TestOnAttachesTheDiscoveredLinks(t *testing.T) {
	h := homeLinks()
	e := newTestEngine(h)
	apply(t, e, `{"enabled":true}`)
	s := h.current()
	if s == nil || !e.Running() {
		t.Fatal("merging is on but nothing is attached")
	}
	if got := len(s.Snapshot()); got != 2 {
		t.Fatalf("%d links attached, want 2", got)
	}
	e.Stop()
	if h.current() != nil || e.Running() {
		t.Fatal("Stop left the scheduler attached")
	}
}

// Changing a setting while merging runs keeps the scheduler: the open flows and the measured speeds stay.
func TestApplyingAgainKeepsTheScheduler(t *testing.T) {
	h := homeLinks()
	e := newTestEngine(h)
	apply(t, e, `{"enabled":true}`)
	first := h.current()
	apply(t, e, `{"enabled":true,"limits":{"{wifi}":10}}`)
	if h.current() != first || h.attaches != 1 {
		t.Fatalf("a new setting replaced the scheduler (%d attaches)", h.attaches)
	}
	for _, st := range first.Snapshot() {
		if st.ID == "{wifi}" && st.LimitMbps != 10 {
			t.Fatalf("Wi-Fi limit = %v, want 10", st.LimitMbps)
		}
	}
}

func TestExcludedLinksTakeNoFlows(t *testing.T) {
	h := homeLinks()
	e := newTestEngine(h)
	apply(t, e, `{"enabled":true,"excluded":["{wifi}"]}`)
	s := h.current()
	if got := s.Usable(Fam4); got != 1 {
		t.Fatalf("Usable = %d with Wi-Fi excluded, want 1", got)
	}
	apply(t, e, `{"enabled":true}`)
	if got := s.Usable(Fam4); got != 2 {
		t.Fatalf("Usable = %d after Wi-Fi is included again, want 2", got)
	}
}

func TestFixedWeightsTurnMeasuringOff(t *testing.T) {
	h := homeLinks()
	e := newTestEngine(h)
	apply(t, e, `{"enabled":true,"weights":{"{eth}":3}}`)
	s := h.current()
	picks := map[string]int{}
	for range 8 {
		picks[s.AcquireFor(Fam4, nil).ID]++
	}
	if picks["{eth}"] != 6 || picks["{wifi}"] != 2 {
		t.Fatalf("8 open flows went %v, want 6 on the link weighted 3 and 2 on the other", picks)
	}
}

func TestPhonesAreMarkedByID(t *testing.T) {
	h := homeLinks()
	e := newTestEngine(h)
	apply(t, e, `{"enabled":true,"phones":["{wifi}"],"phoneCooling":true,"coolMbps":5}`)
	s := h.current()
	for _, st := range s.Snapshot() {
		if st.Phone != (st.ID == "{wifi}") {
			t.Fatalf("%s phone = %v", st.ID, st.Phone)
		}
	}
	if !s.PhoneCooling() || s.CoolRate() != 5 {
		t.Fatalf("cooling %v at %v, want on at 5", s.PhoneCooling(), s.CoolRate())
	}
}

func TestProbeTargetsAreChecked(t *testing.T) {
	e := newTestEngine(homeLinks())
	for _, bad := range []string{
		`{"enabled":true,"probeTargets":["example.com:443"]}`,
		`{"enabled":true,"probeTargets":["1.1.1.1"]}`,
		`{"enabled":true,"probeTargets":["1.1.1.1:0"]}`,
		`{"enabled":true,"limits":{"{eth}":-1}}`,
		`{"enabled":true,"weights":{"{eth}":0}}`,
		`{"enabled":`,
	} {
		if err := e.ApplyJSON(bad); err == nil {
			t.Errorf("ApplyJSON(%s) accepted it", bad)
		}
	}
	apply(t, e, `{"enabled":true,"probeTargets":["77.88.8.8:443","[2a02:6b8::feed:0ff]:443"]}`)
	if got := e.Scheduler().ProbeTargets(Fam4); len(got) != 1 || got[0] != "77.88.8.8:443" {
		t.Fatalf("IPv4 probe targets = %v", got)
	}
	if got := e.Scheduler().ProbeTargets(Fam6); len(got) != 1 {
		t.Fatalf("IPv6 probe targets = %v", got)
	}
}

// A setting that is refused leaves what was running as it was.
func TestRefusedSettingsKeepTheRunningOnes(t *testing.T) {
	h := homeLinks()
	e := newTestEngine(h)
	apply(t, e, `{"enabled":true,"limits":{"{eth}":20}}`)
	if err := e.ApplyJSON(`{"enabled":true,"limits":{"{eth}":-5}}`); err == nil {
		t.Fatal("a negative limit was accepted")
	}
	if h.current() == nil {
		t.Fatal("a refused setting switched merging off")
	}
	for _, st := range h.current().Snapshot() {
		if st.ID == "{eth}" && st.LimitMbps != 20 {
			t.Fatalf("limit = %v after a refused change, want 20", st.LimitMbps)
		}
	}
}

func TestStatusDescribesLinksAndSkippedAdapters(t *testing.T) {
	h := homeLinks()
	e := newTestEngine(h)
	off := e.StatusJSON()
	if !strings.Contains(off, `"enabled":false`) {
		t.Fatalf("status while off = %s", off)
	}
	apply(t, e, `{"enabled":true,"excluded":["{wifi}"]}`)
	var st Status
	if err := json.Unmarshal([]byte(e.StatusJSON()), &st); err != nil {
		t.Fatal(err)
	}
	if !st.Enabled || st.Merging {
		t.Fatalf("enabled %v merging %v, want on but not merging with one link", st.Enabled, st.Merging)
	}
	if len(st.Links) != 2 {
		t.Fatalf("%d links in the status, want both (one excluded)", len(st.Links))
	}
	for _, l := range st.Links {
		if l.ID == "{wifi}" && !l.Excluded {
			t.Fatal("Wi-Fi is not reported as excluded")
		}
		if l.ID == "{eth}" && (l.Name != "Ethernet 2" || l.IPv4 != "192.168.1.200" || l.State != "checking") {
			t.Fatalf("Ethernet in the status = %+v", l)
		}
	}
	if len(st.Skipped) != 1 || st.Skipped[0].Name != "Radmin VPN" {
		t.Fatalf("skipped = %+v", st.Skipped)
	}
}

// A rescan picks up a link that appears later and drops one that vanished.
func TestRescanFollowsTheAdapters(t *testing.T) {
	h := homeLinks()
	e := newTestEngine(h)
	apply(t, e, `{"enabled":true}`)
	h.mu.Lock()
	h.nics = append(h.nics, nics.Nic{ID: "{phone}", Name: "iPhone", IP: net.ParseIP("172.20.10.2"), Weight: 1, Phone: true})
	h.mu.Unlock()
	e.Rescan()
	if got := h.current().Usable(Fam4); got != 3 {
		t.Fatalf("Usable = %d after a tether appeared, want 3", got)
	}
	h.mu.Lock()
	h.nics = h.nics[:1]
	h.mu.Unlock()
	e.Rescan()
	if got := h.current().Usable(Fam4); got != 1 {
		t.Fatalf("Usable = %d after two links vanished, want 1", got)
	}
}
