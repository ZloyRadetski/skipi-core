// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package multilink

import (
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/ZloyRadetski/skipi-core/desktop/multilink/nics"
)

// Settings is what the application decides about link merging. Adapters are named by their id (see nics.Nic.ID).
type Settings struct {
	Enabled bool `json:"enabled"`
	// Excluded adapters take no flows.
	Excluded []string `json:"excluded,omitempty"`
	// Weights fix an adapter's share; with none, shares follow each link's measured speed.
	Weights map[string]float64 `json:"weights,omitempty"`
	// Limits cap an adapter, in Mbit/s.
	Limits map[string]float64 `json:"limits,omitempty"`
	// Phones are treated as phone hotspots, besides the ones recognised by themselves.
	Phones       []string `json:"phones,omitempty"`
	PhoneCooling bool     `json:"phoneCooling,omitempty"`
	// CoolMbps is what a cooling phone is held to; 0 takes DefaultCoolMbps.
	CoolMbps float64 `json:"coolMbps,omitempty"`
	// ProbeTargets replace the addresses ("ip:port") that a link's internet access is checked against.
	ProbeTargets []string `json:"probeTargets,omitempty"`
}

func (s Settings) validate() error {
	for id, w := range s.Weights {
		if !(w > 0) || math.IsInf(w, 0) || w > 1000 {
			return fmt.Errorf("the weight of %s must be above 0 and at most 1000", id)
		}
	}
	for id, mbps := range s.Limits {
		if !(mbps >= 0) || mbps > LimitMaxMbps {
			return fmt.Errorf("the limit of %s must be between 0 and %.0f Mbit/s", id, float64(LimitMaxMbps))
		}
	}
	if !(s.CoolMbps >= 0) || s.CoolMbps > LimitMaxMbps {
		return fmt.Errorf("the phone cooling rate must be between 0 and %.0f Mbit/s", float64(LimitMaxMbps))
	}
	for _, target := range s.ProbeTargets {
		addr, err := netip.ParseAddrPort(target)
		if err != nil || addr.Port() == 0 {
			return fmt.Errorf("probe target %q is not an ip:port", target)
		}
	}
	return nil
}

// EngineConfig holds the engine's seams. Discover and Attach are required.
type EngineConfig struct {
	// Discover lists the adapters that could carry traffic, and the ones skipped with why.
	Discover func() ([]nics.Nic, []nics.Skip, error)
	// Kinds names what each adapter is, by name; nil reads the system's.
	Kinds func() map[string]nics.Kind
	// Attach hands the scheduler to the dialer, or takes it away with nil.
	Attach func(*Scheduler)
	// NoLoops leaves ticking, rescanning and probing to the caller (tests).
	NoLoops bool
}

// Engine runs link merging: it finds the adapters, keeps the scheduler's view of them current, measures and
// probes the links, and attaches the scheduler to the dialer while merging is on.
type Engine struct {
	cfg EngineConfig

	mu       sync.Mutex
	settings Settings
	sched    *Scheduler
	found    []nics.Nic
	skipped  []nics.Skip
	stop     chan struct{}
	loops    sync.WaitGroup
}

func NewEngine(cfg EngineConfig) *Engine { return &Engine{cfg: cfg} }

// DefaultDiscover is the system's adapter discovery.
func DefaultDiscover() ([]nics.Nic, []nics.Skip, error) { return nics.DiscoverNicsDetailed(nil, nil) }

// ApplyJSON applies settings written as JSON; a refused setting changes nothing.
func (e *Engine) ApplyJSON(data string) error {
	var s Settings
	if err := json.Unmarshal([]byte(data), &s); err != nil {
		return fmt.Errorf("invalid link merging settings: %w", err)
	}
	return e.Apply(s)
}

// Apply switches merging on or off and applies the rest of the settings while it runs. The scheduler is kept
// across changes, so open flows and measured speeds survive them.
func (e *Engine) Apply(s Settings) error {
	if err := s.validate(); err != nil {
		return err
	}
	if !s.Enabled {
		e.Stop()
		e.mu.Lock()
		e.settings = s
		e.mu.Unlock()
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.settings = s
	fresh := e.sched == nil
	if fresh {
		e.sched = NewScheduler(nil)
	}
	e.configureLocked()
	e.rescanLocked()
	if fresh {
		e.cfg.Attach(e.sched)
		if !e.cfg.NoLoops {
			e.startLoopsLocked()
		}
	}
	return nil
}

func (e *Engine) configureLocked() {
	s, sched := e.settings, e.sched
	sched.SetAuto(len(s.Weights) == 0)
	sched.SetLimits(s.Limits)
	sched.SetPhoneCooling(s.PhoneCooling)
	cool := s.CoolMbps
	if cool == 0 {
		cool = DefaultCoolMbps
	}
	sched.SetCoolRate(cool)
	var targets [2][]string
	for _, target := range s.ProbeTargets {
		addr := netip.MustParseAddrPort(target) // checked by validate
		f := Fam4
		if addr.Addr().Unmap().Is6() {
			f = Fam6
		}
		targets[f] = append(targets[f], target)
	}
	sched.SetProbeTargets(targets)
}

// Stop switches merging off: the dialer goes back to Xray's own for new connections, and the loops end. Open
// connections stay where they are.
func (e *Engine) Stop() {
	e.mu.Lock()
	if e.sched == nil {
		e.mu.Unlock()
		return
	}
	e.cfg.Attach(nil)
	e.sched = nil
	stop := e.stop
	e.stop = nil
	e.mu.Unlock()
	if stop != nil {
		close(stop)
		e.loops.Wait()
	}
}

// Running reports whether merging is on.
func (e *Engine) Running() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.sched != nil
}

// Scheduler is the running scheduler, nil while off.
func (e *Engine) Scheduler() *Scheduler {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.sched
}

// Rescan reads the adapters again and applies what changed.
func (e *Engine) Rescan() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sched != nil {
		e.rescanLocked()
	}
}

func (e *Engine) rescanLocked() {
	found, skipped, err := e.cfg.Discover()
	if err != nil {
		return // the last good view stays; a failed listing must not take every link away
	}
	e.found, e.skipped = found, skipped
	s := e.settings
	use := make([]nics.Nic, 0, len(found))
	for _, n := range found {
		if slices.Contains(s.Excluded, n.ID) {
			continue
		}
		n.Weight = 1
		if w, ok := s.Weights[n.ID]; ok {
			n.Weight = w
		}
		n.Phone = n.Phone || slices.Contains(s.Phones, n.ID)
		use = append(use, n)
	}
	e.sched.Update(use)
}

const (
	tickEvery   = time.Second
	rescanEvery = 3 * time.Second
)

func (e *Engine) startLoopsLocked() {
	stop := make(chan struct{})
	e.stop = stop
	sched := e.sched
	e.loops.Add(3)
	go func() {
		defer e.loops.Done()
		sched.RunProbes(stop)
	}()
	go func() {
		defer e.loops.Done()
		t := time.NewTicker(tickEvery)
		defer t.Stop()
		last := time.Now()
		for {
			select {
			case <-stop:
				return
			case now := <-t.C:
				sched.Tick(now.Sub(last))
				last = now
			}
		}
	}()
	go func() {
		defer e.loops.Done()
		t := time.NewTicker(rescanEvery)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				e.Rescan()
			}
		}
	}()
}

// Status is what the application shows about link merging.
type Status struct {
	Enabled bool `json:"enabled"`
	// Merging is true while at least two links can take new connections.
	Merging bool         `json:"merging"`
	Links   []LinkStatus `json:"links"`
	Skipped []SkipStatus `json:"skipped"`
}

type LinkStatus struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	Kind     string  `json:"kind"`
	IPv4     string  `json:"ipv4,omitempty"`
	IPv6     string  `json:"ipv6,omitempty"`
	State    string  `json:"state"`
	State6   string  `json:"state6"`
	Excluded bool    `json:"excluded"`
	Phone    bool    `json:"phone"`
	Weight   float64 `json:"weight"`
	Flows    int64   `json:"flows"`
	// RateIn and RateOut are what SKIPI moves over the link, LinkIn and LinkOut what every app does, in bytes/s.
	RateIn    float64 `json:"rateIn"`
	RateOut   float64 `json:"rateOut"`
	LinkIn    float64 `json:"linkIn"`
	LinkOut   float64 `json:"linkOut"`
	LimitMbps float64 `json:"limitMbps"`
	CoolMbps  float64 `json:"coolMbps"`
}

type SkipStatus struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// StatusJSON is Status as JSON.
func (e *Engine) StatusJSON() string {
	data, err := json.Marshal(e.Status())
	if err != nil {
		return `{"enabled":false,"merging":false,"links":[],"skipped":[]}`
	}
	return string(data)
}

func (e *Engine) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := Status{Enabled: e.sched != nil, Links: []LinkStatus{}, Skipped: []SkipStatus{}}
	if e.sched == nil {
		return st
	}
	st.Merging = e.sched.Usable(Fam4) >= 2 || e.sched.Usable(Fam6) >= 2
	kinds := e.kinds()
	seen := map[string]bool{}
	for _, s := range e.sched.Snapshot() {
		if !s.Present {
			continue
		}
		seen[s.ID] = true
		st.Links = append(st.Links, LinkStatus{
			ID: s.ID, Name: s.Name, Kind: string(kindOf(kinds, s.Name)), IPv4: s.IP, IPv6: s.IP6,
			State: s.State, State6: s.State6, Phone: s.Phone, Weight: s.Weight, Flows: s.Active,
			RateIn: s.RateIn, RateOut: s.RateOut, LinkIn: s.LinkIn, LinkOut: s.LinkOut,
			LimitMbps: s.LimitMbps, CoolMbps: s.CoolMbps,
		})
	}
	for _, n := range e.found {
		if seen[n.ID] {
			continue
		}
		link := LinkStatus{ID: n.ID, Name: n.Name, Kind: string(kindOf(kinds, n.Name)), State: "-", State6: "-",
			Excluded: slices.Contains(e.settings.Excluded, n.ID), Phone: n.Phone}
		if n.IP != nil {
			link.IPv4 = n.IP.String()
		}
		if n.IP6 != nil {
			link.IPv6 = n.IP6.String()
		}
		st.Links = append(st.Links, link)
	}
	for _, s := range e.skipped {
		st.Skipped = append(st.Skipped, SkipStatus{Name: s.Name, Reason: s.Reason})
	}
	return st
}

func (e *Engine) kinds() map[string]nics.Kind {
	if e.cfg.Kinds != nil {
		return e.cfg.Kinds()
	}
	return nics.AdapterKinds()
}

func kindOf(kinds map[string]nics.Kind, name string) nics.Kind {
	if k, ok := kinds[name]; ok {
		return k
	}
	return nics.Unknown
}
