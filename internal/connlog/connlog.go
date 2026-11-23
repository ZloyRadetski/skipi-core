// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

// Package connlog records which host each routed connection took which outbound, by reading
// Xray's access-style log lines, and serves them as a bounded JSON ring.
package connlog

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	coreapplog "github.com/xtls/xray-core/app/log"
	corecommlog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/core"
)

// capacity bounds the entries kept for a client that polls slowly.
const capacity = 1000

// pendingLimit bounds sniffed names waiting for their routing line.
const pendingLimit = 4096

// Entry is one routed connection: where it goes and through which outbound.
type Entry struct {
	Seq      int64  `json:"seq"`
	Time     int64  `json:"time"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Network  string `json:"network"`
	Outbound string `json:"outbound"`
}

type snapshotJSON struct {
	Seq     int64   `json:"seq"`
	Entries []Entry `json:"entries"`
}

var (
	sniffedDomainPattern = regexp.MustCompile(`\[(\d+)\] .*?sniffed domain: (\S+)`)
	routedPattern        = regexp.MustCompile(`\[(\d+)\] .*?taking detour \[(.+?)\] for \[(.+?)\]`)
	defaultRoutePattern  = regexp.MustCompile(`\[(\d+)\] .*?default route for (\S+)`)
)

// Log joins the dispatcher's Info lines of one session into routed connections.
// Xray records the address before sniffing, so only these lines carry the real domain.
type Log struct {
	enabled atomic.Bool

	mu      sync.Mutex
	seq     int64
	entries []Entry
	pending map[string]string
	order   []string // pending ids, oldest first; may hold ids already consumed
	head    int
}

// New returns an empty log that records only while enabled.
func New(enabled bool) *Log {
	l := &Log{pending: make(map[string]string)}
	l.enabled.Store(enabled)
	return l
}

// Record reads one log line; lines that are not about routing are ignored.
func (l *Log) Record(line string) {
	if !l.enabled.Load() {
		return
	}
	// The dispatcher logs far more Info lines than these three; skip the regexps for the rest.
	if !strings.Contains(line, "sniffed domain: ") &&
		!strings.Contains(line, "taking detour") &&
		!strings.Contains(line, "default route for") {
		return
	}
	if m := sniffedDomainPattern.FindStringSubmatch(line); m != nil {
		l.mu.Lock()
		l.remember(m[1], m[2])
		l.mu.Unlock()
		return
	}
	if m := routedPattern.FindStringSubmatch(line); m != nil {
		l.add(m[1], m[3], m[2])
		return
	}
	if m := defaultRoutePattern.FindStringSubmatch(line); m != nil {
		l.add(m[1], m[2], "default")
	}
}

// remember stores a sniffed name for its connection id, dropping the oldest names when full.
// Callers hold l.mu.
func (l *Log) remember(id, name string) {
	if _, ok := l.pending[id]; !ok {
		for len(l.pending) >= pendingLimit && l.head < len(l.order) {
			delete(l.pending, l.order[l.head])
			l.order[l.head] = ""
			l.head++
		}
		l.order = append(l.order, id)
		if len(l.order)-l.head > 2*pendingLimit {
			// Most ids were consumed by their routing line; keep only the live ones.
			live := l.order[:0]
			for _, queued := range l.order[l.head:] {
				if _, ok := l.pending[queued]; ok || queued == id {
					live = append(live, queued)
				}
			}
			clear(l.order[len(live):])
			l.order, l.head = live, 0
		}
		// Compact once the consumed prefix outweighs the live part.
		if l.head > pendingLimit {
			n := copy(l.order, l.order[l.head:])
			clear(l.order[n:])
			l.order = l.order[:n]
			l.head = 0
		}
	}
	l.pending[id] = name
}

func (l *Log) add(id, destination, outbound string) {
	network, host, port := splitDestination(destination)
	l.mu.Lock()
	defer l.mu.Unlock()
	if name, ok := l.pending[id]; ok {
		host = name
		delete(l.pending, id)
	}
	if host == "" {
		return
	}
	l.seq++
	l.entries = append(l.entries, Entry{
		Seq:      l.seq,
		Time:     time.Now().UnixMilli(),
		Host:     host,
		Port:     port,
		Network:  network,
		Outbound: outbound,
	})
	// Trim in place once the slice holds twice the capacity: one copy per capacity-many
	// connections instead of one allocation per connection.
	if len(l.entries) >= 2*capacity {
		n := copy(l.entries, l.entries[len(l.entries)-capacity:])
		clear(l.entries[n:])
		l.entries = l.entries[:n]
	}
}

// splitDestination reads Xray's "network:host:port", where an IPv6 host is bracketed.
func splitDestination(destination string) (network, host string, port int) {
	network = "tcp"
	if i := strings.Index(destination, ":"); i > 0 {
		network, destination = destination[:i], destination[i+1:]
	}
	if i := strings.LastIndex(destination, ":"); i >= 0 {
		if p, err := strconv.Atoi(destination[i+1:]); err == nil {
			port = p
			destination = destination[:i]
		}
	}
	return network, strings.Trim(destination, "[]"), port
}

// Snapshot returns the entries newer than afterSeq and the cursor for the next read.
func (l *Log) Snapshot(afterSeq int64) string {
	l.mu.Lock()
	visible := l.entries
	if over := len(visible) - capacity; over > 0 {
		visible = visible[over:]
	}
	// Seq grows by one per entry, so the newer ones start at a binary-searchable index.
	first := sort.Search(len(visible), func(i int) bool { return visible[i].Seq > afterSeq })
	out := snapshotJSON{Seq: l.seq, Entries: make([]Entry, len(visible)-first)}
	copy(out.Entries, visible[first:])
	l.mu.Unlock()
	encoded, err := json.Marshal(out)
	if err != nil {
		return `{"seq":0,"entries":[]}`
	}
	return string(encoded)
}

// handler sits in front of Xray's own log instance: it hands every line on,
// and reads Info lines for the connection log, which the configured level would drop.
type handler struct {
	inner corecommlog.Handler
	log   *Log
}

func (h *handler) Handle(msg corecommlog.Message) {
	if g, ok := msg.(*corecommlog.GeneralMessage); ok && g.Severity == corecommlog.Severity_Info && h.log.enabled.Load() {
		h.log.Record(msg.String())
	}
	if h.inner != nil {
		h.inner.Handle(msg)
	}
}

// Severity lets Info lines reach the handler while the log is on; the inner instance still
// applies the configured level to what it writes.
func (h *handler) Severity() corecommlog.Severity {
	severity := corecommlog.Severity_Warning
	if s, ok := h.inner.(corecommlog.SeverityLogger); ok {
		severity = s.Severity()
	}
	if h.log.enabled.Load() && severity < corecommlog.Severity_Info {
		return corecommlog.Severity_Info
	}
	return severity
}

// active is the running session's handler. Every core.New replaces Xray's
// process-global handler, so a probe must put it back with Restore.
var active atomic.Pointer[handler]

// Install puts the handler in front of the log instance of server.
func Install(server *core.Instance, l *Log) {
	h := &handler{log: l}
	if feature := server.GetFeature((*coreapplog.Instance)(nil)); feature != nil {
		if inner, ok := feature.(corecommlog.Handler); ok {
			h.inner = inner
		}
	}
	active.Store(h)
	corecommlog.RegisterHandler(h)
}

// Restore takes the global handler back after a probe replaced it.
func Restore() {
	if h := active.Load(); h != nil {
		corecommlog.RegisterHandler(h)
	}
}

// Clear forgets the session's handler once it has stopped.
func Clear(l *Log) {
	if h := active.Load(); h != nil && h.log == l {
		active.Store(nil)
	}
}

// SetEnabled switches recording on or off.
func (l *Log) SetEnabled(enabled bool) { l.enabled.Store(enabled) }
