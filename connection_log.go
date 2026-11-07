// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	coreapplog "github.com/xtls/xray-core/app/log"
	corecommlog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/core"
)

// connectionLogCapacity bounds the entries kept for a client that polls slowly.
const connectionLogCapacity = 1000

// connectionLogPendingLimit bounds sniffed names waiting for their routing line.
const connectionLogPendingLimit = 4096

// ConnectionLogEntry is one routed connection: where it goes and through which outbound.
type ConnectionLogEntry struct {
	Seq      int64  `json:"seq"`
	Time     int64  `json:"time"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Network  string `json:"network"`
	Outbound string `json:"outbound"`
}

type connectionLogSnapshot struct {
	Seq     int64                `json:"seq"`
	Entries []ConnectionLogEntry `json:"entries"`
}

var (
	sniffedDomainPattern = regexp.MustCompile(`\[(\d+)\] .*?sniffed domain: (\S+)`)
	routedPattern        = regexp.MustCompile(`\[(\d+)\] .*?taking detour \[(.+?)\] for \[(.+?)\]`)
	defaultRoutePattern  = regexp.MustCompile(`\[(\d+)\] .*?default route for (\S+)`)
)

// connectionLog joins the dispatcher's Info lines of one session into routed connections.
// Xray records the address before sniffing, so only these lines carry the real domain.
type connectionLog struct {
	enabled atomic.Bool

	mu      sync.Mutex
	seq     int64
	entries []ConnectionLogEntry
	pending map[string]string
}

func newConnectionLog(enabled bool) *connectionLog {
	l := &connectionLog{pending: make(map[string]string)}
	l.enabled.Store(enabled)
	return l
}

// record reads one log line; lines that are not about routing are ignored.
func (l *connectionLog) record(line string) {
	if !l.enabled.Load() {
		return
	}
	if m := sniffedDomainPattern.FindStringSubmatch(line); m != nil {
		l.mu.Lock()
		if len(l.pending) >= connectionLogPendingLimit {
			l.pending = make(map[string]string)
		}
		l.pending[m[1]] = m[2]
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

func (l *connectionLog) add(id, destination, outbound string) {
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
	l.entries = append(l.entries, ConnectionLogEntry{
		Seq:      l.seq,
		Time:     time.Now().UnixMilli(),
		Host:     host,
		Port:     port,
		Network:  network,
		Outbound: outbound,
	})
	if over := len(l.entries) - connectionLogCapacity; over > 0 {
		l.entries = append([]ConnectionLogEntry(nil), l.entries[over:]...)
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

// snapshot returns the entries newer than afterSeq and the cursor for the next read.
func (l *connectionLog) snapshot(afterSeq int64) string {
	l.mu.Lock()
	out := connectionLogSnapshot{Seq: l.seq, Entries: []ConnectionLogEntry{}}
	for _, e := range l.entries {
		if e.Seq > afterSeq {
			out.Entries = append(out.Entries, e)
		}
	}
	l.mu.Unlock()
	encoded, err := json.Marshal(out)
	if err != nil {
		return `{"seq":0,"entries":[]}`
	}
	return string(encoded)
}

// connectionLogHandler sits in front of Xray's own log instance: it hands every line on,
// and reads Info lines for the connection log, which the configured level would drop.
type connectionLogHandler struct {
	inner corecommlog.Handler
	log   *connectionLog
}

func (h *connectionLogHandler) Handle(msg corecommlog.Message) {
	if g, ok := msg.(*corecommlog.GeneralMessage); ok && g.Severity == corecommlog.Severity_Info {
		h.log.record(msg.String())
	}
	if h.inner != nil {
		h.inner.Handle(msg)
	}
}

// Severity lets Info lines reach the handler while the log is on; the inner instance still
// applies the configured level to what it writes.
func (h *connectionLogHandler) Severity() corecommlog.Severity {
	severity := corecommlog.Severity_Warning
	if s, ok := h.inner.(corecommlog.SeverityLogger); ok {
		severity = s.Severity()
	}
	if h.log.enabled.Load() && severity < corecommlog.Severity_Info {
		return corecommlog.Severity_Info
	}
	return severity
}

// activeConnectionLog is the running session's handler. Every core.New replaces Xray's
// process-global handler, so a probe must put it back with restoreConnectionLog.
var activeConnectionLog atomic.Pointer[connectionLogHandler]

// installConnectionLog puts the handler in front of the log instance of server.
func installConnectionLog(server *core.Instance, l *connectionLog) {
	h := &connectionLogHandler{log: l}
	if feature := server.GetFeature((*coreapplog.Instance)(nil)); feature != nil {
		if inner, ok := feature.(corecommlog.Handler); ok {
			h.inner = inner
		}
	}
	activeConnectionLog.Store(h)
	corecommlog.RegisterHandler(h)
}

// restoreConnectionLog takes the global handler back after a probe replaced it.
func restoreConnectionLog() {
	if h := activeConnectionLog.Load(); h != nil {
		corecommlog.RegisterHandler(h)
	}
}

// clearConnectionLog forgets the session's handler once it has stopped.
func clearConnectionLog(l *connectionLog) {
	if h := activeConnectionLog.Load(); h != nil && h.log == l {
		activeConnectionLog.Store(nil)
	}
}
