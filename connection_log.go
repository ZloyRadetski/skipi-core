// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"encoding/json"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	corecommlog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/serial"
)

const (
	// connectionLogCapacity bounds the in-memory history a host can scroll back through.
	connectionLogCapacity = 512
	// connectionLogPendingLimit bounds names waiting for an access record that may never come.
	connectionLogPendingLimit = 2048

	dispatcherLogPrefix = "app/dispatcher: "
	sniffedDomainPrefix = "sniffed domain: "
	defaultRoutePrefix  = "default route for "
	detourMarker        = "taking detour ["
	detourTargetMarker  = "] for ["
)

// connectionEntry is one connection the running session accepted. It only ever lives in memory.
type connectionEntry struct {
	Seq      int64  `json:"seq"`
	Time     int64  `json:"time"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Network  string `json:"network"`
	Outbound string `json:"outbound"`
}

type connectionLogSnapshot struct {
	Seq     int64             `json:"seq"`
	Entries []connectionEntry `json:"entries"`
}

// routedName is a sniffed domain waiting for the access record of its connection.
type routedName struct {
	domain      string
	destination string
}

// connectionRecorder turns Xray's log stream into connection entries. Xray writes an access record
// with the address the client asked for, which is a bare IP for a TUN client: the sniffed name exists
// only in the dispatcher's Info messages of that session, so the two are joined here.
type connectionRecorder struct {
	enabled atomic.Bool

	mu      sync.Mutex
	nextSeq int64
	entries []connectionEntry
	sniffed map[string]string
	routed  map[string][]routedName
	pending int
}

func newConnectionRecorder() *connectionRecorder {
	return &connectionRecorder{
		sniffed: make(map[string]string),
		routed:  make(map[string][]routedName),
	}
}

// reset forgets the previous session. Sequence numbers keep growing so a host's cursor stays valid.
func (r *connectionRecorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = nil
	r.forgetPendingLocked()
}

func (r *connectionRecorder) forgetPendingLocked() {
	r.sniffed = make(map[string]string)
	r.routed = make(map[string][]routedName)
	r.pending = 0
}

func (r *connectionRecorder) observe(message corecommlog.Message) {
	switch typed := message.(type) {
	case *corecommlog.AccessMessage:
		r.record(typed)
	case *corecommlog.GeneralMessage:
		if typed.Severity == corecommlog.Severity_Info {
			r.observeDispatcher(serial.ToString(typed.Content))
		}
	}
}

func (r *connectionRecorder) observeDispatcher(text string) {
	session, body, found := strings.Cut(text, dispatcherLogPrefix)
	if !found {
		return
	}
	session = strings.TrimSpace(session)

	if domain, ok := strings.CutPrefix(body, sniffedDomainPrefix); ok {
		r.mu.Lock()
		defer r.mu.Unlock()
		if len(r.sniffed)+r.pending >= connectionLogPendingLimit {
			r.forgetPendingLocked()
		}
		r.sniffed[session] = domain
		return
	}

	destination, ok := routedDestination(body)
	if !ok {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	domain, ok := r.sniffed[session]
	if !ok {
		return
	}
	delete(r.sniffed, session)
	key := routedKey(destination)
	r.routed[key] = append(r.routed[key], routedName{domain: domain, destination: destination})
	r.pending++
}

// routedDestination reads the destination out of the dispatcher's routing messages.
func routedDestination(body string) (string, bool) {
	if destination, ok := strings.CutPrefix(body, defaultRoutePrefix); ok {
		return destination, true
	}
	index := strings.Index(body, detourMarker)
	if index < 0 {
		return "", false
	}
	rest := body[index+len(detourMarker):]
	start := strings.LastIndex(rest, detourTargetMarker)
	if start < 0 || !strings.HasSuffix(rest, "]") {
		return "", false
	}
	return rest[start+len(detourTargetMarker) : len(rest)-1], true
}

// routedKey groups a destination by network and port, which sniffing never changes.
func routedKey(destination string) string {
	network, _, port, ok := parseConnectionTarget(destination)
	if !ok {
		return destination
	}
	return network + ":" + strconv.Itoa(port)
}

func (r *connectionRecorder) record(message *corecommlog.AccessMessage) {
	if message.Status != corecommlog.AccessAccepted {
		return
	}
	outbound := detourOutbound(message.Detour)
	if outbound == "" {
		return
	}
	target := serial.ToString(message.To)
	network, host, port, ok := parseConnectionTarget(target)
	if !ok {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	domain := r.takeRoutedLocked(network, port, target)
	if domain != "" && net.ParseIP(host) != nil {
		host = domain
	}
	r.nextSeq++
	r.entries = append(r.entries, connectionEntry{
		Seq:      r.nextSeq,
		Time:     time.Now().UnixMilli(),
		Host:     host,
		Port:     port,
		Network:  network,
		Outbound: outbound,
	})
	if len(r.entries) > connectionLogCapacity {
		r.entries = append(r.entries[:0], r.entries[len(r.entries)-connectionLogCapacity:]...)
	}
}

// takeRoutedLocked finds the name routed for this access record. Route-only sniffing keeps the IP in
// the routing message, so it matches exactly; otherwise that message carries the domain instead.
func (r *connectionRecorder) takeRoutedLocked(network string, port int, target string) string {
	key := network + ":" + strconv.Itoa(port)
	candidates := r.routed[key]
	for index, candidate := range candidates {
		_, host, _, ok := parseConnectionTarget(candidate.destination)
		if candidate.destination == target || (ok && net.ParseIP(host) == nil) {
			r.routed[key] = append(candidates[:index:index], candidates[index+1:]...)
			if len(r.routed[key]) == 0 {
				delete(r.routed, key)
			}
			r.pending--
			return candidate.domain
		}
	}
	return ""
}

// detourOutbound reads the outbound tag from "inbound >> outbound", "->" and "==>" forms, or a bare tag.
func detourOutbound(detour string) string {
	for _, separator := range []string{" >> ", " -> ", " ==> "} {
		if _, outbound, found := strings.Cut(detour, separator); found {
			return strings.TrimSpace(outbound)
		}
	}
	return strings.TrimSpace(detour)
}

// parseConnectionTarget reads the forms Xray inbounds put into an access record: tcp:host:port and
// udp:host:port from SOCKS, //host:port from an HTTP CONNECT, and a full URL from a plain HTTP request.
func parseConnectionTarget(target string) (network string, host string, port int, ok bool) {
	if strings.HasPrefix(target, "//") || strings.Contains(target, "://") {
		parsed, err := url.Parse(target)
		if err != nil || parsed.Hostname() == "" {
			return "", "", 0, false
		}
		port, err = strconv.Atoi(parsed.Port())
		if err != nil {
			switch parsed.Scheme {
			case "http":
				port = 80
			case "https":
				port = 443
			default:
				return "", "", 0, false
			}
		}
		return "tcp", parsed.Hostname(), port, true
	}
	network, address, found := strings.Cut(target, ":")
	if !found || (network != "tcp" && network != "udp") {
		return "", "", 0, false
	}
	host, rawPort, err := net.SplitHostPort(address)
	if err != nil {
		return "", "", 0, false
	}
	port, err = strconv.Atoi(rawPort)
	if err != nil {
		return "", "", 0, false
	}
	return network, host, port, true
}

// read returns the entries newer than [after] and the cursor to pass next time.
func (r *connectionRecorder) read(after int64) string {
	r.mu.Lock()
	snapshot := connectionLogSnapshot{Seq: r.nextSeq, Entries: []connectionEntry{}}
	for _, entry := range r.entries {
		if entry.Seq > after {
			snapshot.Entries = append(snapshot.Entries, entry)
		}
	}
	r.mu.Unlock()
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return `{"seq":0,"entries":[]}`
	}
	return string(encoded)
}

// SetConnectionLogEnabled switches the in-memory connection log. It applies at once, running or not.
func (c *CoreController) SetConnectionLogEnabled(enabled bool) {
	c.connections.enabled.Store(enabled)
}

// ReadConnectionLog returns the connections newer than [afterSeq] as JSON: {"seq":n,"entries":[...]}.
func (c *CoreController) ReadConnectionLog(afterSeq int64) string {
	return c.connections.read(afterSeq)
}
