// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

// Package trafficstats turns Xray's in-memory traffic counters into the cumulative snapshot
// and the legacy compact string the mobile binding exposes.
package trafficstats

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	corestats "github.com/xtls/xray-core/features/stats"
)

// Bytes is deliberately kept private to the binding: the mobile side only
// sees the compact JSON snapshot returned by QueryTrafficStats.
type Bytes struct {
	Uplink   int64 `json:"uplink"`
	Downlink int64 `json:"downlink"`
}

// Snapshot is the cumulative per-tag traffic of the inbounds and outbounds.
type Snapshot struct {
	Inbound  map[string]Bytes `json:"inbound"`
	Outbound map[string]Bytes `json:"outbound"`
}

// EmptySnapshotJSON is what a stopped controller reports.
const EmptySnapshotJSON = `{"inbound":{},"outbound":{}}`

// Drain moves the new Xray counter values into the cumulative totals and returns just this
// drain's deltas. totals must be non-nil.
func Drain(manager corestats.Manager, totals map[string]int64) map[string]int64 {
	deltas := make(map[string]int64)
	manager.VisitCounters(func(name string, counter corestats.Counter) bool {
		if !isCounter(name) {
			return true
		}
		if value := counter.Set(0); value > 0 {
			totals[name] += value
			deltas[name] = value
		}
		return true
	})
	return deltas
}

// Encode renders a snapshot as JSON, falling back to the empty snapshot.
func Encode(snapshot Snapshot) string {
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return EmptySnapshotJSON
	}
	return string(encoded)
}

// OutboundCompact renders the outbound part of a snapshot in the legacy compact format
// "tag,direction,value;tag,direction,value;".
func OutboundCompact(snapshot Snapshot) string {
	var b strings.Builder
	b.Grow(512)
	for _, tag := range sortedTags(snapshot.Outbound) {
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

func SnapshotFromTotals(totals map[string]int64) Snapshot {
	snapshot := newSnapshot()
	for name, value := range totals {
		if value <= 0 {
			continue
		}
		kind, tag, direction, ok := parseCounterName(name)
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

func newSnapshot() Snapshot {
	return Snapshot{
		Inbound:  make(map[string]Bytes),
		Outbound: make(map[string]Bytes),
	}
}

func isCounter(name string) bool {
	_, _, _, ok := parseCounterName(name)
	return ok
}

func parseCounterName(name string) (kind, tag, direction string, ok bool) {
	parts := strings.Split(name, ">>>")
	if len(parts) != 4 || (parts[0] != "inbound" && parts[0] != "outbound") || parts[2] != "traffic" {
		return "", "", "", false
	}
	if parts[1] == "" || (parts[3] != "uplink" && parts[3] != "downlink") {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[3], true
}

func sortedTags(stats map[string]Bytes) []string {
	tags := make([]string, 0, len(stats))
	for tag := range stats {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	return tags
}
