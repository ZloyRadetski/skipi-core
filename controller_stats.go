// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"github.com/ZloyRadetski/skipi-core/internal/trafficstats"
)

// QueryTrafficStats atomically drains Xray's in-memory counters into a
// process-private cumulative snapshot. It never opens an Xray API listener.
//
// Multiple Android UI consumers may call this safely: every call receives the
// same totals accumulated since this CoreController was started, rather than
// stealing a delta from another consumer.
func (c *CoreController) QueryTrafficStats() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	return trafficstats.Encode(c.collectTrafficStatsLocked())
}

// QueryAllOutboundTrafficStats is retained for binary compatibility with
// older callers. New callers should use QueryTrafficStats, which includes
// inbound counters and is safe for concurrent readers.
// It retains the legacy delta semantics: each reported counter is reset after
// it is read. Returns a compact string: "tag,direction,value;tag,direction,value;".
func (c *CoreController) QueryAllOutboundTrafficStats() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	snapshot := trafficstats.SnapshotFromTotals(c.drainTrafficStatsLocked())
	return trafficstats.OutboundCompact(snapshot)
}

func (c *CoreController) collectTrafficStatsLocked() trafficstats.Snapshot {
	c.drainTrafficStatsLocked()
	return trafficstats.SnapshotFromTotals(c.trafficStatsTotals)
}

// drainTrafficStatsLocked moves the new Xray counter values into the
// cumulative process-private totals and returns just this drain's deltas. The
// caller must hold c.mu.
func (c *CoreController) drainTrafficStatsLocked() map[string]int64 {
	if c.statsManager == nil {
		return make(map[string]int64)
	}
	if c.trafficStatsTotals == nil {
		c.trafficStatsTotals = make(map[string]int64)
	}
	return trafficstats.Drain(c.statsManager, c.trafficStatsTotals)
}
