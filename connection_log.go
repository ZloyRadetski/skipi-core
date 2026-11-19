// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import "github.com/ZloyRadetski/skipi-core/internal/connlog"

// ConnectionLogEntry is one routed connection: where it goes and through which outbound.
type ConnectionLogEntry struct {
	Seq      int64  `json:"seq"`
	Time     int64  `json:"time"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Network  string `json:"network"`
	Outbound string `json:"outbound"`
}

// The implementation lives in internal/connlog, whose Entry must stay field-for-field the same
// as the bound ConnectionLogEntry; this conversion stops compiling when they drift apart.
var _ = connlog.Entry(ConnectionLogEntry{})

// SetConnectionLogEnabled switches the connection log of this and later sessions. It takes no
// controller lock either.
func (c *CoreController) SetConnectionLogEnabled(enabled bool) {
	c.connLogEnabled.Store(enabled)
	if l := c.connLog.Load(); l != nil {
		l.SetEnabled(enabled)
	}
}

// ReadConnectionLog returns the routed connections newer than afterSeq as JSON. It takes no
// controller lock, so neither a slow probe nor a slow start or stop can hold a poll back.
func (c *CoreController) ReadConnectionLog(afterSeq int64) string {
	l := c.connLog.Load()
	if l == nil {
		return `{"seq":0,"entries":[]}`
	}
	return l.Snapshot(afterSeq)
}
