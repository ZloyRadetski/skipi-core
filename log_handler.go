// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"sync/atomic"

	coreapplog "github.com/xtls/xray-core/app/log"
	corecommlog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/core"
)

// sessionLogHandler sits in front of the running session's Xray logger. Xray keeps one process-global
// handler and every core.New replaces it, so a latency probe would otherwise silence the session.
type sessionLogHandler struct {
	next     corecommlog.Handler
	recorder *connectionRecorder
}

var activeSessionLog atomic.Pointer[sessionLogHandler]

// Handle gives the session's logger every message; that logger still applies the configured level.
func (h *sessionLogHandler) Handle(message corecommlog.Message) {
	if h.next != nil {
		h.next.Handle(message)
	}
	if h.recorder.enabled.Load() {
		h.recorder.observe(message)
	}
}

// Severity lets Info messages be built while the connection log needs them, at any file log level.
func (h *sessionLogHandler) Severity() corecommlog.Severity {
	severity := corecommlog.Severity_Debug
	if logger, ok := h.next.(corecommlog.SeverityLogger); ok {
		severity = logger.Severity()
	}
	if h.recorder.enabled.Load() && severity < corecommlog.Severity_Info {
		return corecommlog.Severity_Info
	}
	return severity
}

// installSessionLogHandler must run after core.New, which registers the session's own logger.
func installSessionLogHandler(server *core.Instance, recorder *connectionRecorder) {
	handler := &sessionLogHandler{recorder: recorder}
	if logger, ok := server.GetFeature((*coreapplog.Instance)(nil)).(*coreapplog.Instance); ok {
		handler.next = logger
	}
	activeSessionLog.Store(handler)
	corecommlog.RegisterHandler(handler)
}

// restoreSessionLogHandler takes the global handler back after another core.New in this process.
func restoreSessionLogHandler() {
	if handler := activeSessionLog.Load(); handler != nil {
		corecommlog.RegisterHandler(handler)
	}
}

func clearSessionLogHandler() {
	handler := activeSessionLog.Swap(nil)
	if handler != nil && handler.next != nil {
		corecommlog.RegisterHandler(handler.next)
	}
}
