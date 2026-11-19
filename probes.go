// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"context"
	"errors"
	"time"

	"github.com/xtls/xray-core/core"

	"github.com/ZloyRadetski/skipi-core/internal/probe"
)

// MeasureOutboundDelay tests the latency of an outbound proxy configuration against a target URL.
// It optimizes performance by stripping inbounds and non-essential app modules.
func MeasureOutboundDelay(configJSON string, targetURL string) (int64, error) {
	return probe.Delay(configJSON, targetURL)
}

// MeasureOutboundDownload downloads exactly maxBytes through an isolated
// outbound configuration and returns a JSON result containing the measured
// payload, elapsed time, first-byte time and HTTP status. requestID is optional
// but, when supplied, allows CancelOutboundDownload to stop a running request.
func MeasureOutboundDownload(
	configJSON string,
	targetURL string,
	maxBytes int64,
	timeoutMillis int64,
	requestID string,
) (string, error) {
	return probe.Download(configJSON, targetURL, maxBytes, timeoutMillis, requestID)
}

// CancelOutboundDownload cancels an isolated download test previously started
// with the same requestID. It is safe to call for an already-finished or
// unknown request.
func CancelOutboundDownload(requestID string) {
	probe.CancelDownload(requestID)
}

// FastSelectBestOutbound concurrently tests candidate outbounds against a probe URL (defaulting to
// http://connectivitycheck.gstatic.com/generate_204) and returns the tag of the fastest responsive node.
// It uses early-return racing with a tight per-node timeout to avoid blocking on dead nodes.
func FastSelectBestOutbound(configJSON string, candidateTags string, probeURL string, timeoutMs int64) string {
	return probe.FastSelect(configJSON, candidateTags, probeURL, timeoutMs)
}

// MeasureDelay measures network latency to a target URL through the currently running core instance.
func (c *CoreController) MeasureDelay(targetURL string) (int64, error) {
	c.mu.Lock()
	inst, _ := c.instance.(*core.Instance)
	c.mu.Unlock()

	if inst == nil {
		return -1, errors.New("core instance is not running")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	return probe.InstanceDelay(ctx, inst, targetURL)
}
