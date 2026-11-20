// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

// Package probe measures outbounds through short-lived, stripped-down Xray instances:
// latency, download throughput and the fastest of several candidates.
package probe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	corenet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	coreserial "github.com/xtls/xray-core/infra/conf/serial"

	"github.com/ZloyRadetski/skipi-core/internal/connlog"
	"github.com/ZloyRadetski/skipi-core/internal/lifecycle"
)

// Every probe builds a whole Xray instance. The host decides how many it runs at once, but Core
// bounds that itself, and a Close that hangs is abandoned (and counted) instead of holding the
// probe's caller.
const defaultProbeSlots = 32

var (
	// newProbeInstance builds the stripped-down instance of one probe. Tests replace it.
	newProbeInstance = startOutboundTestInstance
	probeSlots       = make(chan struct{}, defaultProbeSlots)
	// probeCloseTimeout bounds closing a probe instance.
	probeCloseTimeout = 5 * time.Second
)

func setProbeSlots(n int) { probeSlots = make(chan struct{}, n) }

// acquireProbeSlot waits for room for one more probe instance and returns its release.
func acquireProbeSlot() func() {
	slots := probeSlots
	slots <- struct{}{}
	return func() { <-slots }
}

// closeProbeInstance closes a probe instance within probeCloseTimeout.
func closeProbeInstance(c io.Closer) {
	_, _ = lifecycle.RunBounded(c.Close, probeCloseTimeout, nil)
}

// Delay tests the latency of an outbound proxy configuration against a target URL.
// It optimizes performance by stripping inbounds and non-essential app modules.
func Delay(configJSON string, targetURL string) (int64, error) {
	release := acquireProbeSlot()
	defer release()
	server, err := newProbeInstance(configJSON)
	if err != nil {
		return -1, err
	}
	defer closeProbeInstance(server)

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	return InstanceDelay(ctx, server, targetURL)
}

// outboundDownloadResult is deliberately encoded as JSON at the mobile
// boundary. Returning a string keeps the gomobile surface stable and lets the
// Android UI add fields without coupling itself to a generated Go object.
type outboundDownloadResult struct {
	BytesDownloaded int64 `json:"bytesDownloaded"`
	ElapsedMillis   int64 `json:"elapsedMillis"`
	TtfbMillis      int64 `json:"ttfbMillis"`
	StatusCode      int   `json:"statusCode"`
}

// downloads tracks the cancel of every download that has a request ID. A cancel for an ID that is
// not running yet is kept for a while, so a cancel that overtakes its download is not lost.
var downloads struct {
	sync.Mutex
	running map[string]context.CancelFunc
	early   map[string]time.Time
}

const (
	earlyCancelTTL = time.Minute
	maxEarlyCancel = 256
)

var errDownloadCancelled = errors.New("download was cancelled")

// registerDownload records cancel for id; it reports false when id was cancelled already.
func registerDownload(id string, cancel context.CancelFunc) bool {
	downloads.Lock()
	defer downloads.Unlock()
	if at, ok := downloads.early[id]; ok {
		delete(downloads.early, id)
		if time.Since(at) < earlyCancelTTL {
			return false
		}
	}
	if downloads.running == nil {
		downloads.running = make(map[string]context.CancelFunc)
	}
	downloads.running[id] = cancel
	return true
}

func unregisterDownload(id string) {
	downloads.Lock()
	delete(downloads.running, id)
	downloads.Unlock()
}

const (
	maxOutboundDownloadBytes         int64 = 100 << 20
	minOutboundDownloadTimeoutMillis int64 = 10_000
	maxOutboundDownloadTimeoutMillis int64 = 10 * 60 * 1000
)

// Download downloads exactly maxBytes through an isolated
// outbound configuration and returns a JSON result containing the measured
// payload, elapsed time, first-byte time and HTTP status. requestID is optional
// but, when supplied, allows CancelOutboundDownload to stop a running request.
func Download(
	configJSON string,
	targetURL string,
	maxBytes int64,
	timeoutMillis int64,
	requestID string,
) (string, error) {
	if maxBytes <= 0 || maxBytes > maxOutboundDownloadBytes {
		return "", fmt.Errorf("download byte limit must be between 1 and %d", maxOutboundDownloadBytes)
	}
	if timeoutMillis < minOutboundDownloadTimeoutMillis || timeoutMillis > maxOutboundDownloadTimeoutMillis {
		return "", fmt.Errorf(
			"download timeout must be between %d and %d ms",
			minOutboundDownloadTimeoutMillis,
			maxOutboundDownloadTimeoutMillis,
		)
	}
	if strings.TrimSpace(targetURL) == "" {
		return "", errors.New("download target URL is empty")
	}

	// The cancel is reachable before the instance exists: building it takes a while, and a
	// cancel in that time must still stop the download.
	cancelCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if requestID != "" {
		if !registerDownload(requestID, cancel) {
			return "", errDownloadCancelled
		}
		defer unregisterDownload(requestID)
	}

	release := acquireProbeSlot()
	defer release()
	if cancelCtx.Err() != nil {
		return "", errDownloadCancelled
	}
	server, err := newProbeInstance(configJSON)
	if err != nil {
		return "", err
	}
	defer closeProbeInstance(server)
	if cancelCtx.Err() != nil {
		return "", errDownloadCancelled
	}

	ctx, stop := context.WithTimeout(cancelCtx, time.Duration(timeoutMillis)*time.Millisecond)
	defer stop()

	result, err := instanceDownload(ctx, server, targetURL, maxBytes)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("failed to encode download result: %w", err)
	}
	return string(encoded), nil
}

// CancelDownload cancels an isolated download test previously started
// with the same requestID. It is safe to call for an already-finished or
// unknown request.
func CancelDownload(requestID string) {
	if requestID == "" {
		return
	}
	downloads.Lock()
	defer downloads.Unlock()
	if cancel, ok := downloads.running[requestID]; ok {
		cancel()
		return
	}
	// Not running yet (or already done): keep the cancel briefly for a download that comes late.
	now := time.Now()
	if downloads.early == nil {
		downloads.early = make(map[string]time.Time)
	}
	for id, at := range downloads.early {
		if now.Sub(at) >= earlyCancelTTL || len(downloads.early) >= maxEarlyCancel {
			delete(downloads.early, id)
		}
	}
	downloads.early[requestID] = now
}

// probeKeys are the top-level config sections a probe instance is built from: the outbounds, the
// global transport settings that are merged into them while parsing, and the log.
var probeKeys = map[string]bool{"log": true, "outbounds": true, "transport": true}

// probeOnlyJSON cuts everything but probeKeys from the config before it is parsed. Routing and
// DNS would otherwise be built (scanning the geo files for every geosite and geoip rule) only to
// be thrown away. Text that is not a JSON object is returned as is, for the loader to report.
func probeOnlyJSON(configJSON string) string {
	d := json.NewDecoder(strings.NewReader(configJSON))
	d.UseNumber()
	var root map[string]json.RawMessage
	if err := d.Decode(&root); err != nil || root == nil {
		return configJSON
	}
	for key := range root {
		if !probeKeys[key] {
			delete(root, key)
		}
	}
	out, err := json.Marshal(root)
	if err != nil {
		return configJSON
	}
	return string(out)
}

// startOutboundTestInstance strips a normal app configuration down to the
// dispatcher and outbound pieces required by an isolated test instance.
func startOutboundTestInstance(configJSON string) (*core.Instance, error) {
	config, err := coreserial.LoadJSONConfig(strings.NewReader(probeOnlyJSON(configJSON)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse test config: %w", err)
	}

	// Optimize test instance by removing inbounds and non-essential apps
	config.Inbound = nil
	var essentialApps []*serial.TypedMessage
	for _, app := range config.App {
		if app.Type == "xray.app.proxyman.OutboundConfig" ||
			app.Type == "xray.app.dispatcher.Config" ||
			app.Type == "xray.app.log.Config" {
			essentialApps = append(essentialApps, app)
		}
	}
	config.App = essentialApps

	server, err := core.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create test instance: %w", err)
	}
	connlog.Restore()

	if err := server.Start(); err != nil {
		_ = server.Close()
		return nil, fmt.Errorf("failed to start test instance: %w", err)
	}
	return server, nil
}

// InstanceDelay measures network latency for an instance to a given target URL with 2 attempts and jitter reduction.
func InstanceDelay(ctx context.Context, inst *core.Instance, targetURL string) (int64, error) {
	if inst == nil {
		return -1, errors.New("core instance is nil")
	}

	if targetURL == "" {
		targetURL = "https://www.google.com/generate_204"
	}

	tr := &http.Transport{
		TLSHandshakeTimeout: 6 * time.Second,
		DisableKeepAlives:   false,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dest, err := corenet.ParseDestination(fmt.Sprintf("%s:%s", network, addr))
			if err != nil {
				return nil, err
			}
			return core.Dial(ctx, inst, dest)
		},
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{
		Transport: tr,
		Timeout:   12 * time.Second,
	}

	var minDuration int64 = -1
	success := false
	var lastErr error

	const attempts = 2
	for i := 0; i < attempts; i++ {
		select {
		case <-ctx.Done():
			if !success {
				return -1, ctx.Err()
			}
			return minDuration, nil
		default:
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if err != nil {
			lastErr = fmt.Errorf("failed to create HTTP request: %w", err)
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		_, err = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
			lastErr = fmt.Errorf("invalid status code: %s", resp.Status)
			continue
		}

		if err != nil {
			lastErr = fmt.Errorf("failed to read response body: %w", err)
			continue
		}

		duration := time.Since(start).Milliseconds()
		if !success || duration < minDuration {
			minDuration = duration
		}
		success = true
	}

	if !success {
		return -1, lastErr
	}
	return minDuration, nil
}

// instanceDownload reads exactly maxBytes from targetURL through the
// supplied Xray instance. The body is deliberately not drained beyond that
// limit: test size is a hard network budget, not merely a reporting hint.
func instanceDownload(
	ctx context.Context,
	inst *core.Instance,
	targetURL string,
	maxBytes int64,
) (outboundDownloadResult, error) {
	if inst == nil {
		return outboundDownloadResult{}, errors.New("core instance is nil")
	}

	tr := &http.Transport{
		TLSHandshakeTimeout: 6 * time.Second,
		DisableKeepAlives:   true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dest, err := corenet.ParseDestination(fmt.Sprintf("%s:%s", network, addr))
			if err != nil {
				return nil, err
			}
			return core.Dial(ctx, inst, dest)
		},
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{Transport: tr}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return outboundDownloadResult{}, fmt.Errorf("failed to create download request: %w", err)
	}
	req.Header.Set("User-Agent", "SKIPI-SpeedTest/1.0")
	req.Header.Set("Cache-Control", "no-cache")
	// The byte budget must apply to the actual response body. Asking for an
	// identity response avoids a transport transparently decompressing a
	// smaller on-wire payload into maxBytes of decoded data.
	req.Header.Set("Accept-Encoding", "identity")

	startedAt := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return outboundDownloadResult{}, fmt.Errorf("download request failed: %w", err)
	}
	defer resp.Body.Close()

	ttfbMillis := time.Since(startedAt).Milliseconds()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return outboundDownloadResult{}, fmt.Errorf("invalid download status code: %s", resp.Status)
	}

	bytesDownloaded, err := io.CopyN(io.Discard, resp.Body, maxBytes)
	if err != nil {
		return outboundDownloadResult{}, fmt.Errorf(
			"download ended before %d bytes (%d bytes received): %w",
			maxBytes,
			bytesDownloaded,
			err,
		)
	}

	return outboundDownloadResult{
		BytesDownloaded: bytesDownloaded,
		ElapsedMillis:   time.Since(startedAt).Milliseconds(),
		TtfbMillis:      ttfbMillis,
		StatusCode:      resp.StatusCode,
	}, nil
}

// FastSelect concurrently tests candidate outbounds against a probe URL (defaulting to
// http://connectivitycheck.gstatic.com/generate_204) and returns the tag of the fastest responsive node.
// It uses early-return racing with a tight per-node timeout to avoid blocking on dead nodes.
func FastSelect(configJSON string, candidateTags string, probeURL string, timeoutMs int64) string {
	if configJSON == "" || candidateTags == "" {
		return ""
	}

	tags := strings.Split(candidateTags, ",")
	candidates := make([]string, 0, len(tags))
	for _, t := range tags {
		trimmed := strings.TrimSpace(t)
		if trimmed != "" {
			candidates = append(candidates, trimmed)
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	if len(candidates) == 1 {
		return candidates[0]
	}

	if probeURL == "" {
		probeURL = "http://connectivitycheck.gstatic.com/generate_204"
	}
	if timeoutMs <= 0 {
		timeoutMs = 1200
	}

	// Same stripped-down instance as the other probes: no inbounds, routing, geo data or
	// observatory, only what a forced-outbound dial needs.
	release := acquireProbeSlot()
	defer release()
	server, err := newProbeInstance(configJSON)
	if err != nil {
		return candidates[0]
	}
	defer closeProbeInstance(server)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()

	type probeResult struct {
		tag     string
		latency int64
		err     error
	}

	resultCh := make(chan probeResult, len(candidates))

	for _, tag := range candidates {
		go func(outboundTag string) {
			tr := &http.Transport{
				TLSHandshakeTimeout: time.Duration(timeoutMs) * time.Millisecond,
				DisableKeepAlives:   true,
				DialContext: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
					d, err := corenet.ParseDestination(fmt.Sprintf("%s:%s", network, addr))
					if err != nil {
						return nil, err
					}
					taggedCtx := session.SetForcedOutboundTagToContext(dialCtx, outboundTag)
					return core.Dial(taggedCtx, server, d)
				},
			}
			defer tr.CloseIdleConnections()

			client := &http.Client{
				Transport: tr,
				Timeout:   time.Duration(timeoutMs) * time.Millisecond,
			}

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
			if err != nil {
				resultCh <- probeResult{tag: outboundTag, latency: -1, err: err}
				return
			}

			start := time.Now()
			resp, err := client.Do(req)
			if err != nil {
				resultCh <- probeResult{tag: outboundTag, latency: -1, err: err}
				return
			}
			_ = resp.Body.Close()

			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
				dur := time.Since(start).Milliseconds()
				resultCh <- probeResult{tag: outboundTag, latency: dur, err: nil}
			} else {
				resultCh <- probeResult{tag: outboundTag, latency: -1, err: fmt.Errorf("bad status: %d", resp.StatusCode)}
			}
		}(tag)
	}

	var fastestTag string
	var lowestLatency int64 = 999999

	received := 0
	for received < len(candidates) {
		select {
		case res := <-resultCh:
			received++
			if res.err == nil && res.latency >= 0 {
				if fastestTag == "" {
					fastestTag = res.tag
					lowestLatency = res.latency
					if res.latency < 350 {
						return fastestTag
					}
				} else if res.latency < lowestLatency {
					fastestTag = res.tag
					lowestLatency = res.latency
				}
			}
		case <-ctx.Done():
			if fastestTag != "" {
				return fastestTag
			}
			return candidates[0]
		}
		if fastestTag != "" && (received >= (len(candidates)+1)/2 || received >= 3) {
			return fastestTag
		}
	}

	if fastestTag != "" {
		return fastestTag
	}
	return candidates[0]
}
