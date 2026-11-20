package probe

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/core"
)

func TestMeasureOutboundDownloadReadsExactRequestedBytes(t *testing.T) {
	const requestedBytes = int64(256 * 1024)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Cache-Control"); got != "no-cache" {
			t.Errorf("expected no-cache request header, got %q", got)
		}
		w.Header().Set("Content-Length", fmt.Sprintf("%d", requestedBytes))
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, strings.Repeat("x", int(requestedBytes)))
	}))
	defer ts.Close()

	configJSON := `{
		"log": {
			"loglevel": "none"
		},
		"outbounds": [
			{
				"protocol": "freedom",
				"tag": "direct"
			}
		]
	}`

	encoded, err := Download(
		configJSON,
		ts.URL,
		requestedBytes,
		10_000,
		"",
	)
	if err != nil {
		t.Fatalf("Download failed: %v", err)
	}

	var result outboundDownloadResult
	if err := json.Unmarshal([]byte(encoded), &result); err != nil {
		t.Fatalf("invalid download result JSON: %v; value=%s", err, encoded)
	}
	if result.BytesDownloaded != requestedBytes {
		t.Fatalf("expected %d downloaded bytes, got %d", requestedBytes, result.BytesDownloaded)
	}
	if result.StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, result.StatusCode)
	}
	if result.ElapsedMillis < 0 || result.TtfbMillis < 0 {
		t.Fatalf("expected non-negative timings, got elapsed=%d ttfb=%d", result.ElapsedMillis, result.TtfbMillis)
	}
}

func TestMeasureOutboundDownloadRejectsUnsafeLimits(t *testing.T) {
	if _, err := Download("{}", "https://example.com", 0, 10_000, ""); err == nil {
		t.Fatal("expected zero-byte download to be rejected")
	}
	if _, err := Download("{}", "https://example.com", maxOutboundDownloadBytes+1, 10_000, ""); err == nil {
		t.Fatal("expected oversized download to be rejected")
	}
	if _, err := Download("{}", "https://example.com", 1, minOutboundDownloadTimeoutMillis-1, ""); err == nil {
		t.Fatal("expected short timeout to be rejected")
	}
}

func TestCancelOutboundDownloadStopsRunningRequest(t *testing.T) {
	started := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1")
		w.WriteHeader(http.StatusOK)
		close(started)
		<-r.Context().Done()
	}))
	defer ts.Close()

	configJSON := `{
		"log": { "loglevel": "none" },
		"outbounds": [{ "protocol": "freedom", "tag": "direct" }]
	}`
	const requestID = "cancel-outbound-download-test"
	done := make(chan error, 1)
	go func() {
		_, err := Download(configJSON, ts.URL, 1, 60_000, requestID)
		done <- err
	}()

	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("download request did not start")
	}

	CancelDownload(requestID)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected cancelled download to return an error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled download did not stop promptly")
	}
}

const directConfig = `{"log":{"loglevel":"none"},"outbounds":[{"protocol":"freedom","tag":"direct"}]}`

// M8: a cancel that arrives while the test instance is still starting, or even before the
// download was called, is not lost.
func TestCancelBeforeTheInstanceIsUpStopsTheDownload(t *testing.T) {
	requests := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++ }))
	defer ts.Close()

	gate, entered := make(chan struct{}), make(chan struct{})
	orig := newProbeInstance
	newProbeInstance = func(cfg string) (*core.Instance, error) {
		close(entered)
		<-gate
		return startOutboundTestInstance(cfg)
	}
	defer func() { newProbeInstance = orig }()

	done := make(chan error, 1)
	go func() {
		_, err := Download(directConfig, ts.URL, 1, 60_000, "early-cancel")
		done <- err
	}()
	<-entered
	CancelDownload("early-cancel")
	close(gate)
	if err := <-done; err == nil || !strings.Contains(err.Error(), "cancel") {
		t.Fatalf("err = %v", err)
	}

	newProbeInstance = orig
	CancelDownload("cancelled-first")
	if _, err := Download(directConfig, ts.URL, 1, 60_000, "cancelled-first"); err == nil || !strings.Contains(err.Error(), "cancel") {
		t.Fatalf("a cancel before the call: err = %v", err)
	}
	if requests != 0 {
		t.Fatalf("a cancelled download still reached the server %d times", requests)
	}
}

// M7: every probe builds an Xray instance; however many the app asks for at once, only a bounded
// number exist at a time.
func TestProbesRunABoundedNumberOfInstancesAtOnce(t *testing.T) {
	defer func(old int) { setProbeSlots(old) }(cap(probeSlots))
	setProbeSlots(3)
	var mu sync.Mutex
	now, peak := 0, 0
	orig := newProbeInstance
	newProbeInstance = func(string) (*core.Instance, error) {
		mu.Lock()
		now++
		peak = max(peak, now)
		mu.Unlock()
		time.Sleep(30 * time.Millisecond)
		mu.Lock()
		now--
		mu.Unlock()
		return nil, errors.New("no instance in this test")
	}
	defer func() { newProbeInstance = orig }()

	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = Delay(directConfig, "http://127.0.0.1:1") }()
	}
	wg.Wait()
	if peak > 3 {
		t.Fatalf("%d instances at once, want at most 3", peak)
	}
}

type hangingCloser struct{ release chan struct{} }

func (h hangingCloser) Close() error { <-h.release; return nil }

// M7: closing a test instance is bounded; one that hangs is abandoned, not waited for.
func TestClosingAProbeInstanceIsBounded(t *testing.T) {
	defer func(old time.Duration) { probeCloseTimeout = old }(probeCloseTimeout)
	probeCloseTimeout = 50 * time.Millisecond
	h := hangingCloser{release: make(chan struct{})}
	defer close(h.release)
	began := time.Now()
	closeProbeInstance(h)
	if took := time.Since(began); took > time.Second {
		t.Fatalf("close took %v", took)
	}
}

// Perf 2: a probe needs only the outbounds. Routing, DNS and the rest are cut from the JSON
// before it is parsed, so a probe never scans the geo files (and never fails on them).
func TestAProbeInstanceIsBuiltWithoutReadingRoutingOrDNS(t *testing.T) {
	t.Setenv("xray.location.asset", t.TempDir()) // no geo files here at all
	config := `{
		"log": {"loglevel": "none"},
		"inbounds": [{"port": 1, "protocol": "socks"}],
		"dns": {"servers": [{"address": "1.1.1.1", "domains": ["geosite:no-such-list"]}]},
		"routing": {"rules": [{"type": "field", "domain": ["geosite:no-such-list"], "outboundTag": "direct"},
			{"type": "field", "ip": ["geoip:no-such-list"], "outboundTag": "direct"}]},
		"observatory": {"subjectSelector": ["direct"]},
		"outbounds": [{"protocol": "freedom", "tag": "direct"}]
	}`
	inst, err := startOutboundTestInstance(config)
	if err != nil {
		t.Fatalf("the probe instance read what it does not need: %v", err)
	}
	_ = inst.Close()
}

// Perf 3: pinging N servers builds one instance for all of them, not one each, and reports every
// tag: its delay, or -1 when it failed.
func TestDelaysMeasureEveryTagThroughOneInstance(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	built := 0
	orig := newProbeInstance
	newProbeInstance = func(cfg string) (*core.Instance, error) { built++; return orig(cfg) }
	defer func() { newProbeInstance = orig }()

	config := `{"log":{"loglevel":"none"},"outbounds":[
		{"protocol":"freedom","tag":"a"},{"protocol":"freedom","tag":"b"},{"protocol":"blackhole","tag":"dead"}]}`
	out := Delays(config, "a, b,dead,missing", ts.URL, 3000)
	var got map[string]int64
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if built != 1 {
		t.Fatalf("built %d instances, want 1", built)
	}
	if got["a"] < 0 || got["b"] < 0 {
		t.Fatalf("reachable tags failed: %v", got)
	}
	if got["dead"] != -1 || got["missing"] != -1 || len(got) != 4 {
		t.Fatalf("failed tags must be -1 and every tag reported: %v", got)
	}
	if out := Delays("not json", "a", ts.URL, 1000); out != `{"a":-1}` {
		t.Fatalf("a config that does not load fails every tag: %s", out)
	}
}
