package probe

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
