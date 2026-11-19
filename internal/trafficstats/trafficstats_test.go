package trafficstats

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTrafficStatsSnapshotFromTotalsSeparatesDirectionsAndTags(t *testing.T) {
	snapshot := SnapshotFromTotals(map[string]int64{
		"inbound>>>socks-in>>>traffic>>>uplink":       11,
		"inbound>>>socks-in>>>traffic>>>downlink":     22,
		"outbound>>>proxy>>>traffic>>>uplink":         33,
		"outbound>>>proxy>>>traffic>>>downlink":       44,
		"outbound>>>direct>>>traffic>>>uplink":        55,
		"not-a-traffic-counter":                       99,
		"inbound>>>missing-direction>>>traffic>>>bad": 77,
	})

	if got := snapshot.Inbound["socks-in"]; got != (Bytes{Uplink: 11, Downlink: 22}) {
		t.Fatalf("unexpected inbound stats: %+v", got)
	}
	if got := snapshot.Outbound["proxy"]; got != (Bytes{Uplink: 33, Downlink: 44}) {
		t.Fatalf("unexpected proxy stats: %+v", got)
	}
	if got := snapshot.Outbound["direct"]; got != (Bytes{Uplink: 55}) {
		t.Fatalf("unexpected direct stats: %+v", got)
	}
	if _, found := snapshot.Inbound["missing-direction"]; found {
		t.Fatal("invalid traffic counter must not appear in the snapshot")
	}

	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("snapshot must be JSON encodable: %v", err)
	}
	if !strings.Contains(string(encoded), `"inbound"`) || !strings.Contains(string(encoded), `"outbound"`) {
		t.Fatalf("snapshot JSON must retain both directions: %s", encoded)
	}
}
