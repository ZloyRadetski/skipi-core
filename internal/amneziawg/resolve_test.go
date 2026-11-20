package amneziawg

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
)

func TestResolveAmneziaWgEndpointPrefersIPv4Literal(t *testing.T) {
	endpoint, err := ResolveEndpoint("relay.example:50125", func(_ context.Context, host string) ([]netip.Addr, error) {
		if host != "relay.example" {
			t.Fatalf("unexpected lookup host %q", host)
		}
		return []netip.Addr{
			netip.MustParseAddr("2001:db8::10"),
			netip.MustParseAddr("198.51.100.25"),
		}, nil
	})
	if err != nil {
		t.Fatalf("resolveAmneziaWgEndpoint failed: %v", err)
	}
	if endpoint != "198.51.100.25:50125" {
		t.Fatalf("unexpected resolved endpoint %q", endpoint)
	}
}

func TestAmneziaWgEndpointLookupFallsBackToConfiguredDNS(t *testing.T) {
	systemLookups := 0
	configuredDNSLookups := 0
	addresses, err := LookupHostWithFallback(
		context.Background(),
		"relay.example",
		func(_ context.Context, host string) ([]netip.Addr, error) {
			systemLookups++
			if host != "relay.example" {
				t.Fatalf("unexpected system lookup host %q", host)
			}
			return nil, fmt.Errorf("system resolver unavailable")
		},
		func(_ context.Context, host string) ([]netip.Addr, error) {
			configuredDNSLookups++
			if host != "relay.example" {
				t.Fatalf("unexpected configured DNS lookup host %q", host)
			}
			return []netip.Addr{netip.MustParseAddr("198.51.100.25")}, nil
		},
	)
	if err != nil {
		t.Fatalf("configured DNS fallback failed: %v", err)
	}
	if systemLookups != 1 || configuredDNSLookups != 1 {
		t.Fatalf("expected one system and one configured DNS lookup, got system=%d configured=%d", systemLookups, configuredDNSLookups)
	}
	if len(addresses) != 1 || addresses[0].String() != "198.51.100.25" {
		t.Fatalf("unexpected fallback addresses %v", addresses)
	}
}

// C6: the lookup of the peer's name goes out through a socket the caller can protect or bind.
func TestConfiguredDNSLookupDialsThroughTheGivenControl(t *testing.T) {
	var called atomic.Int32
	control := func(network, address string, c syscall.RawConn) error {
		called.Add(1)
		return errors.New("refused by the protector")
	}
	_, err := LookupHostWithConfiguredDNS(context.Background(), "relay.example", []netip.Addr{netip.MustParseAddr("127.0.0.1")}, control)
	if err == nil || called.Load() == 0 {
		t.Fatalf("err = %v, control called %d times", err, called.Load())
	}
}
