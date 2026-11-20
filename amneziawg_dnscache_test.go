// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func dnsTestRunner(lookup func(ctx context.Context, host string) ([]string, error)) *AmneziaWgRunner {
	return &AmneziaWgRunner{
		localAddrs: []netip.Addr{netip.MustParseAddr("10.8.0.2")},
		lookupHost: lookup,
	}
}

func TestAFailedLookupIsNotRepeatedWithinTheNegativeTTL(t *testing.T) {
	var calls atomic.Int32
	r := dnsTestRunner(func(ctx context.Context, host string) ([]string, error) {
		calls.Add(1)
		return nil, errors.New("no such host")
	})
	for i := 0; i < 5; i++ {
		if _, err := r.lookupTunnelHost(context.Background(), "dead.example"); err == nil {
			t.Fatal("a failed lookup must stay an error")
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("lookups = %d, want 1: a dead name must not stall every datagram", got)
	}
}

func TestAFailedLookupIsTriedAgainAfterTheNegativeTTL(t *testing.T) {
	var calls atomic.Int32
	r := dnsTestRunner(func(ctx context.Context, host string) ([]string, error) {
		calls.Add(1)
		return nil, errors.New("no such host")
	})
	old := tunnelDNSNegativeTTL
	tunnelDNSNegativeTTL = 20 * time.Millisecond
	defer func() { tunnelDNSNegativeTTL = old }()

	_, _ = r.lookupTunnelHost(context.Background(), "dead.example")
	time.Sleep(40 * time.Millisecond)
	_, _ = r.lookupTunnelHost(context.Background(), "dead.example")
	if got := calls.Load(); got != 2 {
		t.Fatalf("lookups = %d, want 2 after the negative entry expired", got)
	}
}

func TestConcurrentLookupsOfOneNameShareOneQuery(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	r := dnsTestRunner(func(ctx context.Context, host string) ([]string, error) {
		calls.Add(1)
		<-release
		return []string{"1.2.3.4"}, nil
	})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip, err := r.lookupTunnelHost(context.Background(), "busy.example")
			if err != nil || ip.String() != "1.2.3.4" {
				t.Errorf("got %v, %v", ip, err)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if got := calls.Load(); got != 1 {
		t.Fatalf("lookups = %d, want 1", got)
	}
}

func TestAFullCacheEvictsOneEntryInsteadOfDroppingAll(t *testing.T) {
	r := dnsTestRunner(func(ctx context.Context, host string) ([]string, error) {
		return []string{"1.2.3.4"}, nil
	})
	for i := 0; i < tunnelDNSCacheEntries; i++ {
		if _, err := r.lookupTunnelHost(context.Background(), fmt.Sprintf("h%d.example", i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.lookupTunnelHost(context.Background(), "extra.example"); err != nil {
		t.Fatal(err)
	}
	r.dnsMu.Lock()
	n := len(r.dnsCache)
	r.dnsMu.Unlock()
	if n != tunnelDNSCacheEntries {
		t.Fatalf("cache holds %d entries, want %d (one evicted, the rest kept)", n, tunnelDNSCacheEntries)
	}
}

func TestACallerThatGivesUpDoesNotPoisonTheSharedQuery(t *testing.T) {
	release := make(chan struct{})
	r := dnsTestRunner(func(ctx context.Context, host string) ([]string, error) {
		select {
		case <-release:
			return []string{"1.2.3.4"}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { _, err := r.lookupTunnelHost(ctx, "slow.example"); errc <- err }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	if err := <-errc; err == nil {
		t.Fatal("a cancelled caller must get an error")
	}
	close(release)
	// A later caller must still be able to resolve the name.
	if ip, err := r.lookupTunnelHost(context.Background(), "slow.example"); err != nil || ip == nil {
		t.Fatalf("later lookup: %v, %v", ip, err)
	}
}
