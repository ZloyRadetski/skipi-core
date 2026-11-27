// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package egress

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/ZloyRadetski/skipi-core/desktop/multilink"
	"github.com/ZloyRadetski/skipi-core/desktop/multilink/nics"
	xnet "github.com/xtls/xray-core/common/net"
)

func TestALinkWithAHandleIsBoundThroughTheHostBeforeItConnects(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			io.Copy(io.Discard, c)
			c.Close()
		}
	}()
	var mu sync.Mutex
	var bound []uint64
	nics.SetHostBinder(func(handle uint64, fd uintptr) error {
		mu.Lock()
		bound = append(bound, handle)
		mu.Unlock()
		return nil
	})
	defer nics.SetHostBinder(nil)

	sched := multilink.NewScheduler([]nics.Nic{{ID: "mobile", Name: "Mobile data", IP: net.IPv4(192, 0, 2, 1).To4(), Handle: 42, Weight: 1}})
	sl := sched.AcquireFor(multilink.Fam4, nil)
	if sl == nil {
		t.Fatal("no link")
	}
	addr := ln.Addr().(*net.TCPAddr)
	dest := xnet.TCPDestination(xnet.IPAddress(addr.IP), xnet.Port(addr.Port))
	conn, err := dialBound(context.Background(), sl, multilink.Fam4, dest, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(bound) != 1 || bound[0] != 42 {
		t.Fatalf("bound %v", bound)
	}
}

func TestAFailedBindFailsTheDial(t *testing.T) {
	nics.SetHostBinder(nil)
	sched := multilink.NewScheduler([]nics.Nic{{ID: "mobile", Name: "Mobile data", IP: net.IPv4(192, 0, 2, 1).To4(), Handle: 42, Weight: 1}})
	sl := sched.AcquireFor(multilink.Fam4, nil)
	dest := xnet.TCPDestination(xnet.IPAddress(net.IPv4(127, 0, 0, 1)), 9)
	if _, err := dialBound(context.Background(), sl, multilink.Fam4, dest, nil, 0); err == nil {
		t.Fatal("a link that cannot be bound must not dial")
	}
}
