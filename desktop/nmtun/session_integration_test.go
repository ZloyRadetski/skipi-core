// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build linux

package nmtun

import (
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

// Runs against the real NetworkManager of the machine and only touches a throwaway interface with
// a documentation-range route. Enable with SKIPI_NM_INTEGRATION=1.
func TestSessionAttachesAnUnprivilegedProcessToANetworkManagerTun(t *testing.T) {
	if os.Getenv("SKIPI_NM_INTEGRATION") != "1" {
		t.Skip("set SKIPI_NM_INTEGRATION=1 to run against the real NetworkManager")
	}
	plan := Plan{
		Name:      "skipi-it0",
		MTU:       1400,
		Addresses: []string{"172.31.253.1/30"},
		Routes:    []string{"203.0.113.0/24"},
	}

	session, err := Open(plan)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = session.Close()
		}
	}()

	iface, err := net.InterfaceByName(plan.Name)
	if err != nil {
		t.Fatalf("interface: %v", err)
	}
	if iface.MTU != 1400 {
		t.Errorf("MTU = %d", iface.MTU)
	}
	addresses, _ := iface.Addrs()
	found := false
	for _, a := range addresses {
		if a.String() == "172.31.253.1/30" {
			found = true
		}
	}
	if !found {
		t.Errorf("address not configured: %v", addresses)
	}

	conn, err := net.Dial("udp", "203.0.113.5:9")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte("skipi"))
	_ = conn.Close()
	packet := make([]byte, 2048)
	_ = syscall.SetNonblock(session.FD(), false)
	received := make(chan int, 1)
	go func() {
		n, _ := syscall.Read(session.FD(), packet)
		received <- n
	}()
	select {
	case n := <-received:
		if n < 20 || packet[0]>>4 != 4 {
			t.Errorf("unexpected packet of %d bytes", n)
		}
	case <-time.After(5 * time.Second):
		t.Error("no packet reached the tun fd")
	}

	if err := session.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	closed = true
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := net.InterfaceByName(plan.Name); err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Error("interface still exists after Close")
}
