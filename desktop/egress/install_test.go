// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package egress

import (
	"context"
	gonet "net"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

// Loading the package puts the SKIPI dialer in place, and the controller it carries reaches Xray's own dials.
func TestInstalledDialerCarriesTheController(t *testing.T) {
	if err := InstallError(); err != nil {
		t.Fatalf("install: %v", err)
	}
	ln, err := gonet.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
		}
	}()
	var seen atomic.Int32
	SetController(func(network, address string, c syscall.RawConn) error {
		seen.Add(1)
		return nil
	})
	defer SetController(nil)
	port := ln.Addr().(*gonet.TCPAddr).Port
	conn, err := internet.DialSystem(context.Background(), net.TCPDestination(net.LocalHostIP, net.Port(port)), nil)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if seen.Load() == 0 {
		t.Fatal("the controller did not see Xray's dial")
	}
	SetController(nil)
	conn, err = internet.DialSystem(context.Background(), net.TCPDestination(net.LocalHostIP, net.Port(port)), nil)
	if err == nil {
		conn.Close()
	}
	if seen.Load() != 1 {
		t.Fatal("a cleared controller still ran")
	}
}
