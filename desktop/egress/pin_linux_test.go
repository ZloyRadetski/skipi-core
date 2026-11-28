// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package egress

import (
	"context"
	gonet "net"
	"os"
	"syscall"
	"testing"

	"github.com/ZloyRadetski/skipi-core/desktop/multilink"
	"github.com/ZloyRadetski/skipi-core/desktop/multilink/nics"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

// With the TUN's controller in place Xray's dialer binds each socket to the physical interface first; a merged dial
// that then asks Xray for a link would bind it a second time, which the kernel refuses without CAP_NET_RAW. The dial
// has to succeed and leave the socket on the link it was given.
func TestMergedDialSucceedsWhileTheTunControllerBindsSockets(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root may rebind a socket, so the refusal cannot be seen")
	}
	lo, err := gonet.InterfaceByName("lo")
	if err != nil {
		t.Skip("no loopback interface")
	}
	listener, err := gonet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	bind := nics.ForceEgress(lo.Index, false)
	SetController(func(network, address string, c syscall.RawConn) error { return bind(network, address, c) })
	defer SetController(nil)

	d := NewDialer(&internet.DefaultSystemDialer{})
	d.SetScheduler(multilink.NewScheduler([]nics.Nic{
		{ID: "lo-a", Name: "lo", Index: lo.Index, IP: gonet.ParseIP("127.0.0.1"), Weight: 1},
		{ID: "lo-b", Name: "lo", Index: lo.Index, IP: gonet.ParseIP("127.0.0.1"), Weight: 1},
	}))
	port := listener.Addr().(*gonet.TCPAddr).Port
	// A domain destination is mergeable without being an address on the internet.
	dest := net.TCPDestination(net.ParseAddress("localhost"), net.Port(port))
	conn, err := d.Dial(context.Background(), nil, dest, nil)
	if err != nil {
		t.Fatalf("merged dial with the TUN controller in place failed: %v", err)
	}
	conn.Close()
}
