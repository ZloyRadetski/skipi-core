// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package egress

import (
	"context"
	"errors"
	"io"
	gonet "net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/ZloyRadetski/skipi-core/desktop/multilink"
	"github.com/ZloyRadetski/skipi-core/desktop/multilink/nics"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

type dialCall struct {
	src     net.Address
	dest    net.Destination
	sockopt *internet.SocketConfig
}

// fakeBase records what Xray's own dialer would have been asked and answers with fail(call) or a fresh pipe.
type fakeBase struct {
	calls []dialCall
	fail  func(call dialCall) error
	last  net.Conn
}

func (b *fakeBase) Dial(_ context.Context, src net.Address, dest net.Destination, sockopt *internet.SocketConfig) (net.Conn, error) {
	call := dialCall{src, dest, sockopt}
	b.calls = append(b.calls, call)
	if b.fail != nil {
		if err := b.fail(call); err != nil {
			return nil, err
		}
	}
	client, server := gonet.Pipe()
	go io.Copy(io.Discard, server)
	b.last = client
	if dest.Network == net.Network_UDP {
		client.Close()
		packet, err := gonet.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		b.last = &net.PacketConnWrapper{PacketConn: packet, Dest: &gonet.UDPAddr{IP: dest.Address.IP(), Port: int(dest.Port)}}
	}
	return b.last, nil
}

func (b *fakeBase) DestIpAddress() net.IP { return nil }

func twoLinks() *multilink.Scheduler {
	return multilink.NewScheduler([]nics.Nic{
		{ID: "{eth}", Name: "Ethernet 2", Index: 19, IP: gonet.ParseIP("192.168.1.200"), Weight: 1},
		{ID: "{wifi}", Name: "Wi-Fi", Index: 15, IP: gonet.ParseIP("192.168.168.111"), Weight: 1},
	})
}

var server = net.TCPDestination(net.ParseAddress("203.0.113.7"), 443)

func dialTo(t *testing.T, d *Dialer, src net.Address, dest net.Destination, sockopt *internet.SocketConfig) net.Conn {
	t.Helper()
	conn, err := d.Dial(context.Background(), src, dest, sockopt)
	if err != nil {
		t.Fatalf("Dial(%v) = %v", dest, err)
	}
	return conn
}

func sameCall(t *testing.T, got dialCall, src net.Address, dest net.Destination, sockopt *internet.SocketConfig) {
	t.Helper()
	if got.src != src || got.dest != dest || got.sockopt != sockopt {
		t.Fatalf("Xray's dialer got (%v, %v, %p), want the call unchanged (%v, %v, %p)", got.src, got.dest, got.sockopt, src, dest, sockopt)
	}
}

// Off, the dialer is Xray's own: the same arguments reach it and its connection comes back as it is.
func TestOffPassesEveryDialThroughUnchanged(t *testing.T) {
	base := &fakeBase{}
	d := NewDialer(base)
	sockopt := &internet.SocketConfig{Mark: 7}
	conn := dialTo(t, d, nil, server, sockopt)
	defer conn.Close()
	sameCall(t, base.calls[0], nil, server, sockopt)
	if conn != base.last {
		t.Fatalf("the connection came back as %T, want Xray's own", conn)
	}
}

// With one usable link there is nothing to merge, and the dial is exactly today's.
func TestOneUsableLinkPassesThroughUnchanged(t *testing.T) {
	base := &fakeBase{}
	d := NewDialer(base)
	d.SetScheduler(multilink.NewScheduler([]nics.Nic{{ID: "{eth}", Name: "Ethernet 2", IP: gonet.ParseIP("192.168.1.200"), Weight: 1}}))
	sockopt := &internet.SocketConfig{}
	dialTo(t, d, nil, server, sockopt).Close()
	sameCall(t, base.calls[0], nil, server, sockopt)
}

// Two links: each new connection leaves through one of them, named in a copy of the socket options and bound
// to its address; the caller's options stay as they were.
func TestTwoLinksSpreadConnectionsAndPinEach(t *testing.T) {
	base := &fakeBase{}
	d := NewDialer(base)
	d.SetScheduler(twoLinks())
	sockopt := &internet.SocketConfig{Mark: 7}
	var conns []net.Conn
	for range 4 {
		conns = append(conns, dialTo(t, d, nil, server, sockopt))
	}
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	byLink := map[string]int{}
	for _, call := range base.calls {
		if call.sockopt == sockopt {
			t.Fatal("the caller's socket options were changed in place")
		}
		if call.sockopt.Mark != 7 {
			t.Fatalf("the copy lost the caller's options: %+v", call.sockopt)
		}
		want := map[string]string{"Ethernet 2": "192.168.1.200", "Wi-Fi": "192.168.168.111"}[call.sockopt.Interface]
		if want == "" || call.src == nil || call.src.String() != want {
			t.Fatalf("pinned to %q from %v, want a link and its own address", call.sockopt.Interface, call.src)
		}
		byLink[call.sockopt.Interface]++
	}
	if byLink["Ethernet 2"] != 2 || byLink["Wi-Fi"] != 2 {
		t.Fatalf("4 open connections went %v, want 2 on each link", byLink)
	}
	if sockopt.Interface != "" {
		t.Fatalf("the caller's options now name %q", sockopt.Interface)
	}
}

// What the user or Xray already decided stays: a sockopt interface, a sendThrough address, and destinations that
// are not on the internet (the LAN, loopback, link-local, the TUN's fake range).
func TestDecidedOrLocalDialsPassThrough(t *testing.T) {
	for _, tc := range []struct {
		name    string
		src     net.Address
		dest    net.Destination
		sockopt *internet.SocketConfig
	}{
		{"interface set", nil, server, &internet.SocketConfig{Interface: "Wi-Fi"}},
		{"sendThrough", net.ParseAddress("192.168.168.111"), server, nil},
		{"loopback", nil, net.TCPDestination(net.ParseAddress("127.0.0.1"), 10808), nil},
		{"LAN", nil, net.TCPDestination(net.ParseAddress("192.168.1.1"), 80), nil},
		{"private 10/8", nil, net.TCPDestination(net.ParseAddress("10.1.2.3"), 80), nil},
		{"link-local", nil, net.TCPDestination(net.ParseAddress("169.254.1.1"), 80), nil},
		{"CGNAT", nil, net.TCPDestination(net.ParseAddress("100.64.0.1"), 80), nil},
		{"fake range", nil, net.TCPDestination(net.ParseAddress("198.18.0.5"), 80), nil},
		{"multicast", nil, net.UDPDestination(net.ParseAddress("239.255.255.250"), 1900), nil},
		{"IPv6 ULA", nil, net.TCPDestination(net.ParseAddress("fd00::1"), 80), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := &fakeBase{}
			d := NewDialer(base)
			d.SetScheduler(twoLinks())
			dialTo(t, d, tc.src, tc.dest, tc.sockopt).Close()
			sameCall(t, base.calls[0], tc.src, tc.dest, tc.sockopt)
		})
	}
}

func unreachable() error {
	return &gonet.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ENETUNREACH)}
}

// A link that cannot reach the network is left for another one within the same dial, and sidelined.
func TestBrokenLinkFailsOverWithinTheDial(t *testing.T) {
	base := &fakeBase{fail: func(call dialCall) error {
		if call.sockopt != nil && call.sockopt.Interface == "Wi-Fi" {
			return unreachable()
		}
		return nil
	}}
	d := NewDialer(base)
	sched := twoLinks()
	d.SetScheduler(sched)
	for range 40 {
		dialTo(t, d, nil, server, nil).Close()
	}
	wifiDials := 0
	for _, call := range base.calls {
		if call.sockopt != nil && call.sockopt.Interface == "Wi-Fi" {
			wifiDials++
		}
	}
	if wifiDials != 1 {
		t.Fatalf("Wi-Fi was dialed %d times, want once: after the link error it is sidelined", wifiDials)
	}
}

// A refusal would come from every link: it is returned at once.
func TestRefusalIsNotRetried(t *testing.T) {
	refused := &gonet.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	base := &fakeBase{fail: func(dialCall) error { return refused }}
	d := NewDialer(base)
	d.SetScheduler(twoLinks())
	if _, err := d.Dial(context.Background(), nil, server, nil); !errors.Is(err, refused) {
		t.Fatalf("Dial = %v, want the refusal", err)
	}
	if len(base.calls) != 1 {
		t.Fatalf("%d dials, want 1", len(base.calls))
	}
}

// When every link fails the dial reports the last error, and nothing is left counted on any link.
func TestAllLinksFailingReturnsTheErrorAndReleases(t *testing.T) {
	base := &fakeBase{fail: func(dialCall) error { return unreachable() }}
	d := NewDialer(base)
	sched := twoLinks()
	d.SetScheduler(sched)
	if _, err := d.Dial(context.Background(), nil, server, nil); err == nil {
		t.Fatal("Dial succeeded with every link down")
	}
	if len(base.calls) != 2 {
		t.Fatalf("%d dials, want one per link", len(base.calls))
	}
	for _, st := range sched.Snapshot() {
		if st.Active != 0 {
			t.Fatalf("%s still counts %d flows", st.Name, st.Active)
		}
	}
}

// A domain is resolved by Xray's dialer as today, so no source address is forced; only the link is named.
func TestDomainDestinationIsPinnedWithoutASourceAddress(t *testing.T) {
	base := &fakeBase{}
	d := NewDialer(base)
	d.SetScheduler(twoLinks())
	dialTo(t, d, nil, net.TCPDestination(net.ParseAddress("example.com"), 443), nil).Close()
	call := base.calls[0]
	if call.sockopt == nil || call.sockopt.Interface == "" || call.src != nil {
		t.Fatalf("got interface %v from %v, want a link and no source", call.sockopt, call.src)
	}
}

// UDP is pinned too, but the socket comes back as Xray's own type: masque, WireGuard and udphop assert it, and
// quic-go only enables GSO on a bare UDP socket.
func TestUDPIsPinnedAndReturnedAsItIs(t *testing.T) {
	base := &fakeBase{}
	d := NewDialer(base)
	sched := twoLinks()
	d.SetScheduler(sched)
	conn := dialTo(t, d, nil, net.UDPDestination(net.ParseAddress("203.0.113.7"), 443), nil)
	if _, ok := conn.(*net.PacketConnWrapper); !ok {
		t.Fatalf("UDP came back as %T, want *net.PacketConnWrapper", conn)
	}
	if base.calls[0].sockopt == nil || base.calls[0].sockopt.Interface == "" {
		t.Fatal("the UDP socket was not pinned to a link")
	}
	for _, st := range sched.Snapshot() {
		if st.Active != 0 {
			t.Fatalf("%s counts %d flows for a UDP socket", st.Name, st.Active)
		}
	}
}

// Switching off takes effect for the next dial; open connections stay where they are.
func TestSwitchingOffAffectsOnlyNewDials(t *testing.T) {
	base := &fakeBase{}
	d := NewDialer(base)
	d.SetScheduler(twoLinks())
	open := dialTo(t, d, nil, server, nil)
	defer open.Close()
	d.SetScheduler(nil)
	dialTo(t, d, nil, server, nil).Close()
	sameCall(t, base.calls[1], nil, server, nil)
	if _, err := open.Write([]byte("x")); err != nil {
		t.Fatalf("an open connection broke when merging was switched off: %v", err)
	}
}

// A measurement must come back from the same link every time, or the numbers jump between the links' paths.
func TestMeasurementsAreNotMerged(t *testing.T) {
	base := &fakeBase{}
	d := NewDialer(base)
	d.SetScheduler(twoLinks())
	conn, err := d.Dial(WithoutMerging(context.Background()), nil, server, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	sameCall(t, base.calls[0], nil, server, nil)
}

// The scheduler can lose its last link between the usable count and the pick; the dial then goes the way Xray's
// own dialer takes rather than returning no connection and no error.
func TestNoLinkPickedFallsBackToTheBaseDialer(t *testing.T) {
	base := &fakeBase{}
	d := NewDialer(base)
	d.SetScheduler(twoLinks())
	d.acquire = func(multilink.Family, map[string]struct{}) *multilink.Slot { return nil }
	conn, err := d.Dial(context.Background(), nil, server, nil)
	if conn == nil || err != nil {
		t.Fatalf("Dial = %v, %v", conn, err)
	}
	conn.Close()
	if len(base.calls) != 1 || base.calls[0].sockopt != nil {
		t.Fatalf("calls %+v", base.calls)
	}
}

// While another link is left to try, one attempt gets a short time; the last one keeps the whole budget.
func TestAHangingLinkIsGivenUpEarlyWhileAnotherIsLeft(t *testing.T) {
	old := attemptTimeout
	attemptTimeout = 50 * time.Millisecond
	defer func() { attemptTimeout = old }()
	var deadlines []bool
	base := &fakeBase{}
	hang := &hangingBase{fakeBase: base, deadlines: &deadlines}
	d := NewDialer(hang)
	d.SetScheduler(twoLinks())
	conn := dialTo(t, d, nil, server, nil)
	conn.Close()
	if len(deadlines) != 2 || !deadlines[0] || deadlines[1] {
		t.Fatalf("attempt deadlines %v, want [true false]", deadlines)
	}
}

// hangingBase never answers its first dial until the context ends.
type hangingBase struct {
	*fakeBase
	deadlines *[]bool
}

func (b *hangingBase) Dial(ctx context.Context, src net.Address, dest net.Destination, sockopt *internet.SocketConfig) (net.Conn, error) {
	_, has := ctx.Deadline()
	*b.deadlines = append(*b.deadlines, has)
	if len(*b.deadlines) == 1 {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return b.fakeBase.Dial(ctx, src, dest, sockopt)
}
