// Based on net-merge (https://github.com/net-merge/net-merge), Copyright (c) 2026 Rohit Mahto, MIT License;
// see third_party/net-merge. Changes for SKIPI Core: Copyright 2026, Radetski, GPL-3.0.

package multilink

import (
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/ZloyRadetski/skipi-core/desktop/multilink/nics"
)

// pipeServer accepts one connection on loopback and hands it to serve.
func pipeServer(t *testing.T, serve func(net.Conn)) net.Conn {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		serve(c)
		c.Close()
	}()
	raw, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestOpenedConnPacesWrites(t *testing.T) {
	s := NewScheduler(nil)
	sl := &Slot{}
	sl.setLimit(80) // 10 MB/s
	c := s.Open(pipeServer(t, func(c net.Conn) { io.Copy(io.Discard, c) }), sl, Fam4)
	defer c.Close()

	const size = 2 << 20 // 2 MB at 10 MB/s is 200 ms, minus the 500 KB burst
	start := time.Now()
	if _, err := c.Write(make([]byte, size)); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < 60*time.Millisecond || d > 2*time.Second {
		t.Fatalf("2 MB through a limited connection took %s, want about 150-300 ms", d)
	}
}

func TestOpenedConnPacesReads(t *testing.T) {
	s := NewScheduler(nil)
	sl := &Slot{}
	sl.setLimit(80) // 10 MB/s
	raw := pipeServer(t, func(c net.Conn) { c.Write(make([]byte, 2<<20)) })
	if err := raw.(*net.TCPConn).SetReadBuffer(32 << 10); err != nil {
		t.Fatal(err)
	}
	c := s.Open(raw, sl, Fam4)
	defer c.Close()

	const size = 2 << 20
	buf := make([]byte, 64<<10)
	start := time.Now()
	for read := 0; read < size; {
		n, err := c.Read(buf)
		read += n
		if err != nil {
			t.Fatalf("after %d bytes: %v", read, err)
		}
	}
	if d := time.Since(start); d < 60*time.Millisecond || d > 2*time.Second {
		t.Fatalf("2 MB through a limited connection took %s, want about 150-300 ms", d)
	}
}

// A connection counts on its link from the dial until it is closed, and only once however often it is closed.
func TestOpenedConnHoldsItsLinkUntilClosed(t *testing.T) {
	s := NewScheduler([]nics.Nic{nic("A", "10.0.0.1", 1)})
	sl := s.AcquireFor(Fam4, nil)
	c := s.Open(pipeServer(t, func(c net.Conn) { io.Copy(io.Discard, c) }), sl, Fam4)
	if got := sl.active.Load(); got != 1 {
		t.Fatalf("active while open = %d, want 1", got)
	}
	c.Close()
	c.Close()
	if got := sl.active.Load(); got != 0 {
		t.Fatalf("active after close = %d, want 0", got)
	}
	s.mu.Lock()
	flows := len(sl.flows[Fam4])
	s.mu.Unlock()
	if flows != 0 {
		t.Fatalf("%d flows still tracked after close, want 0", flows)
	}
}

// A half-close ends the flow for balancing (the peer may take a minute to finish) and still reaches the socket.
func TestOpenedConnHalfCloseReleasesAndPassesThrough(t *testing.T) {
	s := NewScheduler([]nics.Nic{nic("A", "10.0.0.1", 1)})
	sl := s.AcquireFor(Fam4, nil)
	got := make(chan error, 1)
	c := s.Open(pipeServer(t, func(c net.Conn) {
		_, err := c.Read(make([]byte, 1))
		got <- err
	}), sl, Fam4)
	defer c.Close()
	cw, ok := c.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("the connection hides CloseWrite")
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-got:
		if err != io.EOF {
			t.Fatalf("the peer read %v, want EOF", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the half-close did not reach the peer")
	}
	if n := sl.active.Load(); n != 0 {
		t.Fatalf("active after CloseWrite = %d, want 0", n)
	}
}

func TestOpenedConnCountsBytesOnItsLink(t *testing.T) {
	s := NewScheduler([]nics.Nic{nic("A", "10.0.0.1", 1)})
	sl := s.AcquireFor(Fam4, nil)
	c := s.Open(pipeServer(t, func(c net.Conn) { io.CopyN(c, c, 5) }), sl, Fam4)
	defer c.Close()
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, 5)); err != nil {
		t.Fatal(err)
	}
	st := s.Snapshot()[0]
	if st.BytesOut != 5 || st.BytesIn != 5 {
		t.Fatalf("counted in %d out %d, want 5 and 5", st.BytesIn, st.BytesOut)
	}
}

func TestUsableCountsLinksThatCanCarryTheFamily(t *testing.T) {
	v6 := nic("B", "10.0.0.2", 1)
	v6.IP6 = net.ParseIP("2001:db8::2")
	s := NewScheduler([]nics.Nic{nic("A", "10.0.0.1", 1), v6, nic("C", "10.0.0.3", 1)})
	if got := s.Usable(Fam4); got != 3 {
		t.Fatalf("Usable(v4) = %d, want 3", got)
	}
	if got := s.Usable(Fam6); got != 1 {
		t.Fatalf("Usable(v6) = %d, want 1", got)
	}
	// A link whose probe failed carries nothing while another works.
	s.SetState(s.slots[2], Fam4, false)
	if got := s.Usable(Fam4); got != 2 {
		t.Fatalf("Usable(v4) with a dead link = %d, want 2", got)
	}
	s.Fail(s.slots[1], Fam4, time.Minute)
	if got := s.Usable(Fam4); got != 1 {
		t.Fatalf("Usable(v4) with a link in cooldown = %d, want 1", got)
	}
}

func TestClassifyDialErrors(t *testing.T) {
	op := func(errno syscall.Errno) error {
		return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connectex", errno)}
	}
	for _, tc := range []struct {
		name            string
		err             error
		retry, linkDown bool
	}{
		{"network unreachable", op(wsaeNetUnreach), true, true},
		{"network down", op(wsaeNetDown), true, true},
		{"address not available", op(wsaeAddrNotAvail), true, true},
		{"host unreachable", op(wsaeHostUnreach), true, false},
		{"timed out", op(wsaeTimedOut), true, false},
		{"refused", op(wsaeConnRefused), false, false},
		{"name not found", &net.DNSError{Err: "no such host", Name: "example.com"}, false, false},
		{"other", errors.New("boom"), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			retry, linkDown := Classify(tc.err)
			if retry != tc.retry || linkDown != tc.linkDown {
				t.Fatalf("Classify = retry %v link down %v, want %v %v", retry, linkDown, tc.retry, tc.linkDown)
			}
		})
	}
}
