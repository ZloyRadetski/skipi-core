// Based on net-merge (https://github.com/net-merge/net-merge), Copyright (c) 2026 Rohit Mahto, MIT License;
// see third_party/net-merge. Changes for SKIPI Core: Copyright 2026, Radetski, GPL-3.0.

package multilink

import (
	"context"
	"errors"
	"net"
	"sync"
	"syscall"
	"time"
)

// flowConn is one connection that the scheduler placed on a link. It counts the connection's bytes on that link,
// paces them when the link has a cap, and ends the flow for balancing at the first close or half-close: a finished
// connection can wait a minute for the peer, and counting it as busy would steer new flows away from that link.
type flowConn struct {
	net.Conn
	sl       *Slot
	fam      Family
	s        *Scheduler
	once     sync.Once
	activity *flowActivity
}

// Open hands a connection dialed out of sl to the scheduler. sl comes from AcquireFor; from here the returned
// connection releases it when it closes, so the caller must not call ReleaseFor for it.
func (s *Scheduler) Open(conn net.Conn, sl *Slot, f Family) net.Conn {
	return &flowConn{Conn: conn, sl: sl, fam: f, s: s, activity: s.track(sl, f)}
}

func (c *flowConn) Read(p []byte) (int, error) {
	if pair := c.sl.limit.Load(); pair != nil && len(p) > pair.chunk {
		p = p[:pair.chunk] // hand out a chunk at a time, so a limited flow stays smooth
	}
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.sl.bytesIn[c.fam].Add(int64(n))
		c.activity.bytes.Add(int64(n))
		c.sl.throttle(true, n)
	}
	return n, err
}

func (c *flowConn) Write(p []byte) (int, error) {
	n, err := c.sl.writePaced(c.Conn, p, false)
	c.sl.bytesOut[c.fam].Add(int64(n))
	c.activity.bytes.Add(int64(n))
	return n, err
}

func (c *flowConn) release() {
	c.once.Do(func() {
		c.s.untrack(c.sl, c.fam, c.activity)
		c.s.ReleaseFor(c.sl, c.fam)
	})
}

func (c *flowConn) Close() error { c.release(); return c.Conn.Close() }

func (c *flowConn) CloseWrite() error {
	c.release()
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

func (c *flowConn) CloseRead() error {
	c.release()
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

// Windows socket error codes; the portable syscall.E* constants don't match them on Windows.
const (
	wsaeAddrNotAvail syscall.Errno = 10049
	wsaeNetDown      syscall.Errno = 10050
	wsaeNetUnreach   syscall.Errno = 10051
	wsaeTimedOut     syscall.Errno = 10060
	wsaeConnRefused  syscall.Errno = 10061
	wsaeHostUnreach  syscall.Errno = 10065
)

// Classify says what a failed dial means for its link: whether another link is worth trying (retry), and whether
// this link itself is broken and should take no new flows for a while (linkDown). A refused connection or a name
// that does not resolve would fail on every link, so they are not retried.
func Classify(err error) (retry, linkDown bool) {
	is := func(wsa, std syscall.Errno) bool { return errors.Is(err, wsa) || errors.Is(err, std) }
	var dns *net.DNSError
	var ne net.Error
	switch {
	case errors.As(err, &dns):
		return false, false
	case is(wsaeAddrNotAvail, syscall.EADDRNOTAVAIL), is(wsaeNetDown, syscall.ENETDOWN), is(wsaeNetUnreach, syscall.ENETUNREACH):
		return true, true
	case is(wsaeHostUnreach, syscall.EHOSTUNREACH), is(wsaeTimedOut, syscall.ETIMEDOUT):
		return true, false
	case is(wsaeConnRefused, syscall.ECONNREFUSED):
		return false, false
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return true, false
	}
	return false, false
}

// Usable counts the links a new flow of family f could go to now: present, with an address of the family, and
// neither failing their probe nor sidelined after a link error.
func (s *Scheduler) Usable(f Family) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	n := 0
	for _, sl := range s.slots {
		if sl.present && sl.ip(f) != nil && sl.state[f] != stateDown && !now.Before(sl.downUntil[f]) {
			n++
		}
	}
	return n
}

// IP is the link's address of family f, nil when it has none.
func (sl *Slot) IP(f Family) net.IP { return sl.ip(f) }

// Key is the id the link is known by (see nicKey).
func (sl *Slot) Key() string { return sl.key }

// FailCooldown is how long a link that failed a dial with a link error takes no new flows.
const FailCooldown = 15 * time.Second
