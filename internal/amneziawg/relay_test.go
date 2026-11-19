package amneziawg

import (
	"io"
	"net"
	"testing"
	"time"
)

func tcpPair(t *testing.T) (client, server *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan *net.TCPConn, 1)
	go func() { c, _ := ln.Accept(); accepted <- c.(*net.TCPConn) }()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return c.(*net.TCPConn), <-accepted
}

// A client that has sent its whole request and shut down its write side must still receive the
// answer: the relay used to close both ends as soon as one direction hit EOF.
func TestRelayKeepsTheAnswerAfterTheClientHalfCloses(t *testing.T) {
	clientA, srvA := tcpPair(t)
	clientB, srvB := tcpPair(t)
	defer clientA.Close()
	defer clientB.Close()
	go Relay(t.Context(), srvA, srvB)

	_, _ = clientA.Write([]byte("request"))
	_ = clientA.CloseWrite()

	got, err := io.ReadAll(clientB) // ends when the relay half-closes towards B
	if err != nil || string(got) != "request" {
		t.Fatalf("B read %q, %v", got, err)
	}
	_, _ = clientB.Write([]byte("response"))
	_ = clientB.Close()

	_ = clientA.SetReadDeadline(time.Now().Add(3 * time.Second))
	answer, err := io.ReadAll(clientA)
	if err != nil || string(answer) != "response" {
		t.Fatalf("A read %q, %v", answer, err)
	}
}
