package skipicore

import (
	"fmt"
	"io"
	"net"
	"runtime"
	"testing"
	"time"
)

// A finished UDP association must not leave a goroutine behind: they used to wait for the
// runner's own context, so a long session grew by one goroutine per UDP flow.
func TestAmneziaWgUDPAssociateDoesNotLeakGoroutines(t *testing.T) {
	settings, err := ParseAmneziaWgSettings(`{"secretKey":"aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZhbGlkIGtleSE=","address":["10.8.0.2/32"],"dnsServers":["1.1.1.1"],
	"peers":[{"publicKey":"YW5vdGhlciB2YWxpZCBrZXkgZm9yIHRlc3Rpbmcgb2s=","endpoint":"127.0.0.1:59999","allowedIPs":["0.0.0.0/0"]}]}`)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := NewAmneziaWgRunner(settings, 0)
	if err != nil {
		t.Fatal(err)
	}
	runner.socksPort = 0 // an ephemeral port, not the fixed default another process may hold
	if err := runner.Start(); err != nil {
		t.Fatal(err)
	}
	defer runner.Stop()

	time.Sleep(200 * time.Millisecond)
	before := runtime.NumGoroutine()
	const associations = 100
	for i := 0; i < associations; i++ {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", runner.socksPort))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte{5, 1, 0})
		var greeting [2]byte
		_, _ = io.ReadFull(c, greeting[:])
		_, _ = c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
		var reply [10]byte
		_, _ = io.ReadFull(c, reply[:])
		_ = c.Close()
	}
	var after int
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if after = runtime.NumGoroutine(); after-before < associations/10 {
			return
		}
	}
	t.Fatalf("goroutines grew from %d to %d after %d closed UDP associations", before, after, associations)
}

// The lock-free metrics path must stay usable: with a wrong metric name or kind it silently
// returned nil and every call fell back to the stop-the-world MemStats read.
func TestReadMemoryStatsUsesMetricsPath(t *testing.T) {
	stats := readMemoryStatsFromMetrics()
	if stats == nil {
		t.Fatal("runtime/metrics path unavailable")
	}
	if stats.AllocBytes <= 0 || stats.SysBytes <= 0 || stats.NumGoroutines <= 0 || stats.NumGC == 0 && stats.TotalAlloc <= 0 {
		t.Fatalf("implausible stats: %+v", stats)
	}
}

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
	go relay(t.Context(), srvA, srvB)

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

func TestSocksHandshakeTimesOutOnSilentClient(t *testing.T) {
	settings, err := ParseAmneziaWgSettings(`{"secretKey":"aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZhbGlkIGtleSE=","address":["10.8.0.2/32"],"dnsServers":["1.1.1.1"],
	"peers":[{"publicKey":"YW5vdGhlciB2YWxpZCBrZXkgZm9yIHRlc3Rpbmcgb2s=","endpoint":"127.0.0.1:59999","allowedIPs":["0.0.0.0/0"]}]}`)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := NewAmneziaWgRunner(settings, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer runner.Stop()
	defer func(old time.Duration) { socksHandshakeTimeout = old }(socksHandshakeTimeout)
	socksHandshakeTimeout = 300 * time.Millisecond
	client, server := tcpPair(t)
	defer client.Close()
	finished := make(chan struct{})
	go func() { runner.handleSocksConn(t.Context(), server); close(finished) }()
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("a silent client still holds the handler")
	}
}
