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

// chunkReader returns the given chunk sizes one per Read, then EOF.
type chunkReader struct{ sizes []int }

func (r *chunkReader) Read(p []byte) (int, error) {
	if len(r.sizes) == 0 {
		return 0, io.EOF
	}
	n := min(r.sizes[0], len(p))
	r.sizes = r.sizes[1:]
	for i := range p[:n] {
		p[i] = 'x'
	}
	return n, nil
}

// Perf 7: an idle or quiet direction holds a small buffer; the large pooled one is taken only
// while reads fill the small one, and handed back once the flow quiets down.
func TestCopyTakesTheLargeBufferOnlyWhileTrafficFillsTheSmallOne(t *testing.T) {
	taken, returned := 0, 0
	origTake, origReturn := takeCopyBuffer, returnCopyBuffer
	takeCopyBuffer = func() *[]byte { taken++; return origTake() }
	returnCopyBuffer = func(b *[]byte) { returned++; origReturn(b) }
	defer func() { takeCopyBuffer, returnCopyBuffer = origTake, origReturn }()

	var sink countingWriter
	if err := copyPooled(&sink, &chunkReader{sizes: []int{10, 200, 1000}}); err != nil {
		t.Fatal(err)
	}
	if taken != 0 || sink.n != 1210 {
		t.Fatalf("quiet traffic took %d large buffers, copied %d bytes", taken, sink.n)
	}

	sink = countingWriter{}
	bulk := []int{smallCopyBufferSize, 32 << 10, 32 << 10, 32 << 10, 100, 5, smallCopyBufferSize, 7}
	if err := copyPooled(&sink, &chunkReader{sizes: bulk}); err != nil {
		t.Fatal(err)
	}
	want := 0
	for _, n := range bulk {
		want += n
	}
	if sink.n != want {
		t.Fatalf("copied %d bytes, want %d", sink.n, want)
	}
	if taken != 2 || returned != 2 {
		t.Fatalf("bulk traffic: taken %d, returned %d; want the large buffer twice, each handed back", taken, returned)
	}
}

type countingWriter struct{ n int }

func (w *countingWriter) Write(p []byte) (int, error) { w.n += len(p); return len(p), nil }
