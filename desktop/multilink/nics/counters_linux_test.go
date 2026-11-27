package nics

import (
	"errors"
	"net"
	"testing"
	"time"
)

// The adapter's name is looked up once, not on every tick, and again after the TTL or a failed read.
func TestOctetsResolvesTheNameOnce(t *testing.T) {
	ifaces, _ := net.Interfaces()
	var name string
	var idx int
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 {
			continue
		}
		name, idx = ifc.Name, ifc.Index
		break
	}
	if name == "" {
		t.Skip("no up adapter")
	}
	var c counterCache
	calls := 0
	resolve := func(i int) (string, error) {
		calls++
		if i != idx {
			return "", errors.New("no such adapter")
		}
		return name, nil
	}
	now := time.Now()
	for range 5 {
		if _, _, ok := c.read(idx, now, resolve); !ok {
			t.Fatal("counters not read")
		}
	}
	if calls != 1 {
		t.Fatalf("%d lookups for 5 reads", calls)
	}
	c.read(idx, now.Add(2*counterPathsTTL), resolve)
	if calls != 2 {
		t.Fatalf("%d lookups after the TTL, want 2", calls)
	}
	if _, _, ok := c.read(idx+1000, now, resolve); ok {
		t.Fatal("read counters of an adapter that does not exist")
	}
	if _, _, ok := c.read(0, now, resolve); ok {
		t.Fatal("read counters of index 0")
	}
}
