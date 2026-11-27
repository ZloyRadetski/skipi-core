// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package multilink

import (
	"net"
	"testing"

	"github.com/ZloyRadetski/skipi-core/desktop/multilink/nics"
)

// Windows lets the user rename an adapter and localises its name; the adapter itself, and with it
// the flows, the measured speed and the cap set for it, stay the same.
func TestRenamedAdapterKeepsItsSlotAndLimit(t *testing.T) {
	eth := nics.Nic{ID: "{guid-1}", Name: "Ethernet 2", IP: net.ParseIP("10.0.0.1"), Weight: 1}
	s := NewScheduler([]nics.Nic{eth})
	s.SetLimit("{guid-1}", 10)
	sl := s.AcquireFor(Fam4, nil)
	s.ReleaseFor(sl, Fam4)

	eth.Name = "Home line"
	s.Update([]nics.Nic{eth})

	stats := s.Snapshot()
	if len(stats) != 1 {
		t.Fatalf("got %d slots after a rename, want 1", len(stats))
	}
	if stats[0].Name != "Home line" || stats[0].ID != "{guid-1}" {
		t.Fatalf("got %q (%q), want the new name with the same id", stats[0].Name, stats[0].ID)
	}
	if stats[0].Total != 1 || stats[0].LimitMbps != 10 {
		t.Fatalf("got total %d limit %v, want the counters and the cap kept", stats[0].Total, stats[0].LimitMbps)
	}
}

// Two adapters may share a name for a moment (Windows numbers a replacement only later); the id keeps them apart.
func TestAdaptersWithTheSameNameStaySeparate(t *testing.T) {
	s := NewScheduler([]nics.Nic{
		{ID: "a", Name: "Ethernet", IP: net.ParseIP("10.0.0.1"), Weight: 1},
		{ID: "b", Name: "Ethernet", IP: net.ParseIP("10.0.0.2"), Weight: 1},
	})
	if got := len(s.Snapshot()); got != 2 {
		t.Fatalf("got %d slots, want 2", got)
	}
}

// A nic without an id (the tests above this file, an OS that reports none) is keyed by its name as before.
func TestAdapterWithoutIDIsKeyedByName(t *testing.T) {
	s := NewScheduler([]nics.Nic{nic("A", "10.0.0.1", 1)})
	s.SetLimit("A", 5)
	if got := s.Snapshot()[0].LimitMbps; got != 5 {
		t.Fatalf("got limit %v, want 5", got)
	}
}
