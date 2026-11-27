// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package hostlinks

import (
	"testing"

	"github.com/ZloyRadetski/skipi-core/desktop/multilink/nics"
)

const twoLinks = `[
 {"id":"wifi","name":"Wi-Fi","kind":"wifi","ipv4":"192.0.2.10","handle":11},
 {"id":"mobile","name":"Mobile data","kind":"mobile","ipv4":"198.51.100.7","ipv6":"2001:db8::7","handle":12}
]`

func TestLinksBecomeAdaptersWithTheirHandles(t *testing.T) {
	var s Source
	if err := s.SetJSON(twoLinks); err != nil {
		t.Fatal(err)
	}
	found, skipped, err := s.Discover()
	if err != nil || len(skipped) != 0 || len(found) != 2 {
		t.Fatalf("found %v skipped %v err %v", found, skipped, err)
	}
	if found[0].Handle != 11 || found[0].IP.String() != "192.0.2.10" || found[0].Phone {
		t.Fatalf("wifi: %+v", found[0])
	}
	if found[1].Handle != 12 || found[1].IP6 == nil || !found[1].Phone {
		t.Fatalf("mobile data is metered and eased like a phone: %+v", found[1])
	}
	if k := s.Kinds(); k["Wi-Fi"] != nics.WiFi || k["Mobile data"] != nics.Mobile {
		t.Fatalf("kinds %v", k)
	}
}

func TestALinkWithoutAnAddressIsLeftOut(t *testing.T) {
	var s Source
	if err := s.SetJSON(`[{"id":"wifi","name":"Wi-Fi","kind":"wifi","handle":1}]`); err != nil {
		t.Fatal(err)
	}
	if found, _, _ := s.Discover(); len(found) != 0 {
		t.Fatalf("found %v", found)
	}
}

func TestABadListChangesNothing(t *testing.T) {
	var s Source
	if err := s.SetJSON(twoLinks); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`nope`, `[{"id":"","name":"x","handle":1}]`, `[{"id":"a","name":"x"}]`,
		`[{"id":"a","name":"x","handle":1},{"id":"a","name":"y","handle":2}]`} {
		if s.SetJSON(bad) == nil {
			t.Fatalf("%s was accepted", bad)
		}
	}
	if found, _, _ := s.Discover(); len(found) != 2 {
		t.Fatalf("the good list was lost: %v", found)
	}
}
