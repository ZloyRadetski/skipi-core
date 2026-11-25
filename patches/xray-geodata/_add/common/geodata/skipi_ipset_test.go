package geodata

// Tests of the SKIPI patch (skipi-core/patches/xray-geodata). They compare the compact IP sets and
// the streaming loader with what upstream builds (netipx, proto.Unmarshal) and exercise the entry
// index. Run them with scripts/check-xray-patches.sh after every xray-core update.

import (
	"math/rand"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go4.org/netipx"
	"google.golang.org/protobuf/proto"
)

func skipiRandPrefix(rnd *rand.Rand) netip.Prefix {
	switch rnd.Intn(6) {
	case 0: // whole families and the edges of the space
		edges := []string{"0.0.0.0/0", "255.255.255.255/32", "0.0.0.0/32", "::/0", "::/128",
			"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", "255.255.255.0/24", "128.0.0.0/1"}
		return netip.MustParsePrefix(edges[rnd.Intn(len(edges))])
	case 1, 2: // v6
		var b [16]byte
		rnd.Read(b[:])
		if rnd.Intn(2) == 0 { // cluster so ranges touch and overlap
			for i := 4; i < 16; i++ {
				b[i] = 0
			}
		}
		return netip.PrefixFrom(netip.AddrFrom16(b), rnd.Intn(129)).Masked()
	default: // v4
		var b [4]byte
		rnd.Read(b[:])
		if rnd.Intn(2) == 0 {
			b[0], b[1] = 10, byte(rnd.Intn(3))
		}
		return netip.PrefixFrom(netip.AddrFrom4(b), rnd.Intn(33)).Masked()
	}
}

func skipiProbes(rnd *rand.Rand, prefixes []netip.Prefix) []netip.Addr {
	var out []netip.Addr
	for _, p := range prefixes {
		r := netipx.RangeOfPrefix(p)
		out = append(out, r.From(), r.To(), r.From().Prev(), r.To().Next())
	}
	for i := 0; i < 300; i++ {
		var b [16]byte
		rnd.Read(b[:])
		out = append(out, netip.AddrFrom16(b))
		out = append(out, netip.AddrFrom4([4]byte{b[0], b[1], b[2], b[3]}))
		out = append(out, netip.AddrFrom4([4]byte{10, byte(rnd.Intn(3)), b[2], b[3]}))
	}
	return out
}

func TestSkipiIPSetMatchesNetipx(t *testing.T) {
	rnd := rand.New(rand.NewSource(1))
	for round := 0; round < 300; round++ {
		n := 1 + rnd.Intn(60)
		if round%50 == 0 {
			n = 2000
		}
		var prefixes []netip.Prefix
		var sb skipiSetBuilder
		var ref4, ref6 netipx.IPSetBuilder
		for i := 0; i < n; i++ {
			p := skipiRandPrefix(rnd)
			prefixes = append(prefixes, p)
			sb.add(p)
			if p.Addr().Is4() {
				ref4.AddPrefix(p)
			} else {
				ref6.AddPrefix(p)
			}
		}
		set := sb.build()
		s4, err := ref4.IPSet()
		if err != nil {
			t.Fatal(err)
		}
		s6, err := ref6.IPSet()
		if err != nil {
			t.Fatal(err)
		}
		for _, ip := range skipiProbes(rnd, prefixes) {
			want := false
			got := false
			if ip.Is4() {
				want, got = s4.Contains(ip), set.ipv4.Contains(ip)
			} else if ip.Is6() {
				want, got = s6.Contains(ip), set.ipv6.Contains(ip)
			}
			if want != got {
				t.Fatalf("round %d: Contains(%v) = %v, netipx says %v", round, ip, got, want)
			}
		}
		// max4/max6 as upstream computes them from the merged set's prefixes.
		wantMax := func(set *netipx.IPSet) uint8 {
			has, max := false, 0
			for _, p := range set.Prefixes() {
				has = true
				if b := p.Bits(); b > max {
					max = b
				}
			}
			switch {
			case !has:
				return 0xff
			case max == 0:
				return 0xfe
			}
			return uint8(max)
		}
		if got, want := set.max4, wantMax(s4); got != want {
			t.Fatalf("round %d: max4 = %d, upstream %d", round, got, want)
		}
		if got, want := set.max6, wantMax(s6); got != want {
			t.Fatalf("round %d: max6 = %d, upstream %d", round, got, want)
		}
	}
}

func skipiWriteGeoIP(t *testing.T, dir string, entries map[string][]netip.Prefix, order []string) {
	t.Helper()
	var list GeoIPList
	for _, code := range order {
		geoip := &GeoIP{Code: code}
		for _, p := range entries[code] {
			geoip.Cidr = append(geoip.Cidr, &CIDR{Ip: p.Addr().AsSlice(), Prefix: uint32(p.Bits())})
		}
		list.Entry = append(list.Entry, geoip)
	}
	data, err := proto.Marshal(&list)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "geoip.dat"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSkipiLoadIPMatchesUpstreamLoader(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XRAY_LOCATION_ASSET", dir)
	rnd := rand.New(rand.NewSource(2))
	entries := map[string][]netip.Prefix{}
	var order []string
	for _, code := range []string{"A", "PRIVATE", "LONG-CODE-WITH-DASHES-AND-DIGITS-0123456789", "RU", "Z"} {
		for i := 0; i < 1+rnd.Intn(5000); i++ {
			entries[code] = append(entries[code], skipiRandPrefix(rnd))
		}
		order = append(order, code)
	}
	skipiWriteGeoIP(t, dir, entries, order)

	for _, code := range order {
		var sb skipiSetBuilder
		if err := loadIPInto(&sb, "geoip.dat", code); err != nil {
			t.Fatalf("%s: %v", code, err)
		}
		got := sb.build()

		cidrs, err := loadIP("geoip.dat", code)
		if err != nil {
			t.Fatal(err)
		}
		var ref4, ref6 netipx.IPSetBuilder
		for _, c := range cidrs {
			addr, _ := netip.AddrFromSlice(c.Ip)
			p := netip.PrefixFrom(addr, int(c.Prefix))
			if addr.Is4() {
				ref4.AddPrefix(p)
			} else {
				ref6.AddPrefix(p)
			}
		}
		s4, _ := ref4.IPSet()
		s6, _ := ref6.IPSet()
		for _, ip := range skipiProbes(rnd, entries[code]) {
			var want, have bool
			if ip.Is4() {
				want, have = s4.Contains(ip), got.ipv4.Contains(ip)
			} else {
				want, have = s6.Contains(ip), got.ipv6.Contains(ip)
			}
			if want != have {
				t.Fatalf("%s: Contains(%v) = %v, upstream %v", code, ip, have, want)
			}
		}
	}

	var sb skipiSetBuilder
	if err := loadIPInto(&sb, "geoip.dat", "NOPE"); err == nil {
		t.Fatal("a missing code must be an error")
	}
	if err := checkFile("geoip.dat", "RU"); err != nil {
		t.Fatal(err)
	}
	if err := checkFile("geoip.dat", "NOPE"); err == nil {
		t.Fatal("checkFile accepted a missing code")
	}
}

// The entry table is cached per path; a replaced file (new size or time) must be read afresh.
func TestSkipiEntryIndexFollowsTheFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XRAY_LOCATION_ASSET", dir)
	p := func(s string) []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix(s)} }

	skipiWriteGeoIP(t, dir, map[string][]netip.Prefix{"A": p("1.0.0.0/8"), "B": p("2.0.0.0/8")}, []string{"A", "B"})
	var sb skipiSetBuilder
	if err := loadIPInto(&sb, "geoip.dat", "B"); err != nil {
		t.Fatal(err)
	}
	if !sb.build().ipv4.Contains(netip.MustParseAddr("2.1.1.1")) {
		t.Fatal("B not loaded")
	}

	// Same name, different content and a later time.
	skipiWriteGeoIP(t, dir, map[string][]netip.Prefix{"C": p("3.0.0.0/8"), "B": p("4.0.0.0/8")}, []string{"C", "B"})
	later := time.Now().Add(time.Hour)
	if err := os.Chtimes(filepath.Join(dir, "geoip.dat"), later, later); err != nil {
		t.Fatal(err)
	}
	sb = skipiSetBuilder{}
	if err := loadIPInto(&sb, "geoip.dat", "B"); err != nil {
		t.Fatal(err)
	}
	set := sb.build()
	if set.ipv4.Contains(netip.MustParseAddr("2.1.1.1")) || !set.ipv4.Contains(netip.MustParseAddr("4.1.1.1")) {
		t.Fatal("the entry index was not refreshed after the file changed")
	}
	if err := checkFile("geoip.dat", "A"); err == nil {
		t.Fatal("code A is gone from the new file")
	}
}
