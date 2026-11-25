package geodata

// SKIPI patch (skipi-core/patches/xray-geodata): compact, streaming IP sets.
//
// Upstream decodes a whole geoip entry into []*CIDR, copies it into a netipx.IPSetBuilder
// (48 bytes per range, then several more copies while it sorts and merges), and calls
// IPSet.Prefixes() twice. For a few hundred thousand prefixes that is a transient ~150 MB and most
// of the tunnel start time. Here the entry is decoded straight into packed ranges (8 bytes per IPv4
// range, 32 per IPv6 range), sorted and merged in place, and the set that stays resident is the
// same packed slice. Matching results, max4/max6 and the error handling are the same as upstream.

import (
	"context"
	"io"
	"math/bits"
	"net/netip"
	"slices"
	"unicode/utf8"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform/filesystem"

	"google.golang.org/protobuf/encoding/protowire"
)

// skipiSet4 is a sorted list of disjoint, non-adjacent IPv4 ranges packed as from<<32|to.
type skipiSet4 struct{ r []uint64 }

// Contains reports whether ip is in the set.
func (s *skipiSet4) Contains(ip netip.Addr) bool {
	if s == nil || !ip.Is4() {
		return false
	}
	a4 := ip.As4()
	a := uint64(a4[0])<<24 | uint64(a4[1])<<16 | uint64(a4[2])<<8 | uint64(a4[3])
	r := s.r
	lo, hi := 0, len(r)
	for lo < hi { // first range that starts after a
		m := int(uint(lo+hi) >> 1)
		if r[m]>>32 > a {
			hi = m
		} else {
			lo = m + 1
		}
	}
	return lo > 0 && r[lo-1]&0xffffffff >= a
}

type skipiU128 struct{ hi, lo uint64 }

func (a skipiU128) cmp(b skipiU128) int {
	switch {
	case a.hi < b.hi:
		return -1
	case a.hi > b.hi:
		return 1
	case a.lo < b.lo:
		return -1
	case a.lo > b.lo:
		return 1
	}
	return 0
}

func (a skipiU128) add(b skipiU128) (skipiU128, bool) {
	lo, c := bits.Add64(a.lo, b.lo, 0)
	hi, c := bits.Add64(a.hi, b.hi, c)
	return skipiU128{hi, lo}, c != 0
}

func (a skipiU128) sub(b skipiU128) skipiU128 {
	lo, bw := bits.Sub64(a.lo, b.lo, 0)
	hi, _ := bits.Sub64(a.hi, b.hi, bw)
	return skipiU128{hi, lo}
}

func (a skipiU128) shl(n int) skipiU128 {
	switch {
	case n == 0:
		return a
	case n >= 128:
		return skipiU128{}
	case n >= 64:
		return skipiU128{hi: a.lo << uint(n-64)}
	}
	return skipiU128{hi: a.hi<<uint(n) | a.lo>>uint(64-n), lo: a.lo << uint(n)}
}

func (a skipiU128) trailingZeros() int {
	if a.lo != 0 {
		return bits.TrailingZeros64(a.lo)
	}
	if a.hi != 0 {
		return 64 + bits.TrailingZeros64(a.hi)
	}
	return 128
}

// log2 is the floor of log2(a) for a != 0.
func (a skipiU128) log2() int {
	if a.hi != 0 {
		return 127 - bits.LeadingZeros64(a.hi)
	}
	return 63 - bits.LeadingZeros64(a.lo)
}

type skipiRange6 struct{ from, to skipiU128 }

// skipiSet6 is a sorted list of disjoint, non-adjacent IPv6 ranges.
type skipiSet6 struct{ r []skipiRange6 }

func skipiAddr6(ip netip.Addr) skipiU128 {
	b := ip.As16()
	var u skipiU128
	for i := 0; i < 8; i++ {
		u.hi = u.hi<<8 | uint64(b[i])
		u.lo = u.lo<<8 | uint64(b[8+i])
	}
	return u
}

// Contains reports whether ip is in the set.
func (s *skipiSet6) Contains(ip netip.Addr) bool {
	if s == nil || !ip.Is6() {
		return false
	}
	a := skipiAddr6(ip)
	r := s.r
	lo, hi := 0, len(r)
	for lo < hi {
		m := int(uint(lo+hi) >> 1)
		if r[m].from.cmp(a) > 0 {
			hi = m
		} else {
			lo = m + 1
		}
	}
	return lo > 0 && r[lo-1].to.cmp(a) >= 0
}

// skipiSetBuilder collects prefixes and builds the final IPSet.
type skipiSetBuilder struct {
	v4 []uint64
	v6 []skipiRange6

	// counting makes add only count (n4, n6), silently; reserve then sizes v4 and v6 exactly.
	counting bool
	n4, n6   int
}

func (b *skipiSetBuilder) reserve() {
	b.v4 = slices.Grow(b.v4, b.n4)
	b.v6 = slices.Grow(b.v6, b.n6)
	b.counting = false
}

// add records a valid prefix; the caller has checked the address and prefix.IsValid().
func (b *skipiSetBuilder) add(p netip.Prefix) {
	addr := p.Addr()
	if b.counting {
		if addr.Is4() {
			b.n4++
		} else {
			b.n6++
		}
		return
	}
	p = p.Masked()
	if addr.Is4() {
		a4 := addr.As4()
		from := uint64(a4[0])<<24 | uint64(a4[1])<<16 | uint64(a4[2])<<8 | uint64(a4[3])
		host := uint64(1)<<uint(32-p.Bits()) - 1
		b.v4 = append(b.v4, from<<32|(from|host))
		return
	}
	from := skipiAddr6(addr)
	to := from
	if n := 128 - p.Bits(); n >= 64 {
		to.lo = ^uint64(0)
		if n > 64 {
			to.hi |= uint64(1)<<uint(n-64) - 1
		}
	} else if n > 0 {
		to.lo |= uint64(1)<<uint(n) - 1
	}
	b.v6 = append(b.v6, skipiRange6{from, to})
}

func (b *skipiSetBuilder) build() *IPSet {
	set := &IPSet{max4: 0xff, max6: 0xff}
	if len(b.v4) > 0 {
		slices.Sort(b.v4)
		r := b.v4[:1]
		for _, x := range b.v4[1:] {
			last := &r[len(r)-1]
			// x starts at or before one past the end of the last range: merge them.
			if x>>32 <= (*last&0xffffffff)+1 {
				if x&0xffffffff > *last&0xffffffff {
					*last = *last&^0xffffffff | x&0xffffffff
				}
			} else {
				r = append(r, x)
			}
		}
		set.ipv4 = &skipiSet4{r: slices.Clone(r)} // exact size: the builder slice has up to 2x slack
		set.max4 = skipiMaxBits4(r)
	}
	if len(b.v6) > 0 {
		slices.SortFunc(b.v6, func(x, y skipiRange6) int {
			if c := x.from.cmp(y.from); c != 0 {
				return c
			}
			return x.to.cmp(y.to)
		})
		r := b.v6[:1]
		for _, x := range b.v6[1:] {
			last := &r[len(r)-1]
			next, overflow := last.to.add(skipiU128{lo: 1})
			if overflow || x.from.cmp(next) <= 0 {
				if x.to.cmp(last.to) > 0 {
					last.to = x.to
				}
			} else {
				r = append(r, x)
			}
		}
		set.ipv6 = &skipiSet6{r: slices.Clone(r)}
		set.max6 = skipiMaxBits6(r)
	}
	b.v4, b.v6 = nil, nil
	return set
}

// skipiMaxBits4 is the longest prefix in the minimal prefix cover of the ranges: what upstream
// computes from IPSet.Prefixes(), without materialising them. Zero becomes 0xfe as upstream does.
func skipiMaxBits4(rr []uint64) uint8 {
	max := 0
	for _, x := range rr {
		a, b := x>>32, x&0xffffffff
		for a <= b {
			size := uint64(1) << 32
			if a != 0 {
				size = a & -a
			}
			for size > b-a+1 {
				size >>= 1
			}
			if n := 32 - (bits.Len64(size) - 1); n > max {
				max = n
			}
			a += size
		}
	}
	if max == 0 {
		return 0xfe
	}
	return uint8(max)
}

func skipiMaxBits6(rr []skipiRange6) uint8 {
	max := 0
	for _, x := range rr {
		a, b := x.from, x.to
		for {
			k := a.trailingZeros()
			diff := b.sub(a) // size - 1, so a range of the whole space does not overflow
			lg := 128
			if diff.hi != ^uint64(0) || diff.lo != ^uint64(0) {
				size, _ := diff.add(skipiU128{lo: 1})
				lg = size.log2()
			}
			if lg < k {
				k = lg
			}
			if n := 128 - k; n > max {
				max = n
			}
			if k == 128 {
				break
			}
			next, overflow := a.add(skipiU128{lo: 1}.shl(k))
			if overflow || next.cmp(b) > 0 {
				break
			}
			a = next
		}
	}
	if max == 0 {
		return 0xfe
	}
	return uint8(max)
}

// skipiAddCIDR adds a CIDR to b with upstream's validation and logging.
func skipiAddCIDR(b *skipiSetBuilder, ipBytes []byte, prefixLen int) {
	addr, ok := netip.AddrFromSlice(ipBytes)
	if !ok {
		if !b.counting { // the counting pass stays silent: the filling pass reports it
			errors.LogError(context.Background(), "ignore invalid IP byte slice: ", ipBytes)
		}
		return
	}
	prefix := netip.PrefixFrom(addr, prefixLen)
	if !prefix.IsValid() {
		if !b.counting {
			errors.LogError(context.Background(), "ignore created invalid prefix from addr ", addr, " and length ", prefixLen)
		}
		return
	}
	if addr.Is4() || addr.Is6() {
		b.add(prefix)
	}
}

// loadIPInto streams the CIDRs of the geoip code straight into b. Like loadIP it reads the entry
// found by code and accepts and rejects what proto.Unmarshal of a GeoIP does.
func loadIPInto(b *skipiSetBuilder, file, code string) error {
	r, size, err := filesystem.OpenAsset(file)
	if err != nil {
		return errors.New("failed to open ", file).Base(err)
	}
	defer r.Close()
	br, n, err := skipiOpenEntry(r, []byte(code), size)
	if err != nil {
		return errors.New("failed to load code ", code, " from ", file).Base(err)
	}
	loadErr := func(err error) error {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return errors.New("failed to load code ", code, " from ", file).Base(err)
	}
	unmarshalErr := func(err error) error {
		return errors.New("error unmarshal IP in ", file, ":", code).Base(err)
	}
	for n > 0 {
		w, err := br.Peek(min(n, br.Size()))
		if err != nil {
			return loadErr(err)
		}
		used, err := skipiDecodeGeoIP(b, w, len(w) < n)
		if err != nil {
			return unmarshalErr(err)
		}
		if used == 0 {
			break // a field longer than the buffer
		}
		br.Discard(used)
		n -= used
	}
	if n > 0 {
		w := make([]byte, n)
		if _, err := io.ReadFull(br, w); err != nil {
			return loadErr(err)
		}
		if _, err := skipiDecodeGeoIP(b, w, false); err != nil {
			return unmarshalErr(err)
		}
	}
	return nil
}

// skipiDecodeGeoIP walks the whole fields at the start of b, a part of an encoded GeoIP, adds every
// CIDR to sb and returns how many bytes it used. A field cut off by the end of b is an error unless
// more is set.
func skipiDecodeGeoIP(sb *skipiSetBuilder, b []byte, more bool) (int, error) {
	used := 0
	for used < len(b) {
		f, n, err := consumeField(b[used:])
		if err == io.ErrUnexpectedEOF && more {
			break
		}
		if err != nil {
			return used, err
		}
		used += n
		if f.typ != protowire.BytesType {
			continue
		}
		switch f.num {
		case 1: // code
			if !utf8.Valid(f.v) {
				return used, errInvalidUTF8
			}
		case 2: // cidr
			var ip []byte
			var prefix uint32
			for c := f.v; len(c) > 0; {
				cf, cn, err := consumeField(c)
				if err != nil {
					return used, err
				}
				c = c[cn:]
				switch {
				case cf.num == 1 && cf.typ == protowire.BytesType:
					ip = cf.v
				case cf.num == 2 && cf.typ == protowire.VarintType:
					prefix = uint32(cf.x)
				}
			}
			skipiAddCIDR(sb, ip, int(prefix))
		}
	}
	return used, nil
}
