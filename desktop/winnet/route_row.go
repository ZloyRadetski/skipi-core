// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package winnet

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	routeRowSize = 104 // sizeof(MIB_IPFORWARD_ROW2) on a 64-bit Windows

	afINET  = 2
	afINET6 = 23

	mibIPProtoNetMgmt = 3 // a route set by a management tool, like netsh
	infiniteLifetime  = 0xFFFFFFFF
)

// encodeRouteRow builds a MIB_IPFORWARD_ROW2 for an on-link route (the unspecified next hop) of prefix on the
// interface luid. The layout is iphlpapi.h's, written out byte by byte so it can be checked on every platform:
//
//	0   InterfaceLuid (8)        8   InterfaceIndex (4)
//	12  DestinationPrefix.Prefix, a SOCKADDR_INET (28)      40  PrefixLength (1)
//	44  NextHop, a SOCKADDR_INET (28)                        72  SitePrefixLength (1)
//	76  ValidLifetime  80  PreferredLifetime  84  Metric  88  Protocol (4 each)
//	92  Loopback, AutoconfigureAddress, Publish, Immortal (1 each)   96  Age   100  Origin
func encodeRouteRow(luid uint64, prefix netip.Prefix, metric uint32) ([]byte, error) {
	if !prefix.IsValid() {
		return nil, errors.New("invalid route prefix")
	}
	row := make([]byte, routeRowSize)
	le := binary.LittleEndian
	le.PutUint64(row[0:], luid)
	addr := prefix.Masked().Addr()
	family := uint16(afINET)
	if addr.Is6() && !addr.Is4In6() {
		family = afINET6
	}
	le.PutUint16(row[12:], family)
	le.PutUint16(row[44:], family)
	if family == afINET {
		a := addr.Unmap().As4()
		copy(row[12+4:], a[:])
	} else {
		a := addr.As16()
		copy(row[12+8:], a[:])
	}
	row[40] = byte(prefix.Bits())
	le.PutUint32(row[76:], infiniteLifetime)
	le.PutUint32(row[80:], infiniteLifetime)
	le.PutUint32(row[84:], metric)
	le.PutUint32(row[88:], mibIPProtoNetMgmt)
	return row, nil
}
