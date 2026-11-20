// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build windows

package winnet

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestTheDnsSettingsStructIsTheSizeWindowsExpects(t *testing.T) {
	if got := unsafe.Sizeof(dnsSettings{}); got != dnsSettingsSize {
		t.Fatalf("sizeof(DNS_INTERFACE_SETTINGS) = %d, want %d", got, dnsSettingsSize)
	}
	if got := unsafe.Offsetof(dnsSettings{}.NameServer); got != 24 {
		t.Fatalf("NameServer offset = %d, want 24", got)
	}
}

// adapterWithIPv4 finds an adapter the system reports with its IPv4 index and metric, an answer that does not
// come through the row layout under test.
func adapterWithIPv4(t *testing.T) (name string, index, metric uint32) {
	t.Helper()
	size := uint32(15 * 1024)
	buffer := make([]byte, size)
	first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
	if err := windows.GetAdaptersAddresses(windows.AF_INET, windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER, 0, first, &size); err != nil {
		t.Skip("cannot list adapters: " + err.Error())
	}
	for current := first; current != nil; current = current.Next {
		if current.OperStatus == windows.IfOperStatusUp && current.IfIndex != 0 {
			return windows.UTF16PtrToString(current.FriendlyName), current.IfIndex, current.Ipv4Metric
		}
	}
	t.Skip("no adapter is up")
	return
}

func TestTheInterfaceRowHoldsTheMetricAndIndexWhereTheOffsetsSay(t *testing.T) {
	name, index, metric := adapterWithIPv4(t)
	luid, err := interfaceLuid(name)
	if err != nil {
		t.Skip(err.Error())
	}
	row, err := readIPInterface(luid, afINET)
	if err != nil {
		t.Fatalf("GetIpInterfaceEntry(%s): %v", name, err)
	}
	if got := binary.LittleEndian.Uint32(row[16:]); got != index {
		t.Fatalf("InterfaceIndex at 16 = %d, the system says %d", got, index)
	}
	if got := binary.LittleEndian.Uint32(row[ipInterfaceMetric:]); got != metric {
		t.Fatalf("Metric at %d = %d, the system says %d", ipInterfaceMetric, got, metric)
	}
}

// Without administrator rights the system refuses to change DNS or the metric, but it must take our structures:
// a wrong layout is ERROR_INVALID_PARAMETER, a lack of rights is ERROR_ACCESS_DENIED. The loopback adapter is
// the one nobody depends on; a change that unexpectedly goes through is undone.
func TestTheSystemTakesTheDnsAndMetricStructuresAndRefusesOnlyForLackOfRights(t *testing.T) {
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("elevated: this test would really change the adapter")
	}
	const loopback = "Loopback Pseudo-Interface 1"
	luid, err := interfaceLuid(loopback)
	if err != nil {
		t.Skip("no loopback adapter")
	}
	before, err := readIPInterface(luid, afINET)
	if err != nil {
		t.Skip(err.Error())
	}
	t.Cleanup(func() { _, _, _ = procSetIpInterfaceEntry.Call(uintptr(unsafe.Pointer(&before[0]))) })

	for name, call := range map[string]func() error{
		"SetInterfaceDnsSettings": func() error { return nativeSetDNS(loopback, []netip.Addr{netip.MustParseAddr("192.0.2.53")}) },
		"SetIpInterfaceEntry":     func() error { return setInterfaceMetric(luid, 1) },
	} {
		err := call()
		if err == nil {
			t.Logf("%s went through without administrator rights", name)
			continue
		}
		var errno windows.Errno
		if errors.As(err, &errno) && errno == windows.ERROR_INVALID_PARAMETER {
			t.Fatalf("%s: the structure layout is wrong: %v", name, err)
		}
	}
}

func TestFlushingTheResolverCacheWorksWithoutAdministratorRights(t *testing.T) {
	if err := nativeFlushDNS(); err != nil {
		t.Fatal(err)
	}
}
