// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build windows

package netbind

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// AdapterNames lists the friendly names of every adapter Windows reports, straight from the IP Helper API.
// It is what a process-per-check (`netsh interface show interface`) used to answer, in a fraction of a
// millisecond and without a console.
func AdapterNames() ([]string, error) {
	const flags = windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_DNS_SERVER |
		windows.GAA_FLAG_SKIP_UNICAST
	size := uint32(15 * 1024)
	var buffer []byte
	for attempt := 0; attempt < maxAdapterTry; attempt++ {
		buffer = make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, first, &size)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) || attempt == maxAdapterTry-1 {
			return nil, err
		}
	}
	var names []string
	for current := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0])); current != nil; current = current.Next {
		names = append(names, windows.UTF16PtrToString(current.FriendlyName))
	}
	return names, nil
}
