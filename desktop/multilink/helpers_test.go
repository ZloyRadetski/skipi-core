// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package multilink

import (
	"net"
	"testing"
)

// needLoopbackAliases skips a test that binds 127.0.0.2/127.0.0.3 as fake adapters where they are not bindable.
func needLoopbackAliases(t testing.TB) {
	t.Helper()
	for _, ip := range []string{"127.0.0.2", "127.0.0.3"} {
		ln, err := net.Listen("tcp4", ip+":0")
		if err != nil {
			t.Skipf("%s is not bindable; on macOS run: sudo ifconfig lo0 alias %s/32", ip, ip)
		}
		ln.Close()
	}
}
