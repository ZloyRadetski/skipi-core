// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package egress

import (
	"context"
	gonet "net"
	"os"
	"testing"
	"time"

	"github.com/ZloyRadetski/skipi-core/desktop/multilink"
	"github.com/ZloyRadetski/skipi-core/desktop/multilink/nics"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

// TestLiveDialsLeaveThroughEveryLink dials real servers through Xray's dialer on this machine's links and checks
// that the connections really left through each of them. It needs two links with internet:
//
//	SKIPI_MULTILINK_LIVE=1 go test ./desktop/egress -run Live -v
func TestLiveDialsLeaveThroughEveryLink(t *testing.T) {
	if os.Getenv("SKIPI_MULTILINK_LIVE") == "" {
		t.Skip("set SKIPI_MULTILINK_LIVE=1 on a machine with two links")
	}
	found, err := nics.DiscoverNics(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) < 2 {
		t.Skipf("%d link(s) here, need two", len(found))
	}
	sched := multilink.NewScheduler(found)
	System().SetScheduler(sched)
	defer System().SetScheduler(nil)

	bySource := map[string]int{}
	for _, target := range []string{"1.1.1.1", "8.8.8.8", "1.0.0.1", "8.8.4.4", "1.1.1.1", "8.8.8.8"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := internet.DialSystem(ctx, net.TCPDestination(net.ParseAddress(target), 443), nil)
		cancel()
		if err != nil {
			t.Fatalf("dial %s: %v", target, err)
		}
		defer conn.Close()
		local := conn.LocalAddr().(*gonet.TCPAddr).IP.String()
		bySource[local]++
	}
	t.Logf("connections by source address: %v", bySource)
	for _, n := range found {
		if bySource[n.IP.String()] == 0 {
			t.Errorf("no connection left through %s (%s)", n.Name, n.IP)
		}
	}
}
