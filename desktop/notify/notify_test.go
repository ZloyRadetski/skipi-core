// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package notify

import (
	"testing"

	"github.com/godbus/dbus/v5"
)

func TestArgumentsFollowTheDesktopNotificationsSpec(t *testing.T) {
	args := notifyArgs("SKIPI", "VPN включён")

	if len(args) != 8 {
		t.Fatalf("Notify takes 8 arguments, got %d", len(args))
	}
	if args[0] != "SKIPI" || args[2] != "network-vpn" {
		t.Errorf("app_name/app_icon = %v / %v", args[0], args[2])
	}
	if args[3] != "SKIPI" || args[4] != "VPN включён" {
		t.Errorf("summary/body = %v / %v", args[3], args[4])
	}
	if actions, ok := args[5].([]string); !ok || len(actions) != 0 {
		t.Errorf("actions = %#v", args[5])
	}
	if args[7] != int32(4000) {
		t.Errorf("expire_timeout = %v", args[7])
	}
}

// Replacing by id breaks once the previous notification has expired: some servers then update a
// notification that no longer exists and show nothing. Every call is a new notification, and
// servers that support it collapse them through the stacking hints instead.
func TestEveryCallIsANewNotificationThatSupportingServersStack(t *testing.T) {
	args := notifyArgs("SKIPI", "a")

	if args[1] != uint32(0) {
		t.Fatalf("replaces_id = %v, want 0", args[1])
	}
	hints := args[6].(map[string]dbus.Variant)
	for _, key := range []string{"x-canonical-private-synchronous", "x-dunst-stack-tag"} {
		if hints[key].Value() != "skipi-vpn" {
			t.Errorf("hint %s = %v", key, hints[key])
		}
	}
}
