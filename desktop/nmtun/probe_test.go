// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package nmtun

import (
	"strings"
	"testing"
)

const (
	control = "org.freedesktop.NetworkManager.network-control"
	modify  = "org.freedesktop.NetworkManager.settings.modify.own"
)

func TestPermissionsAllowTheTunWhenBothAreGranted(t *testing.T) {
	if err := checkPermissions(map[string]string{control: "yes", modify: "yes"}); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestPermissionsExplainWhatIsMissing(t *testing.T) {
	cases := map[string]struct {
		perms map[string]string
		want  string
	}{
		"control denied":     {map[string]string{control: "no", modify: "yes"}, "network-control"},
		"control needs auth": {map[string]string{control: "auth", modify: "yes"}, "network-control"},
		"modify denied":      {map[string]string{control: "yes", modify: "no"}, "settings.modify.own"},
		"missing entries":    {map[string]string{}, "network-control"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			err := checkPermissions(c.perms)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want mention of %q", err, c.want)
			}
		})
	}
}
