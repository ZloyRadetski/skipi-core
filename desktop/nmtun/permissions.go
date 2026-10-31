// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package nmtun

import "fmt"

const (
	permissionControl = "org.freedesktop.NetworkManager.network-control"
	permissionModify  = "org.freedesktop.NetworkManager.settings.modify.own"
)

// checkPermissions requires both permissions without an interactive prompt: a "yes" lets the
// application work unattended, anything else would stop it at boot.
func checkPermissions(permissions map[string]string) error {
	for _, name := range []string{permissionControl, permissionModify} {
		if permissions[name] != "yes" {
			return fmt.Errorf("NetworkManager does not grant %s to this user (%q)",
				name[len("org.freedesktop.NetworkManager."):], permissions[name])
		}
	}
	return nil
}
