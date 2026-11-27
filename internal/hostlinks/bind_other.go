// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build !(android && cgo)

package hostlinks

// InstallBinder does nothing where there is no host to bind networks: a link with a handle then fails to dial and
// is left for another link.
func InstallBinder() {}
