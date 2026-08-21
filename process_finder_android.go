// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build android

package skipicore

import (
	"fmt"
	"strconv"

	corenet "github.com/xtls/xray-core/common/net"
)

// RegisterProcessFinder registers an Android process finder for socket-based per-app routing rules.
func (c *CoreController) RegisterProcessFinder(finder ProcessFinder) {
	if finder == nil {
		corenet.RegisterAndroidProcessFinder(nil)
		return
	}

	corenet.RegisterAndroidProcessFinder(func(network, srcIP string, srcPort uint16, destIP string, destPort uint16) (uid int, name string, path string, err error) {
		if destPort == 0 || destIP == "" {
			return 0, "", "", fmt.Errorf("processFinder: no dest for %s %s:%d", network, srcIP, srcPort)
		}

		defer func() {
			if r := recover(); r != nil {
				uid, name, path, err = 0, "", "", fmt.Errorf("processFinder panic: %v", r)
			}
		}()

		uid = finder.FindProcessByConnection(network, srcIP, int(srcPort), destIP, int(destPort))
		return uid, strconv.Itoa(uid), "", nil
	})
}
