// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

// Package skipicore is the SKIPI Core: a thin facade over Xray-core and AmneziaWG.
//
// The package is bound to Android with `gomobile bind` (Java package app.skipi.core.skipicore,
// class Skipicore plus the bound types) and is also imported by the desktop bridge
// (desktop/bridge), which is built as a c-shared library from cmd/skipicore-desktop.
//
// gomobile binds only what is defined in this package, so every exported function, method and
// type lives here, in small files grouped by concern (see docs/ARCHITECTURE.md). The
// implementation behind the facade lives in internal/. testdata/public_api.golden pins the
// exported API; api_test.go fails when it changes.
package skipicore

// coreLibVersion is the version of the SKIPI wrapper reported by CheckVersionX.
const coreLibVersion = 1
