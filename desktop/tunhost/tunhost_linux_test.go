// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build linux

package tunhost

import "testing"

func TestOpenRejectsAMalformedPlanBeforeTouchingTheSystem(t *testing.T) {
	if _, err := Open("{"); err == nil {
		t.Fatal("expected a JSON error")
	}
	if _, err := Open(`{"name":"a/b","mtu":1400,"addresses":["10.0.0.1/24"],"routes":[]}`); err == nil {
		t.Fatal("expected a validation error")
	}
}

func TestCloseWithoutASessionIsANoOp(t *testing.T) {
	if err := Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
}

func TestPrepareBindsCoreSocketsBeforeAnInterfaceExistsAndReleaseUndoesIt(t *testing.T) {
	t.Cleanup(func() { _ = Close() })

	if err := Prepare("skipi0"); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if !Prepared() {
		t.Fatal("not prepared after Prepare")
	}

	if err := Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if Prepared() {
		t.Fatal("still prepared after Close")
	}
}

func TestPrepareIsIdempotent(t *testing.T) {
	t.Cleanup(func() { _ = Close() })

	if err := Prepare("skipi0"); err != nil {
		t.Fatal(err)
	}
	if err := Prepare("skipi0"); err != nil {
		t.Fatalf("second Prepare: %v", err)
	}
	if !Prepared() {
		t.Fatal("not prepared")
	}
}

func TestPrepareRejectsAnInvalidInterfaceName(t *testing.T) {
	if err := Prepare("a/b"); err == nil {
		t.Fatal("expected an error")
	}
	if Prepared() {
		t.Fatal("prepared with an invalid name")
	}
}
