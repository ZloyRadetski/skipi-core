// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package desktopbridge

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"testing"
)

func TestRuntimeRequiresAssetsBeforeStart(t *testing.T) {
	runtime := NewRuntime()
	handle := runtime.CreateController()

	err := runtime.Start(handle, testXrayConfig(t), 0)
	if !errors.Is(err, ErrAssetsNotInitialized) {
		t.Fatalf("expected uninitialized-assets error, got %v", err)
	}
}

func TestRuntimeRejectsInvalidAssetDirectory(t *testing.T) {
	runtime := NewRuntime()
	if err := runtime.InitializeAssets(" "); err == nil {
		t.Fatal("expected blank asset directory to be rejected")
	}
	if err := runtime.InitializeAssets(t.TempDir() + "/missing"); err == nil {
		t.Fatal("expected missing asset directory to be rejected")
	}
}

func TestRuntimeStartQueryAndStop(t *testing.T) {
	runtime := initializedRuntime(t)
	handle := runtime.CreateController()
	t.Cleanup(func() {
		_ = runtime.DestroyController(handle)
	})

	if err := runtime.Start(handle, testXrayConfig(t), 0); err != nil {
		t.Fatalf("start core: %v", err)
	}
	if runtime.ActiveHandle() != handle {
		t.Fatalf("active handle = %d, want %d", runtime.ActiveHandle(), handle)
	}
	running, err := runtime.IsRunning(handle)
	if err != nil {
		t.Fatalf("read running state: %v", err)
	}
	if !running {
		t.Fatal("expected started core to be running")
	}

	stats, err := runtime.QueryTrafficStats(handle)
	if err != nil {
		t.Fatalf("query traffic stats: %v", err)
	}
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stats), &parsed); err != nil {
		t.Fatalf("traffic stats are not JSON: %v; value=%q", err, stats)
	}
	if parsed["inbound"] == nil || parsed["outbound"] == nil {
		t.Fatalf("unexpected traffic stats shape: %s", stats)
	}

	if err := runtime.Stop(handle); err != nil {
		t.Fatalf("stop core: %v", err)
	}
	running, err = runtime.IsRunning(handle)
	if err != nil {
		t.Fatalf("read stopped state: %v", err)
	}
	if running {
		t.Fatal("expected stopped core to be inactive")
	}
	if runtime.ActiveHandle() != 0 {
		t.Fatalf("active handle = %d after stop, want 0", runtime.ActiveHandle())
	}
}

func TestRuntimeAllowsOnlyOneActiveController(t *testing.T) {
	runtime := initializedRuntime(t)
	first := runtime.CreateController()
	second := runtime.CreateController()
	t.Cleanup(func() {
		_ = runtime.DestroyController(first)
		_ = runtime.DestroyController(second)
	})

	if err := runtime.Start(first, testXrayConfig(t), 0); err != nil {
		t.Fatalf("start first controller: %v", err)
	}
	err := runtime.Start(second, testXrayConfig(t), 0)
	if !errors.Is(err, ErrAnotherControllerActive) {
		t.Fatalf("expected active-controller error, got %v", err)
	}
}

func TestRuntimeProcessLeaseIsSharedAcrossRuntimeInstances(t *testing.T) {
	firstRuntime := initializedRuntime(t)
	first := firstRuntime.CreateController()
	secondRuntime := NewRuntime()
	second := secondRuntime.CreateController()
	t.Cleanup(func() {
		_ = firstRuntime.DestroyController(first)
		_ = secondRuntime.DestroyController(second)
	})

	if err := firstRuntime.Start(first, testXrayConfig(t), 0); err != nil {
		t.Fatalf("start first runtime: %v", err)
	}
	if err := secondRuntime.InitializeAssets(t.TempDir()); err == nil {
		t.Fatal("expected asset replacement while another runtime is active to fail")
	}
	err := secondRuntime.Start(second, testXrayConfig(t), 0)
	if !errors.Is(err, ErrAssetsNotInitialized) {
		t.Fatalf("expected second runtime to require its own assets, got %v", err)
	}

	if err := firstRuntime.Stop(first); err != nil {
		t.Fatalf("stop first runtime: %v", err)
	}
	if err := secondRuntime.InitializeAssets(t.TempDir()); err != nil {
		t.Fatalf("initialize second runtime after handover: %v", err)
	}
	if err := secondRuntime.Start(second, testXrayConfig(t), 0); err != nil {
		t.Fatalf("start second runtime after handover: %v", err)
	}
}

func TestDestroyControllerStopsActiveCore(t *testing.T) {
	runtime := initializedRuntime(t)
	handle := runtime.CreateController()
	if err := runtime.Start(handle, testXrayConfig(t), 0); err != nil {
		t.Fatalf("start controller: %v", err)
	}
	if err := runtime.DestroyController(handle); err != nil {
		t.Fatalf("destroy active controller: %v", err)
	}
	if runtime.ActiveHandle() != 0 {
		t.Fatalf("active handle = %d after destroy, want 0", runtime.ActiveHandle())
	}
	if _, err := runtime.IsRunning(handle); !errors.Is(err, ErrControllerNotFound) {
		t.Fatalf("expected destroyed handle error, got %v", err)
	}
}

func initializedRuntime(t *testing.T) *Runtime {
	t.Helper()
	runtime := NewRuntime()
	if err := runtime.InitializeAssets(t.TempDir()); err != nil {
		t.Fatalf("initialize assets: %v", err)
	}
	return runtime
}

func testXrayConfig(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve local port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("release local port: %v", err)
	}
	return fmt.Sprintf(
		"{\"log\":{\"loglevel\":\"none\"},\"inbounds\":[{\"listen\":\"127.0.0.1\",\"port\":%d,\"protocol\":\"http\",\"settings\":{}}],\"outbounds\":[{\"protocol\":\"freedom\",\"tag\":\"direct\"}]}",
		port,
	)
}
