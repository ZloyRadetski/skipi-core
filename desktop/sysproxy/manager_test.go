// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package sysproxy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var testEndpoints = Endpoints{Host: "127.0.0.1", HTTPPort: 10809, SocksPort: 10808}

// fakeBackend keeps the "system" proxy as one string, so a test sees exactly what a user would.
type fakeBackend struct {
	current   string
	ownership map[string]Ownership // by owner token; absent means Active
	calls     []string
	applyErr  error
	restoreOK func() error
	clearErr  error
	supported bool
}

func newFakeBackend() *fakeBackend { return &fakeBackend{current: "user-original", supported: true} }

func (b *fakeBackend) log(s string) { b.calls = append(b.calls, s) }

func (b *fakeBackend) Supported() bool { return b.supported }

func (b *fakeBackend) Capture() (json.RawMessage, error) {
	b.log("capture")
	return json.Marshal(b.current)
}

func (b *fakeBackend) Apply(l Lease) error {
	b.log("apply")
	if b.applyErr != nil {
		return b.applyErr
	}
	b.current = "skipi:" + l.Endpoints.Host
	return nil
}

func (b *fakeBackend) Ownership(l Lease) (Ownership, error) {
	if o, ok := b.ownership[l.OwnerToken]; ok {
		return o, nil
	}
	if l.Phase == PhasePrepared {
		return Restorable, nil
	}
	return Active, nil
}

func (b *fakeBackend) Restore(l Lease) error {
	b.log("restore")
	if b.restoreOK != nil {
		if err := b.restoreOK(); err != nil {
			return err
		}
	}
	var original string
	_ = json.Unmarshal(l.Snapshot, &original)
	b.current = original
	return nil
}

func (b *fakeBackend) Discard(Lease) error { b.log("discard"); return nil }

func (b *fakeBackend) ForceClear() error {
	b.log("force-clear")
	b.current = "off"
	return b.clearErr
}

func (b *fakeBackend) RepairStale() (bool, error) { return false, nil }

func newTestManager(t *testing.T, b Backend) (*Manager, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "lease.json")
	m := NewManager(b, path)
	n := 0
	m.newToken = func() string { n++; return "token-" + string(rune('a'+n)) }
	return m, path
}

func mustAction(t *testing.T, got Result, err error, want Action) {
	t.Helper()
	if err != nil {
		t.Fatalf("want %s, got error %v", want, err)
	}
	if got.Action != want {
		t.Fatalf("action = %s, want %s", got.Action, want)
	}
}

func TestAcquireAppliesTheEndpointsAndReleaseRestoresTheExactOriginal(t *testing.T) {
	b := newFakeBackend()
	m, path := newTestManager(t, b)

	res, err := m.Acquire(testEndpoints)
	mustAction(t, res, err, ActionAcquired)
	if b.current != "skipi:127.0.0.1" {
		t.Fatalf("proxy not applied: %q", b.current)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("lease must exist while the proxy is ours: %v", err)
	}

	res, err = m.Release()
	mustAction(t, res, err, ActionReleased)
	if b.current != "user-original" {
		t.Fatalf("original not restored: %q", b.current)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("lease must be removed after release, stat err = %v", err)
	}
}

func TestAcquiringTheSameEndpointsTwiceChangesNothing(t *testing.T) {
	b := newFakeBackend()
	m, _ := newTestManager(t, b)
	if _, err := m.Acquire(testEndpoints); err != nil {
		t.Fatal(err)
	}
	b.calls = nil

	res, err := m.Acquire(testEndpoints)
	mustAction(t, res, err, ActionAlreadyAcquired)
	if len(b.calls) != 0 {
		t.Fatalf("an already acquired proxy must not be touched: %v", b.calls)
	}
}

func TestAcquiringOtherEndpointsKeepsTheUsersOriginalSnapshot(t *testing.T) {
	b := newFakeBackend()
	m, _ := newTestManager(t, b)
	if _, err := m.Acquire(testEndpoints); err != nil {
		t.Fatal(err)
	}
	moved := Endpoints{Host: "127.0.0.1", HTTPPort: 20809, SocksPort: 20808}

	res, err := m.Acquire(moved)
	mustAction(t, res, err, ActionAcquired)
	res, err = m.Release()
	mustAction(t, res, err, ActionReleased)
	if b.current != "user-original" {
		t.Fatalf("the snapshot must stay the user's, got %q", b.current)
	}
}

func TestAFailedApplyRollsBackAndLeavesNoLease(t *testing.T) {
	b := newFakeBackend()
	b.applyErr = errors.New("write denied")
	m, path := newTestManager(t, b)

	_, err := m.Acquire(testEndpoints)
	if err == nil || !strings.Contains(err.Error(), "write denied") {
		t.Fatalf("want the apply error, got %v", err)
	}
	if b.current != "user-original" {
		t.Fatalf("a failed acquire must roll back, got %q", b.current)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("no lease may stay after a clean rollback: %v", err)
	}
}

func TestAFailedRollbackKeepsTheLeaseSoRecoveryCanRetry(t *testing.T) {
	b := newFakeBackend()
	b.applyErr = errors.New("write denied")
	b.restoreOK = func() error { return errors.New("restore denied") }
	m, path := newTestManager(t, b)

	_, err := m.Acquire(testEndpoints)
	if err == nil || !strings.Contains(err.Error(), "write denied") || !strings.Contains(err.Error(), "restore denied") {
		t.Fatalf("both failures must be reported, got %v", err)
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("the lease must stay for a retry: %v", statErr)
	}

	b.restoreOK = nil
	res, err := m.Recover()
	mustAction(t, res, err, ActionRecovered)
	if b.current != "user-original" {
		t.Fatalf("recovery must restore, got %q", b.current)
	}
}

func TestReleaseNeverOverwritesAProxyChangedOutsideSkipi(t *testing.T) {
	b := newFakeBackend()
	m, path := newTestManager(t, b)
	if _, err := m.Acquire(testEndpoints); err != nil {
		t.Fatal(err)
	}
	b.ownership = map[string]Ownership{"token-b": NotOwned}
	b.current = "changed-by-user"
	b.calls = nil

	res, err := m.Release()
	mustAction(t, res, err, ActionSkippedNotOwner)
	if b.current != "changed-by-user" {
		t.Fatalf("a foreign setting must stay: %q", b.current)
	}
	if strings.Join(b.calls, ",") != "discard" {
		t.Fatalf("only our marker may be discarded: %v", b.calls)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("an unowned lease must be dropped: %v", err)
	}
}

func TestRecoverRestoresALeaseAnEarlierSessionLeftBehind(t *testing.T) {
	b := newFakeBackend()
	m, _ := newTestManager(t, b)
	if _, err := m.Acquire(testEndpoints); err != nil {
		t.Fatal(err)
	}

	// A new process: a fresh manager over the same lease file.
	restarted := NewManager(b, m.leasePath)
	res, err := restarted.Recover()
	mustAction(t, res, err, ActionRecovered)
	if b.current != "user-original" {
		t.Fatalf("got %q", b.current)
	}
}

func TestRecoverAndReleaseWithoutALeaseDoNothing(t *testing.T) {
	b := newFakeBackend()
	m, _ := newTestManager(t, b)

	res, err := m.Recover()
	mustAction(t, res, err, ActionNothingToRelease)
	res, err = m.Release()
	mustAction(t, res, err, ActionNothingToRelease)
	if len(b.calls) != 0 {
		t.Fatalf("nothing to restore, nothing to touch: %v", b.calls)
	}
}

func TestForceClearSwitchesTheProxyOffAndDropsTheLease(t *testing.T) {
	b := newFakeBackend()
	m, path := newTestManager(t, b)
	if _, err := m.Acquire(testEndpoints); err != nil {
		t.Fatal(err)
	}

	if err := m.ForceClear(); err != nil {
		t.Fatal(err)
	}
	if b.current != "off" {
		t.Fatalf("got %q", b.current)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("lease must be dropped: %v", err)
	}
}

func TestForceClearReportsAFailureButStillDropsTheLease(t *testing.T) {
	b := newFakeBackend()
	b.clearErr = errors.New("ProxyEnable stayed 1")
	m, path := newTestManager(t, b)
	if _, err := m.Acquire(testEndpoints); err != nil {
		t.Fatal(err)
	}

	err := m.ForceClear()
	if err == nil || !strings.Contains(err.Error(), "ProxyEnable stayed 1") {
		t.Fatalf("the failure must be reported, got %v", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("lease must be dropped anyway: %v", statErr)
	}
}

func TestAnInterruptedPreparedLeaseIsRestoredNotTrustedAsActive(t *testing.T) {
	b := newFakeBackend()
	m, path := newTestManager(t, b)
	prepared := Lease{Version: LeaseVersion, Phase: PhasePrepared, OwnerToken: "t", Endpoints: testEndpoints, Snapshot: json.RawMessage(`"user-original"`)}
	if err := saveLease(path, prepared); err != nil {
		t.Fatal(err)
	}
	b.current = "half-applied"

	res, err := m.Acquire(testEndpoints)
	mustAction(t, res, err, ActionAcquired)
	if got := strings.Join(b.calls, ","); !strings.HasPrefix(got, "restore,") {
		t.Fatalf("the half applied state must be restored first: %s", got)
	}
}

func TestALeaseOfAnUnknownVersionIsRefusedAndLeftAlone(t *testing.T) {
	b := newFakeBackend()
	m, path := newTestManager(t, b)
	if err := os.WriteFile(path, []byte(`{"version":99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Release(); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("an unreadable lease must not be deleted")
	}
}

func TestOnlyLoopbackEndpointsAreAccepted(t *testing.T) {
	m, _ := newTestManager(t, newFakeBackend())
	for _, bad := range []Endpoints{
		{Host: "8.8.8.8", HTTPPort: 1, SocksPort: 2},
		{Host: "127.0.0.1", HTTPPort: 0, SocksPort: 2},
		{Host: "127.0.0.1", HTTPPort: 1, SocksPort: 70000},
	} {
		if _, err := m.Acquire(bad); err == nil {
			t.Fatalf("%+v must be refused", bad)
		}
	}
}

func TestAnotherProcessHoldingTheLockStopsTheChange(t *testing.T) {
	b := newFakeBackend()
	m, _ := newTestManager(t, b)
	unlock, err := lockFile(m.leasePath + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()

	other := NewManager(b, m.leasePath)
	if _, err := other.Acquire(testEndpoints); err == nil || !strings.Contains(err.Error(), "Another SKIPI process") {
		t.Fatalf("got %v", err)
	}
}
