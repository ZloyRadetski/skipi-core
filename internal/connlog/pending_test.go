// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package connlog

import (
	"fmt"
	"strings"
	"testing"

	corecommlog "github.com/xtls/xray-core/common/log"
)

// A full pending table drops its oldest names only; the connections still in flight keep theirs.
func TestPendingOverflowEvictsOldestNotEverything(t *testing.T) {
	l := New(true)
	for i := 0; i < pendingLimit+10; i++ {
		l.Record(fmt.Sprintf("[%d] proxy/dispatcher: sniffed domain: d%d.example", i, i))
	}
	recent := pendingLimit - 1
	l.Record(fmt.Sprintf("[%d] default route for tcp:1.1.1.1:443", recent))
	if !strings.Contains(l.Snapshot(0), fmt.Sprintf("d%d.example", recent)) {
		t.Fatal("a recent sniffed name was lost when the table overflowed")
	}
	l.mu.Lock()
	n := len(l.pending)
	l.mu.Unlock()
	if n > pendingLimit {
		t.Fatalf("pending grew to %d", n)
	}
}

type countingContent struct{ called *int }

func (c countingContent) String() string { *c.called++; return "[1] default route for tcp:a:1" }

// A disabled log must not even format the message.
func TestHandlerDoesNotFormatWhileDisabled(t *testing.T) {
	called := 0
	h := &handler{log: New(false)}
	h.Handle(&corecommlog.GeneralMessage{Severity: corecommlog.Severity_Info, Content: countingContent{&called}})
	if called != 0 {
		t.Fatalf("String called %d times while disabled", called)
	}
}
