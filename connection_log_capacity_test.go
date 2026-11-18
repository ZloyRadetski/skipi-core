package skipicore

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestConnectionLogKeepsNewestEntriesAcrossTrims(t *testing.T) {
	l := newConnectionLog(true)
	const total = 2*connectionLogCapacity + 537
	for i := 1; i <= total; i++ {
		l.record(fmt.Sprintf("[Info] [%d] dispatcher: taking detour [proxy] for [tcp:h%d.test:443]", i, i))
	}
	var s connectionLogSnapshot
	if err := json.Unmarshal([]byte(l.snapshot(0)), &s); err != nil {
		t.Fatal(err)
	}
	if s.Seq != total || len(s.Entries) != connectionLogCapacity {
		t.Fatalf("seq=%d entries=%d", s.Seq, len(s.Entries))
	}
	if s.Entries[0].Seq != total-connectionLogCapacity+1 || s.Entries[len(s.Entries)-1].Seq != total {
		t.Fatalf("window %d..%d", s.Entries[0].Seq, s.Entries[len(s.Entries)-1].Seq)
	}
	var tail connectionLogSnapshot
	_ = json.Unmarshal([]byte(l.snapshot(total-2)), &tail)
	if len(tail.Entries) != 2 || tail.Entries[1].Host != fmt.Sprintf("h%d.test", total) {
		t.Fatalf("tail: %+v", tail)
	}
}
