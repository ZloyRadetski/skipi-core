package multilink

import (
	"testing"
	"time"

	"github.com/ZloyRadetski/skipi-core/desktop/multilink/nics"
)

func dueCount(s *Scheduler) int {
	jobs := s.probeDue()
	for _, j := range jobs {
		j.sl.probing[j.f].Store(false)
	}
	return len(jobs)
}

// With no flow open, no dial lately and no data arriving, nothing needs proving every 15 s.
func TestIdleSchedulerProbesRarely(t *testing.T) {
	s := NewScheduler([]nics.Nic{nic("A", "10.0.0.1", 1), nic("B", "10.0.0.2", 1)})
	clock := time.Unix(1000, 0)
	s.now = func() time.Time { return clock }
	if dueCount(s) != 2 {
		t.Fatal("new links are probed at once")
	}
	for _, sl := range s.slots {
		s.SetState(sl, Fam4, true)
	}
	clock = clock.Add(probeEveryUp)
	if dueCount(s) != 0 {
		t.Fatal("an idle scheduler probed after probeEveryUp")
	}
	clock = clock.Add(probeEveryIdle)
	if dueCount(s) != 2 {
		t.Fatal("an idle scheduler must still probe every probeEveryIdle")
	}
}

// A dial or an open flow brings the normal period back.
func TestDialsBringTheNormalProbePeriodBack(t *testing.T) {
	s := NewScheduler([]nics.Nic{nic("A", "10.0.0.1", 1), nic("B", "10.0.0.2", 1)})
	clock := time.Unix(1000, 0)
	s.now = func() time.Time { return clock }
	dueCount(s)
	for _, sl := range s.slots {
		s.SetState(sl, Fam4, true)
	}
	clock = clock.Add(time.Minute)
	sl := s.AcquireFor(Fam4, nil) // a dial
	s.ReleaseFor(sl, Fam4)
	clock = clock.Add(probeEveryUp)
	if dueCount(s) != 2 {
		t.Fatal("a recent dial must keep the 15 s probes")
	}
	clock = clock.Add(probeEveryUp + probeIdleAfter)
	if dueCount(s) != 0 {
		t.Fatal("the dial is long ago, the scheduler is idle again")
	}
	held := s.AcquireFor(Fam4, nil) // a flow that stays open
	clock = clock.Add(probeEveryUp)
	if dueCount(s) == 0 {
		t.Fatal("an open flow must keep the 15 s probes")
	}
	s.ReleaseFor(held, Fam4)
}

// A failed probe that is ignored because the link is busy must not bring the next one in a second.
func TestIgnoredFailedProbeIsNotRetriedEverySecond(t *testing.T) {
	s := NewScheduler([]nics.Nic{nic("A", "10.0.0.1", 1)})
	clock := time.Unix(1000, 0)
	s.now = func() time.Time { return clock }
	a := s.slots[0]
	if dueCount(s) != 1 {
		t.Fatal("a new link is probed at once")
	}
	a.bytesIn[Fam4].Add(1_000_000)
	s.Tick(time.Second) // busy now
	s.SetState(a, Fam4, false)
	if a.state[Fam4] != stateUnknown {
		t.Fatalf("state %v", a.state[Fam4])
	}
	if dueCount(s) != 0 {
		t.Fatal("probed again in the same second")
	}
	clock = clock.Add(probeEveryDown)
	if dueCount(s) != 1 {
		t.Fatal("never probed again")
	}
}
