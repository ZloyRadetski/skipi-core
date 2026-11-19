// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

// Package lifecycle holds the bounded-stop machinery shared by the Xray controller and the
// AmneziaWG runner: running a Close with a deadline, counting the closes that were given up
// on, and the stop operation that concurrent callers share.
package lifecycle

import (
	"io"
	"sync"
	"sync/atomic"
	"time"
)

var abandonedInstances atomic.Int64

// Abandoned reports how many closes were given up on and have not returned yet.
func Abandoned() int64 {
	return abandonedInstances.Load()
}

// MarkAbandoned counts one more abandoned close.
func MarkAbandoned() { abandonedInstances.Add(1) }

// UnmarkAbandoned ends the count of one abandoned close.
func UnmarkAbandoned() { abandonedInstances.Add(-1) }

// RunBounded runs fn in its own goroutine and waits up to d (or until cancel closes). When it
// gives up, the call is counted in AbandonedInstances until fn returns, and timedOut is true.
func RunBounded(fn func() error, d time.Duration, cancel <-chan struct{}) (error, bool) {
	const (
		running = iota
		finished
		abandoned
	)
	var (
		state  atomic.Int32
		result error
	)
	done := make(chan struct{})
	go func() {
		result = fn()
		if !state.CompareAndSwap(running, finished) {
			abandonedInstances.Add(-1) // the waiter gave up on us; we are no longer leaked
		}
		close(done)
	}()

	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-done:
		return result, false
	case <-timer.C:
	case <-cancel:
	}
	// Count first, then claim: the goroutine can never decrement before this increment.
	abandonedInstances.Add(1)
	if !state.CompareAndSwap(running, abandoned) {
		abandonedInstances.Add(-1) // it finished in the meantime
		<-done
		return result, false
	}
	return nil, true
}

// CloseInBackground closes inst without waiting; the Close is counted as abandoned while it runs.
func CloseInBackground(inst io.Closer) {
	abandonedInstances.Add(1)
	go func() {
		defer abandonedInstances.Add(-1)
		_ = inst.Close()
	}()
}

// StopOp is one in-flight stop. ForceNow makes its waiter give up at once.
type StopOp struct {
	finished  chan struct{}
	force     chan struct{}
	forceOnce sync.Once
	err       error // valid once finished is closed
}

// NewStopOp returns a stop operation that has neither finished nor been forced.
func NewStopOp() *StopOp {
	return &StopOp{finished: make(chan struct{}), force: make(chan struct{})}
}

// Force is closed when ForceNow is called; pass it as RunBounded's cancel channel.
func (o *StopOp) Force() <-chan struct{} { return o.force }

// Done is closed once Finish has been called.
func (o *StopOp) Done() <-chan struct{} { return o.finished }

// Err is the stop's result; it is only valid once Done is closed.
func (o *StopOp) Err() error { return o.err }

// Finish records the stop's result and releases everyone waiting on Done.
func (o *StopOp) Finish(err error) {
	o.err = err
	close(o.finished)
}

// ForceNow makes the waiter of this stop give up at once.
func (o *StopOp) ForceNow() { o.forceOnce.Do(func() { close(o.force) }) }

// Wait lets a second caller share an in-flight stop; its own deadline detaches the instance too.
func (o *StopOp) Wait(d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-o.finished:
	case <-timer.C:
		o.ForceNow()
		<-o.finished
	}
	return o.err
}
