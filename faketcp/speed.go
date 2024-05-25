package faketcp

import (
	"runtime"
	"sync/atomic"
	"time"
)

type speed struct {
	step      uint32
	bytes     atomic.Uint32
	prevTime  atomic.Pointer[time.Time]
	prevSpeed atomic.Pointer[float64]
}

// NewSpeed new a bandwidth grapher, when transmit step bytes data, speed will update
func NewSpeed(step uint32) *speed {
	var s = &speed{
		step:      step,
		prevTime:  atomic.Pointer[time.Time]{},
		prevSpeed: atomic.Pointer[float64]{},
	}
	s.prevTime.Store(nullTime)
	s.prevSpeed.Store(new(float64))
	return s
}

var nullTime = &time.Time{}

func (s *speed) Add(bytes uint32) {
	if bytes > 0 {
		new := s.bytes.Add(bytes)
		if new > s.step {
			s.upgrade()
		} else if new == bytes {
			now := time.Now()
			for !s.prevTime.CompareAndSwap(nullTime, &now) {
				runtime.Gosched()
				now = time.Now()
			}
		}
	}
}
func (s *speed) Speed() float64 {
	return *s.prevSpeed.Load()
}
func (s *speed) upgrade() {
	bytes := s.bytes.Swap(0)
	dur := time.Since(*s.prevTime.Swap(nullTime))

	v := float64(bytes) / dur.Seconds()
	s.prevSpeed.Store(&v)
}
