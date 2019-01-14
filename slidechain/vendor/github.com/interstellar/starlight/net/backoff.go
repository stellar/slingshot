package net

import (
	"math/rand"
	"time"
)

// Backoff assists in implementing retry loops with exponential backoff and jitter.
type Backoff struct {
	// Base is the base duration for waiting between retries.
	Base time.Duration

	lastDur time.Duration
}

const backoff float64 = 1.2

// Next returns the amount of time to wait for the next retry,
// including exponential backoff and jitter.
func (b *Backoff) Next() time.Duration {
	var dur time.Duration

	if b.lastDur > 0 {
		dur = b.lastDur
		dur2 := time.Duration(float64(dur) * backoff)
		if dur2 == dur {
			dur2++
		}
		dur = dur2
	} else {
		dur = b.Base
	}

	b.lastDur = dur

	return Jitter(dur)
}

// Jitter returns a random duration in the range dur ±25%.
func Jitter(dur time.Duration) time.Duration {
	h := int64(dur / 2)
	delta := rand.Int63n(h) - h/2
	return dur + time.Duration(delta)
}
