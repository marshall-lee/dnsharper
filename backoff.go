package main

import (
	"time"
	"math/rand"
)

type backoff struct {
	exp     uint8
	timeout time.Duration
}

func (backoff *backoff) increaseTimeout(baseTimeout, maxTimeout time.Duration) {
	timeoutRange := int64(baseTimeout) * int64(backoff.exp)
	if 2*timeoutRange > int64(maxTimeout) {
		timeoutRange = int64(maxTimeout / 2)
	} else {
		backoff.exp *= 2
	}
	backoff.timeout = time.Duration(timeoutRange + rand.Int63n(1+timeoutRange))
}
