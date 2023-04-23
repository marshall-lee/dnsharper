package main

import (
	"context"
	"sync"
	"time"
)

type ip6 [16]byte

type ip6target struct {
	sync.Mutex
	backoff
	try       uint8
	timestamp time.Time
}

type ip6targets struct {
	sync.Mutex
	baseTimeout time.Duration
	maxTries    uint8
	targets     map[ip6]*ip6target
}

func makeip6targets(baseTimeout time.Duration) *ip6targets {
	targets := make(map[ip6]*ip6target)
	return &ip6targets{baseTimeout: baseTimeout, maxTries: 10, targets: targets}
}

func (t *ip6targets) add(ip6 ip6) {
	t.Lock()
	if _, ok := t.targets[ip6]; !ok {
		t.targets[ip6] = &ip6target{backoff: backoff{timeout: t.baseTimeout, exp: 1}}
	}
	t.Unlock()
}

func (t *ip6targets) reset(ip6 ip6) {
	t.Lock()
	target, ok := t.targets[ip6]
	if !ok {
		target = &ip6target{}
	}
	target.Lock()
	target.try = 0
	target.backoff = backoff{timeout: t.baseTimeout, exp: 1}
	if ok {
		target.timestamp = time.Now()
	}
	target.Unlock()
	t.Unlock()
}

func (t *ip6targets) loop(ctx context.Context, tick time.Duration, fn func(ip6) error) error {
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	for {
		t.Lock()
		ips := make([]ip6, 0, len(t.targets))
		for ip6, target := range t.targets {
			now := time.Now()
			target.Lock()
			if !target.timestamp.IsZero() && now.Sub(target.timestamp) < target.timeout {
				target.Unlock()
				continue
			}
			if target.try++; target.try > t.maxTries {
				delete(t.targets, ip6)
			} else {
				target.timestamp = now
				target.increaseTimeout(t.baseTimeout, maxTimeout)
				ips = append(ips, ip6)
			}
			target.Unlock()
		}
		t.Unlock()
		if len(ips) > 0 {
			for _, ip6 := range ips {
				if err := fn(ip6); err != nil {
					return err
				}

				select {
				case <-ticker.C:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		} else {
			select {
			case <-ticker.C:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}
