package main

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"time"
)

type ip4 [4]byte

type ip4target struct {
	sync.Mutex
	backoff
	timestamp time.Time
}

type ip4targets struct {
	baseTimeout time.Duration
	targets     map[ip4]*ip4target
}

func makeip4targets(ip4net *net.IPNet, baseTimeout time.Duration) ip4targets {
	num := binary.BigEndian.Uint32([]byte(ip4net.IP))
	mask := binary.BigEndian.Uint32([]byte(ip4net.Mask))
	network := num & mask
	broadcast := network | ^mask
	network++
	targets := make(map[ip4]*ip4target, broadcast-network)
	backoff := backoff{timeout: baseTimeout, exp: 1}
	for ; network < broadcast; network++ {
		var ip [4]byte
		binary.BigEndian.PutUint32(ip[:], network)
		targets[ip] = &ip4target{backoff: backoff}
	}
	return ip4targets{baseTimeout: baseTimeout, targets: targets}
}

func (t ip4targets) reset(ip4 ip4) {
	target := t.targets[ip4]
	target.Lock()
	target.backoff = backoff{timeout: t.baseTimeout, exp: 1}
	target.timestamp = time.Now()
	target.Unlock()
}

func (t ip4targets) loop(ctx context.Context, tick time.Duration, fn func(ip4) error) error {
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	for {
		anySent := false
		for ip4, target := range t.targets {
			if err := ctx.Err(); err != nil {
				return err
			}

			now := time.Now()
			target.Lock()
			if !target.timestamp.IsZero() && now.Sub(target.timestamp) < target.timeout {
				target.Unlock()
				continue
			}
			target.timestamp = now
			target.increaseTimeout(t.baseTimeout, maxTimeout)
			target.Unlock()

			if err := fn(ip4); err != nil {
				return err
			}

			anySent = true
			select {
			case <-ticker.C:
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		if !anySent {
			select {
			case <-ticker.C:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}
