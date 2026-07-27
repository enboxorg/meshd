package engine

import (
	"sync"
	"time"

	"github.com/enboxorg/meshnet/net/netmon"
)

// wakeProbeDebounce is the minimum spacing between link-change-driven
// subscription health probes, so a flapping link cannot stampede the DWN
// with rpc.ping traffic.
const wakeProbeDebounce = time.Second

// wakeProber fans netmon link-change callbacks into subscription health
// probes — the daemon analog of the browser online/visibilitychange wake
// listeners. Major deltas (rebind-worthy link changes and wall-clock jumps,
// i.e. resume from sleep) force an immediate liveness verdict on every
// active stream instead of waiting out heartbeat timers that never fired
// while the machine was asleep.
type wakeProber struct {
	minInterval time.Duration
	check       func()
	now         func() time.Time // injectable for tests

	mu   sync.Mutex
	last time.Time
}

func newWakeProber(minInterval time.Duration, check func()) *wakeProber {
	return &wakeProber{
		minInterval: minInterval,
		check:       check,
		now:         time.Now,
	}
}

// OnNetworkChange is registered as a netmon change callback. netmon invokes
// callbacks on their own goroutine, so a blocking probe here cannot stall
// the monitor.
func (p *wakeProber) OnNetworkChange(delta *netmon.ChangeDelta) {
	if delta == nil || !wakeProbeRelevant(delta) {
		return
	}
	now := p.now()
	p.mu.Lock()
	if !p.last.IsZero() && now.Sub(p.last) < p.minInterval {
		p.mu.Unlock()
		return
	}
	p.last = now
	p.mu.Unlock()
	p.check()
}

// wakeProbeRelevant reports whether a delta is a major change worth an
// immediate probe. TimeJumped is checked separately because a resume from
// sleep can report a not-yet-viable default interface, which suppresses
// RebindLikelyRequired.
func wakeProbeRelevant(delta *netmon.ChangeDelta) bool {
	return delta.RebindLikelyRequired || delta.TimeJumped
}
