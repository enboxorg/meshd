package engine

import (
	"sync"
	"time"

	"github.com/enboxorg/meshnet/types/netmap"
)

// peerExpiryScheduler reprojects the local materialized topology when a peer
// membership expires. DWNControl replaces the schedule after every committed
// map, so callbacks from an older generation must never invalidate the map.
//
// Self expiry is deliberately not scheduled here. meshnet's LocalBackend
// SetControlClientStatus path owns a generation-fenced netmap expiry timer; it
// marks the local key expired and blocks engine updates. Sending self expiry
// through the materializer would reject the expired self record and turn a
// terminal local condition into a futile full-DWN reconciliation loop. A later
// membership renewal installs a new map and a new peer-expiry schedule.
type peerExpiryScheduler struct {
	clock  RefreshClock
	notify func()

	mu         sync.Mutex
	timer      RefreshTimer
	cancel     chan struct{}
	generation uint64
	stopped    bool
}

func newPeerExpiryScheduler(clock RefreshClock, notify func()) *peerExpiryScheduler {
	if clock == nil {
		clock = systemRefreshClock{}
	}
	return &peerExpiryScheduler{clock: clock, notify: notify}
}

// Schedule atomically replaces the active deadline with the nearest future
// peer expiry that occurs before self expires. Zero, past, already-expired,
// and post-self-expiry peer deadlines cannot require a local refresh.
func (s *peerExpiryScheduler) Schedule(nm *netmap.NetworkMap) {
	now := s.clock.Now()
	deadline := nextLocalPeerExpiry(nm, now)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return
	}

	s.generation++
	s.stopActiveLocked()
	if deadline.IsZero() {
		return
	}

	timer := s.clock.NewTimer(deadline.Sub(now))
	cancel := make(chan struct{})
	generation := s.generation
	s.timer = timer
	s.cancel = cancel
	go s.wait(timer, cancel, generation)
}

func (s *peerExpiryScheduler) wait(timer RefreshTimer, cancel <-chan struct{}, generation uint64) {
	select {
	case <-timer.C():
		s.fire(generation)
	case <-cancel:
	}
}

func (s *peerExpiryScheduler) fire(generation uint64) {
	s.mu.Lock()
	if s.stopped || generation != s.generation || s.timer == nil {
		s.mu.Unlock()
		return
	}
	s.timer = nil
	s.cancel = nil
	notify := s.notify
	s.mu.Unlock()

	if notify != nil {
		notify()
	}
}

// Stop permanently cancels the active schedule. It is idempotent.
func (s *peerExpiryScheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return
	}
	s.stopped = true
	s.generation++
	s.stopActiveLocked()
}

func (s *peerExpiryScheduler) stopActiveLocked() {
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	if s.cancel != nil {
		close(s.cancel)
		s.cancel = nil
	}
}

func nextLocalPeerExpiry(nm *netmap.NetworkMap, now time.Time) time.Time {
	if nm == nil {
		return time.Time{}
	}

	var nearest time.Time
	for _, peer := range nm.Peers {
		if !peer.Valid() || peer.Expired() {
			continue
		}
		expiry := peer.KeyExpiry()
		if !expiry.After(now) {
			continue
		}
		if nearest.IsZero() || expiry.Before(nearest) {
			nearest = expiry
		}
	}
	if nearest.IsZero() {
		return time.Time{}
	}
	if !nm.SelfNode.Valid() {
		return time.Time{}
	}

	selfExpiry := nm.SelfNode.KeyExpiry()
	if selfExpiry.IsZero() {
		return nearest
	}
	// Self authorization is terminal at its deadline. Do not queue a peer
	// projection at or after it: LocalBackend independently fails the engine
	// closed, and a renewed membership will install and schedule a fresh map.
	if !selfExpiry.After(now) || !nearest.Before(selfExpiry) {
		return time.Time{}
	}
	return nearest
}
