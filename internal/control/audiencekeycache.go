package control

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/enboxorg/meshd/internal/dwn"
)

const (
	defaultAudienceKeyFailureTTL = 30 * time.Second
	maxAudienceKeyFailures       = 256
)

var (
	errAudienceKeyDeliveryAbsent   = errors.New("audience key delivery absent")
	errAudienceRecordAbsent        = errors.New("audience record absent")
	errAudienceSealUnavailable     = errors.New("audience seal route unavailable")
	errAudienceDeliveryUnavailable = errors.New("audience delivery route unavailable")
)

// audienceKeyCacheKey identifies one role-audience key. A DWNClient is bound
// to a single anchor tenant, network, and reader DID, so those values do not
// need to be repeated in every cache key.
type audienceKeyCacheKey struct {
	protocol string
	rolePath string
	keyID    string
}

type audienceKeyCall struct {
	done              chan struct{}
	err               error
	failureGeneration uint64
}

type audienceKeyFailure struct {
	err       error
	expiresAt time.Time
}

// audienceKeyCache retains successfully delivered role-audience private keys
// for the lifetime of a DWNClient and coalesces concurrent misses. Key IDs are
// public-key thumbprints, so audience rotation naturally selects a new entry.
// Only authoritative delivery absence is cached briefly; transient failures
// are never cached, and full/delivery invalidation clears absence entries.
type audienceKeyCache struct {
	mu                sync.Mutex
	keys              map[audienceKeyCacheKey][]byte
	inflight          map[audienceKeyCacheKey]*audienceKeyCall
	failures          map[audienceKeyCacheKey]audienceKeyFailure
	failureGeneration uint64
	failureTTL        time.Duration
	now               func() time.Time
}

// get takes ownership of the buffer returned by load and zeroes it after
// retaining and returning independent copies.
func (c *audienceKeyCache) get(
	ctx context.Context,
	key audienceKeyCacheKey,
	load func(context.Context) ([]byte, error),
) ([]byte, error) {
	for {
		c.mu.Lock()
		if privateKey, ok := c.keys[key]; ok {
			result := append([]byte(nil), privateKey...)
			c.mu.Unlock()
			return result, nil
		}
		now := c.timeNowLocked()
		if failure, ok := c.failures[key]; ok {
			if now.Before(failure.expiresAt) {
				c.mu.Unlock()
				return nil, failure.err
			}
			delete(c.failures, key)
		}
		generation := c.failureGeneration
		if call, ok := c.inflight[key]; ok && call.failureGeneration == generation {
			done := call.done
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-done:
				if call.err != nil {
					// A short-lived leader must not cancel otherwise-live waiters.
					// Re-enter the election; exactly one waiter becomes the new loader.
					if ctx.Err() == nil && (errors.Is(call.err, context.Canceled) ||
						errors.Is(call.err, context.DeadlineExceeded)) {
						continue
					}
					return nil, call.err
				}
				// The successful loader populated the cache before closing done.
				continue
			}
		}

		if c.inflight == nil {
			c.inflight = make(map[audienceKeyCacheKey]*audienceKeyCall)
		}
		call := &audienceKeyCall{done: make(chan struct{}), failureGeneration: generation}
		c.inflight[key] = call
		c.mu.Unlock()

		privateKey, err := load(ctx)
		if err == nil && len(privateKey) == 0 {
			err = fmt.Errorf("delivered audience key is empty")
		}

		c.mu.Lock()
		if err == nil {
			if c.keys == nil {
				c.keys = make(map[audienceKeyCacheKey][]byte)
			}
			c.keys[key] = append([]byte(nil), privateKey...)
			delete(c.failures, key)
		} else if call.failureGeneration == c.failureGeneration && stableAudienceKeyFailure(err) {
			if _, alreadyAvailable := c.keys[key]; !alreadyAvailable {
				c.cacheFailureLocked(key, err)
			}
		}
		call.err = err
		if c.inflight[key] == call {
			delete(c.inflight, key)
		}
		close(call.done)
		c.mu.Unlock()

		if err != nil {
			clear(privateKey)
			return nil, err
		}
		result := append([]byte(nil), privateKey...)
		clear(privateKey)
		return result, nil
	}
}

func (c *audienceKeyCache) invalidateFailures() {
	c.mu.Lock()
	c.failureGeneration++
	c.failures = nil
	c.mu.Unlock()
}

func (c *audienceKeyCache) timeNowLocked() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *audienceKeyCache) cacheFailureLocked(key audienceKeyCacheKey, err error) {
	now := c.timeNowLocked()
	ttl := c.failureTTL
	if ttl <= 0 {
		ttl = defaultAudienceKeyFailureTTL
	}
	if c.failures == nil {
		c.failures = make(map[audienceKeyCacheKey]audienceKeyFailure)
	}
	for cachedKey, failure := range c.failures {
		if !now.Before(failure.expiresAt) {
			delete(c.failures, cachedKey)
		}
	}
	if len(c.failures) >= maxAudienceKeyFailures {
		var oldestKey audienceKeyCacheKey
		var oldest time.Time
		for cachedKey, failure := range c.failures {
			if oldest.IsZero() || failure.expiresAt.Before(oldest) ||
				(failure.expiresAt.Equal(oldest) && audienceKeyCacheKeyLess(cachedKey, oldestKey)) {
				oldestKey = cachedKey
				oldest = failure.expiresAt
			}
		}
		delete(c.failures, oldestKey)
	}
	c.failures[key] = audienceKeyFailure{err: err, expiresAt: now.Add(ttl)}
}

func audienceKeyCacheKeyLess(a, b audienceKeyCacheKey) bool {
	if a.protocol != b.protocol {
		return a.protocol < b.protocol
	}
	if a.rolePath != b.rolePath {
		return a.rolePath < b.rolePath
	}
	return a.keyID < b.keyID
}

func stableAudienceKeyFailure(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, dwn.ErrRateLimited) || errors.Is(err, dwn.ErrTransport) {
		return false
	}
	return errors.Is(err, errAudienceKeyDeliveryAbsent)
}
