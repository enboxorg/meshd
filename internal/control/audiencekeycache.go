package control

import (
	"context"
	"errors"
	"fmt"
	"sync"
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
	done chan struct{}
	err  error
}

// audienceKeyCache retains successfully delivered role-audience private keys
// for the lifetime of a DWNClient and coalesces concurrent misses. Key IDs are
// public-key thumbprints, so audience rotation naturally selects a new entry.
// Failed lookups are deliberately not cached: a delivery can arrive later, or
// a transient DWN error can recover on the next map refresh.
type audienceKeyCache struct {
	mu       sync.Mutex
	keys     map[audienceKeyCacheKey][]byte
	inflight map[audienceKeyCacheKey]*audienceKeyCall
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
		if call, ok := c.inflight[key]; ok {
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
		call := &audienceKeyCall{done: make(chan struct{})}
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
		}
		call.err = err
		delete(c.inflight, key)
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
