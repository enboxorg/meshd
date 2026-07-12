package control

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enboxorg/meshd/internal/dwn"
	dwncrypto "github.com/enboxorg/meshd/internal/dwn/crypto"
)

func TestAudienceKeyCacheReusesSuccessfulLookupAndCopiesKey(t *testing.T) {
	var cache audienceKeyCache
	key := audienceKeyCacheKey{
		protocol: "https://example.com/mesh",
		rolePath: "network/node",
		keyID:    "key-1",
	}

	source := []byte{1, 2, 3, 4}
	var loads atomic.Int32
	first, err := cache.get(context.Background(), key, func(context.Context) ([]byte, error) {
		loads.Add(1)
		return source, nil
	})
	if err != nil {
		t.Fatalf("first get: %v", err)
	}

	// Neither the loader's buffer nor a caller's returned buffer may alias the
	// retained cache entry: both are routinely cleared by the crypto callers.
	source[0] = 99
	clear(first)

	second, err := cache.get(context.Background(), key, func(context.Context) ([]byte, error) {
		return nil, errors.New("cached lookup unexpectedly called loader")
	})
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	if want := []byte{1, 2, 3, 4}; !bytes.Equal(second, want) {
		t.Fatalf("second key = %v, want %v", second, want)
	}
	if got := loads.Load(); got != 1 {
		t.Fatalf("loader calls = %d, want 1", got)
	}

	second[1] = 88
	third, err := cache.get(context.Background(), key, func(context.Context) ([]byte, error) {
		return nil, errors.New("cached lookup unexpectedly called loader")
	})
	if err != nil {
		t.Fatalf("third get: %v", err)
	}
	if want := []byte{1, 2, 3, 4}; !bytes.Equal(third, want) {
		t.Fatalf("third key = %v, want %v", third, want)
	}
}

func TestAudienceKeyCacheDoesNotCacheFailedLookup(t *testing.T) {
	var cache audienceKeyCache
	key := audienceKeyCacheKey{protocol: "p", rolePath: "r", keyID: "k"}
	wantErr := errors.New("temporary delivery query failure")
	var loads atomic.Int32

	if _, err := cache.get(context.Background(), key, func(context.Context) ([]byte, error) {
		loads.Add(1)
		return nil, wantErr
	}); !errors.Is(err, wantErr) {
		t.Fatalf("failed get error = %v, want %v", err, wantErr)
	}

	wantKey := []byte{7, 8, 9}
	got, err := cache.get(context.Background(), key, func(context.Context) ([]byte, error) {
		loads.Add(1)
		return append([]byte(nil), wantKey...), nil
	})
	if err != nil {
		t.Fatalf("retry get: %v", err)
	}
	if !bytes.Equal(got, wantKey) {
		t.Fatalf("retry key = %v, want %v", got, wantKey)
	}
	if got := loads.Load(); got != 2 {
		t.Fatalf("loader calls = %d, want 2", got)
	}
}

func TestAudienceKeyCacheCachesOnlyStableAbsenceUntilTTL(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	cache := audienceKeyCache{failureTTL: time.Minute, now: func() time.Time { return now }}
	key := audienceKeyCacheKey{protocol: "p", rolePath: "r", keyID: "missing"}
	wantErr := fmt.Errorf("%w: no delivery record", errAudienceKeyDeliveryAbsent)
	var loads atomic.Int32
	loader := func(context.Context) ([]byte, error) {
		loads.Add(1)
		return nil, wantErr
	}
	for range 2 {
		if _, err := cache.get(context.Background(), key, loader); !errors.Is(err, errAudienceKeyDeliveryAbsent) {
			t.Fatalf("stable miss error = %v", err)
		}
	}
	if got := loads.Load(); got != 1 {
		t.Fatalf("stable miss loader calls = %d, want 1", got)
	}
	now = now.Add(time.Minute)
	if _, err := cache.get(context.Background(), key, loader); !errors.Is(err, errAudienceKeyDeliveryAbsent) {
		t.Fatalf("expired stable miss error = %v", err)
	}
	if got := loads.Load(); got != 2 {
		t.Fatalf("expired stable miss loader calls = %d, want 2", got)
	}
}

func TestAudienceKeyCacheInvalidationRetainsSuccessAndNeverCachesTransient(t *testing.T) {
	cache := audienceKeyCache{}
	successKey := audienceKeyCacheKey{protocol: "p", rolePath: "r", keyID: "success"}
	if _, err := cache.get(context.Background(), successKey, func(context.Context) ([]byte, error) {
		return []byte{1, 2, 3}, nil
	}); err != nil {
		t.Fatal(err)
	}
	missingKey := audienceKeyCacheKey{protocol: "p", rolePath: "r", keyID: "missing"}
	if _, err := cache.get(context.Background(), missingKey, func(context.Context) ([]byte, error) {
		return nil, fmt.Errorf("%w: absent", errAudienceKeyDeliveryAbsent)
	}); !errors.Is(err, errAudienceKeyDeliveryAbsent) {
		t.Fatalf("stable failure = %v", err)
	}
	cache.invalidateFailures()
	if _, err := cache.get(context.Background(), successKey, func(context.Context) ([]byte, error) {
		return nil, errors.New("successful key was invalidated")
	}); err != nil {
		t.Fatalf("retained success: %v", err)
	}
	var retryLoads atomic.Int32
	if _, err := cache.get(context.Background(), missingKey, func(context.Context) ([]byte, error) {
		retryLoads.Add(1)
		return []byte{4, 5, 6}, nil
	}); err != nil {
		t.Fatalf("invalidated absence retry: %v", err)
	}
	if retryLoads.Load() != 1 {
		t.Fatalf("invalidated absence loads = %d", retryLoads.Load())
	}

	for _, transient := range []error{context.Canceled, context.DeadlineExceeded, dwn.ErrRateLimited, dwn.ErrTransport} {
		key := audienceKeyCacheKey{protocol: "p", rolePath: "r", keyID: transient.Error()}
		var loads atomic.Int32
		for range 2 {
			if _, err := cache.get(context.Background(), key, func(context.Context) ([]byte, error) {
				loads.Add(1)
				return nil, errors.Join(fmt.Errorf("%w: absent", errAudienceKeyDeliveryAbsent), transient)
			}); !errors.Is(err, transient) {
				t.Fatalf("transient %v error = %v", transient, err)
			}
		}
		if loads.Load() != 2 {
			t.Fatalf("transient %v was cached; loads=%d", transient, loads.Load())
		}
	}
}

func TestRoleAudiencePrivateKeyCachesStableUnavailableUntilTTLAndInvalidation(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	client := newMaterializerTestClient()
	client.roleAudienceKeys.failureTTL = time.Minute
	client.roleAudienceKeys.now = func() time.Time { return now }
	info := &dwncrypto.RoleAudienceInfo{Protocol: "p", RolePath: "network/node", KeyID: "missing"}
	key := audienceKeyCacheKey{protocol: info.Protocol, rolePath: info.RolePath, keyID: info.KeyID}

	if _, err := client.roleAudiencePrivateKey(context.Background(), info); !errors.Is(err, errAudienceKeyDeliveryAbsent) {
		t.Fatalf("first stable miss = %v", err)
	}
	client.roleAudienceKeys.mu.Lock()
	firstExpiry := client.roleAudienceKeys.failures[key].expiresAt
	client.roleAudienceKeys.mu.Unlock()
	now = now.Add(30 * time.Second)
	if _, err := client.roleAudiencePrivateKey(context.Background(), info); !errors.Is(err, errAudienceKeyDeliveryAbsent) {
		t.Fatalf("cached stable miss = %v", err)
	}
	client.roleAudienceKeys.mu.Lock()
	cachedExpiry := client.roleAudienceKeys.failures[key].expiresAt
	client.roleAudienceKeys.mu.Unlock()
	if !cachedExpiry.Equal(firstExpiry) {
		t.Fatalf("cached miss re-ran routes: expiry %v -> %v", firstExpiry, cachedExpiry)
	}

	now = firstExpiry
	if _, err := client.roleAudiencePrivateKey(context.Background(), info); !errors.Is(err, errAudienceKeyDeliveryAbsent) {
		t.Fatalf("expired stable miss = %v", err)
	}
	client.roleAudienceKeys.mu.Lock()
	expiredRetry := client.roleAudienceKeys.failures[key].expiresAt
	client.roleAudienceKeys.mu.Unlock()
	if !expiredRetry.After(firstExpiry) {
		t.Fatalf("TTL expiry did not retry routes: %v <= %v", expiredRetry, firstExpiry)
	}

	client.roleAudienceKeys.invalidateFailures()
	now = now.Add(time.Second)
	if _, err := client.roleAudiencePrivateKey(context.Background(), info); !errors.Is(err, errAudienceKeyDeliveryAbsent) {
		t.Fatalf("invalidated stable miss = %v", err)
	}
	client.roleAudienceKeys.mu.Lock()
	invalidatedRetry := client.roleAudienceKeys.failures[key].expiresAt
	client.roleAudienceKeys.mu.Unlock()
	if !invalidatedRetry.After(expiredRetry) {
		t.Fatalf("invalidation did not retry routes: %v <= %v", invalidatedRetry, expiredRetry)
	}
}

func TestAudienceKeyCacheCoalescesConcurrentLookup(t *testing.T) {
	var cache audienceKeyCache
	key := audienceKeyCacheKey{protocol: "p", rolePath: "r", keyID: "k"}
	wantKey := []byte{11, 12, 13}

	const callers = 32
	start := make(chan struct{})
	loadStarted := make(chan struct{})
	releaseLoad := make(chan struct{})
	var startOnce sync.Once
	var loads atomic.Int32
	results := make(chan error, callers)

	loader := func(context.Context) ([]byte, error) {
		loads.Add(1)
		startOnce.Do(func() { close(loadStarted) })
		<-releaseLoad
		return append([]byte(nil), wantKey...), nil
	}

	var ready sync.WaitGroup
	ready.Add(callers)
	for range callers {
		go func() {
			ready.Done()
			<-start
			got, err := cache.get(context.Background(), key, loader)
			if err == nil && !bytes.Equal(got, wantKey) {
				err = fmt.Errorf("key = %v, want %v", got, wantKey)
			}
			results <- err
		}()
	}

	ready.Wait()
	close(start)
	select {
	case <-loadStarted:
	case <-time.After(time.Second):
		t.Fatal("loader did not start")
	}

	// Keep the one loader blocked long enough for the remaining callers to
	// observe its in-flight promise rather than a populated cache entry.
	time.Sleep(25 * time.Millisecond)
	close(releaseLoad)

	for range callers {
		select {
		case err := <-results:
			if err != nil {
				t.Errorf("concurrent get: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("concurrent get did not finish")
		}
	}
	if got := loads.Load(); got != 1 {
		t.Fatalf("loader calls = %d, want 1", got)
	}
}

func TestAudienceKeyCacheScopesEntriesByFullTuple(t *testing.T) {
	var cache audienceKeyCache
	keys := []audienceKeyCacheKey{
		{protocol: "p1", rolePath: "r1", keyID: "k1"},
		{protocol: "p2", rolePath: "r1", keyID: "k1"},
		{protocol: "p1", rolePath: "r2", keyID: "k1"},
		{protocol: "p1", rolePath: "r1", keyID: "k2"},
	}

	var loads atomic.Int32
	for i, key := range keys {
		want := []byte{byte(i + 1)}
		got, err := cache.get(context.Background(), key, func(context.Context) ([]byte, error) {
			loads.Add(1)
			return append([]byte(nil), want...), nil
		})
		if err != nil {
			t.Fatalf("get tuple %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("tuple %d key = %v, want %v", i, got, want)
		}
	}

	for i, key := range keys {
		want := []byte{byte(i + 1)}
		got, err := cache.get(context.Background(), key, func(context.Context) ([]byte, error) {
			return nil, errors.New("cached tuple unexpectedly called loader")
		})
		if err != nil {
			t.Fatalf("cached get tuple %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("cached tuple %d key = %v, want %v", i, got, want)
		}
	}
	if got, want := loads.Load(), int32(len(keys)); got != want {
		t.Fatalf("loader calls = %d, want %d", got, want)
	}
}

func TestAudienceKeyCacheCanceledWaiterDoesNotCancelLeader(t *testing.T) {
	var cache audienceKeyCache
	key := audienceKeyCacheKey{protocol: "p", rolePath: "r", keyID: "k"}
	wantKey := []byte{21, 22, 23}

	loadStarted := make(chan struct{})
	releaseLoad := make(chan struct{})
	leaderResult := make(chan error, 1)
	go func() {
		got, err := cache.get(context.Background(), key, func(context.Context) ([]byte, error) {
			close(loadStarted)
			<-releaseLoad
			return append([]byte(nil), wantKey...), nil
		})
		if err == nil && !bytes.Equal(got, wantKey) {
			err = fmt.Errorf("leader key = %v, want %v", got, wantKey)
		}
		leaderResult <- err
	}()

	select {
	case <-loadStarted:
	case <-time.After(time.Second):
		t.Fatal("leader loader did not start")
	}

	waiterCtx, cancelWaiter := context.WithCancel(context.Background())
	waiterResult := make(chan error, 1)
	var waiterLoads atomic.Int32
	go func() {
		_, err := cache.get(waiterCtx, key, func(context.Context) ([]byte, error) {
			waiterLoads.Add(1)
			return nil, errors.New("waiter unexpectedly became loader")
		})
		waiterResult <- err
	}()
	cancelWaiter()

	select {
	case err := <-waiterResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("waiter error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled waiter did not return")
	}
	if got := waiterLoads.Load(); got != 0 {
		t.Fatalf("waiter loader calls = %d, want 0", got)
	}

	close(releaseLoad)
	select {
	case err := <-leaderResult:
		if err != nil {
			t.Fatalf("leader get: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("leader did not finish")
	}

	got, err := cache.get(context.Background(), key, func(context.Context) ([]byte, error) {
		return nil, errors.New("completed leader did not populate cache")
	})
	if err != nil {
		t.Fatalf("cached get after canceled waiter: %v", err)
	}
	if !bytes.Equal(got, wantKey) {
		t.Fatalf("cached key = %v, want %v", got, wantKey)
	}
}

func TestAudienceKeyCacheCanceledLeaderAllowsLiveWaitersToRetry(t *testing.T) {
	var cache audienceKeyCache
	key := audienceKeyCacheKey{protocol: "p", rolePath: "r", keyID: "k"}
	wantKey := []byte{31, 32, 33}

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderStarted := make(chan struct{})
	leaderResult := make(chan error, 1)
	go func() {
		_, err := cache.get(leaderCtx, key, func(ctx context.Context) ([]byte, error) {
			close(leaderStarted)
			<-ctx.Done()
			return nil, ctx.Err()
		})
		leaderResult <- err
	}()

	select {
	case <-leaderStarted:
	case <-time.After(time.Second):
		t.Fatal("leader loader did not start")
	}

	const waiters = 16
	startWaiters := make(chan struct{})
	results := make(chan error, waiters)
	var retryLoads atomic.Int32
	for range waiters {
		go func() {
			<-startWaiters
			got, err := cache.get(context.Background(), key, func(context.Context) ([]byte, error) {
				retryLoads.Add(1)
				return append([]byte(nil), wantKey...), nil
			})
			if err == nil && !bytes.Equal(got, wantKey) {
				err = fmt.Errorf("key = %v, want %v", got, wantKey)
			}
			results <- err
		}()
	}
	close(startWaiters)
	time.Sleep(25 * time.Millisecond)
	cancelLeader()

	select {
	case err := <-leaderResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("leader error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled leader did not return")
	}

	for range waiters {
		select {
		case err := <-results:
			if err != nil {
				t.Errorf("live waiter: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("live waiter did not finish")
		}
	}
	if got := retryLoads.Load(); got != 1 {
		t.Fatalf("retry loader calls = %d, want 1", got)
	}
}
