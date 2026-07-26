package engine

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/enboxorg/meshd/internal/dwn"
	"github.com/enboxorg/meshd/internal/state"
)

const testFeedLinkKey = "did:dht:owner^https://dwn.example^proj^epoch"

type feedSaveRecorder struct {
	mu    sync.Mutex
	saves []state.FeedSyncState
	err   error
}

func (r *feedSaveRecorder) save(fs state.FeedSyncState) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	r.saves = append(r.saves, fs)
	return nil
}

func (r *feedSaveRecorder) takeSaves() []state.FeedSyncState {
	r.mu.Lock()
	defer r.mu.Unlock()
	saves := append([]state.FeedSyncState(nil), r.saves...)
	r.saves = nil
	return saves
}

func testCursor(position string) *dwn.ProgressToken {
	return &dwn.ProgressToken{StreamID: "aabbccddeeff0011", Epoch: "epoch-1", Position: position}
}

func TestFeedSyncRecorderAdoptRequiresMatchingLinkKey(t *testing.T) {
	tests := []struct {
		name   string
		loaded *state.FeedSyncState
		want   *dwn.ProgressToken
	}{
		{name: "nil state", loaded: nil, want: nil},
		{
			name:   "matching link key adopts cursor",
			loaded: &state.FeedSyncState{LinkKey: testFeedLinkKey, Cursor: testCursor("7"), Fingerprint: "aa"},
			want:   testCursor("7"),
		},
		{
			name:   "link key mismatch discards cursor",
			loaded: &state.FeedSyncState{LinkKey: "other^link^key^x", Cursor: testCursor("7")},
			want:   nil,
		},
		{
			name:   "invalid cursor discarded",
			loaded: &state.FeedSyncState{LinkKey: testFeedLinkKey, Cursor: &dwn.ProgressToken{Position: "7"}},
			want:   nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := newFeedSyncRecorder(testFeedLinkKey, nil, nil)
			r.adopt(test.loaded)
			got := r.resumeCursor()
			switch {
			case test.want == nil && got != nil:
				t.Fatalf("resume cursor = %+v, want nil", got)
			case test.want != nil && (got == nil || *got != *test.want):
				t.Fatalf("resume cursor = %+v, want %+v", got, test.want)
			}
		})
	}

	t.Run("matching link key adopts fingerprint", func(t *testing.T) {
		r := newFeedSyncRecorder(testFeedLinkKey, nil, nil)
		r.adopt(&state.FeedSyncState{LinkKey: testFeedLinkKey, Fingerprint: "ff00"})
		if got := r.storedFingerprint(); got != "ff00" {
			t.Fatalf("stored fingerprint = %q, want ff00", got)
		}
	})
	t.Run("mismatched link key discards fingerprint", func(t *testing.T) {
		r := newFeedSyncRecorder(testFeedLinkKey, nil, nil)
		r.adopt(&state.FeedSyncState{LinkKey: "different", Fingerprint: "ff00"})
		if got := r.storedFingerprint(); got != "" {
			t.Fatalf("stored fingerprint = %q, want empty", got)
		}
	})
}

func TestFeedSyncRecorderDebouncesCursorPersists(t *testing.T) {
	saves := &feedSaveRecorder{}
	r := newFeedSyncRecorder(testFeedLinkKey, saves.save, nil)
	r.debounce = 20 * time.Millisecond

	r.recordCursor(testCursor("1"))
	r.recordCursor(testCursor("2"))
	r.recordCursor(testCursor("3"))
	if got := saves.takeSaves(); len(got) != 0 {
		t.Fatalf("saves before debounce = %d, want 0", len(got))
	}

	deadline := time.Now().Add(2 * time.Second)
	var persisted []state.FeedSyncState
	for len(persisted) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("debounced persist never ran")
		}
		time.Sleep(5 * time.Millisecond)
		persisted = saves.takeSaves()
	}
	if len(persisted) != 1 {
		t.Fatalf("saves = %d, want one coalesced persist", len(persisted))
	}
	got := persisted[0]
	if got.LinkKey != testFeedLinkKey || got.Cursor == nil || got.Cursor.Position != "3" {
		t.Fatalf("persisted = %+v, want latest cursor position 3", got)
	}
}

func TestFeedSyncRecorderFlushAndClearPersistImmediately(t *testing.T) {
	saves := &feedSaveRecorder{}
	r := newFeedSyncRecorder(testFeedLinkKey, saves.save, nil)
	r.debounce = time.Hour // debounced persists must not fire in this test

	r.recordCursor(testCursor("1")) // pending, not yet persisted
	r.flushCursor(testCursor("2"))
	flushed := saves.takeSaves()
	if len(flushed) != 1 || flushed[0].Cursor == nil || flushed[0].Cursor.Position != "2" {
		t.Fatalf("flush saves = %+v, want one save at position 2", flushed)
	}

	r.recordFingerprint("ff00")
	withFingerprint := saves.takeSaves()
	if len(withFingerprint) != 1 || withFingerprint[0].Fingerprint != "ff00" {
		t.Fatalf("fingerprint saves = %+v, want one save with ff00", withFingerprint)
	}
	if withFingerprint[0].Cursor == nil || withFingerprint[0].Cursor.Position != "2" {
		t.Fatalf("fingerprint save cursor = %+v, want retained position 2", withFingerprint[0].Cursor)
	}

	// A progress gap clears the cursor but keeps the fingerprint: it
	// describes feed contents, not log positions.
	r.clearCursor()
	cleared := saves.takeSaves()
	if len(cleared) != 1 || cleared[0].Cursor != nil || cleared[0].Fingerprint != "ff00" {
		t.Fatalf("clear saves = %+v, want nil cursor and retained fingerprint", cleared)
	}
	if r.resumeCursor() != nil {
		t.Fatal("resume cursor survived clearCursor")
	}
}

func TestFeedSyncRecorderCloseFlushesPendingCursor(t *testing.T) {
	saves := &feedSaveRecorder{}
	r := newFeedSyncRecorder(testFeedLinkKey, saves.save, nil)
	r.debounce = time.Hour

	r.recordCursor(testCursor("9"))
	r.close()
	got := saves.takeSaves()
	if len(got) != 1 || got[0].Cursor == nil || got[0].Cursor.Position != "9" {
		t.Fatalf("close saves = %+v, want pending cursor flushed", got)
	}

	// Closed recorders ignore further mutations.
	r.recordCursor(testCursor("10"))
	r.recordFingerprint("aa")
	if got := saves.takeSaves(); len(got) != 0 {
		t.Fatalf("saves after close = %+v, want none", got)
	}
}

func TestFeedSyncRecorderSurvivesSaveErrors(t *testing.T) {
	saves := &feedSaveRecorder{err: errors.New("disk full")}
	r := newFeedSyncRecorder(testFeedLinkKey, saves.save, nil)
	r.flushCursor(testCursor("1"))
	r.recordFingerprint("aa")

	saves.mu.Lock()
	saves.err = nil
	saves.mu.Unlock()
	r.recordFingerprint("bb")
	got := saves.takeSaves()
	if len(got) != 1 || got[0].Fingerprint != "bb" || got[0].Cursor == nil {
		t.Fatalf("saves after recovery = %+v, want cursor+fingerprint", got)
	}
}

func TestFeedModeEnabled(t *testing.T) {
	grants := []dwn.SyncAuthorizationGrant{{
		ID:          "grant-feed",
		DateGranted: "2026-07-01T00:00:00.000000Z",
		DateExpires: "2026-08-01T00:00:00.000000Z",
	}}
	tests := []struct {
		name string
		cfg  Config
		want bool
	}{
		{
			name: "owner signer equals anchor tenant",
			cfg: Config{
				AnchorTenant: "did:dht:owner",
				SelfDID:      "did:dht:owner",
				Signer:       &dwn.Signer{DID: "did:dht:owner"},
			},
			want: true,
		},
		{
			name: "delegate with feed grants",
			cfg: Config{
				AnchorTenant: "did:dht:owner",
				SelfDID:      "did:jwk:node",
				Signer:       &dwn.Signer{DID: "did:jwk:delegate"},
				FeedGrantIDs: []string{"grant-feed"},
				FeedGrants:   grants,
			},
			want: true,
		},
		{
			name: "role-only node keeps records streams",
			cfg: Config{
				AnchorTenant: "did:dht:owner",
				SelfDID:      "did:jwk:node",
				Signer:       &dwn.Signer{DID: "did:jwk:node"},
			},
			want: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := feedModeEnabled(test.cfg); got != test.want {
				t.Fatalf("feedModeEnabled = %v, want %v", got, test.want)
			}
		})
	}
}

func TestFeedLinkKey(t *testing.T) {
	ownerCfg := Config{
		AnchorEndpoint: "https://dwn.example",
		AnchorTenant:   "did:dht:owner",
		Signer:         &dwn.Signer{DID: "did:dht:owner"},
	}
	ownerKey, err := feedLinkKey(ownerCfg)
	if err != nil {
		t.Fatalf("owner feedLinkKey: %v", err)
	}

	grants := []dwn.SyncAuthorizationGrant{{
		ID:          "grant-feed",
		DateGranted: "2026-07-01T00:00:00.000000Z",
		DateExpires: "2026-08-01T00:00:00.000000Z",
	}}
	delegateCfg := Config{
		AnchorEndpoint: "https://dwn.example",
		AnchorTenant:   "did:dht:owner",
		Signer:         &dwn.Signer{DID: "did:jwk:delegate"},
		FeedGrantIDs:   []string{"grant-feed"},
		FeedGrants:     grants,
	}
	delegateKey, err := feedLinkKey(delegateCfg)
	if err != nil {
		t.Fatalf("delegate feedLinkKey: %v", err)
	}
	if ownerKey == delegateKey {
		t.Fatal("owner and delegate link keys must differ (different authorization epochs)")
	}

	// Deterministic: same inputs, same key.
	again, err := feedLinkKey(delegateCfg)
	if err != nil {
		t.Fatal(err)
	}
	if again != delegateKey {
		t.Fatalf("link key not deterministic: %q vs %q", again, delegateKey)
	}

	// Grant churn (different expiry) changes the epoch and the link key.
	churned := delegateCfg
	churned.FeedGrants = []dwn.SyncAuthorizationGrant{{
		ID:          "grant-feed",
		DateGranted: "2026-07-01T00:00:00.000000Z",
		DateExpires: "2026-09-01T00:00:00.000000Z",
	}}
	churnedKey, err := feedLinkKey(churned)
	if err != nil {
		t.Fatal(err)
	}
	if churnedKey == delegateKey {
		t.Fatal("grant churn must change the link key")
	}

	// Delegate mode without grant tuples is a wiring error.
	broken := delegateCfg
	broken.FeedGrants = nil
	if _, err := feedLinkKey(broken); err == nil {
		t.Fatal("feedLinkKey accepted delegate config without grant tuples")
	}
}
