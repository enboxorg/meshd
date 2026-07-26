package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/enboxorg/meshd/internal/dwn"
)

func TestFeedSyncStateRoundTrip(t *testing.T) {
	dir := t.TempDir()

	saved := &FeedSyncState{
		LinkKey: "did:dht:owner^https://dwn.example^proj^epoch",
		Cursor: &dwn.ProgressToken{
			StreamID:   "aabbccddeeff0011",
			Epoch:      "epoch-1",
			Position:   "42",
			MessageCID: "bafyreib",
		},
		Fingerprint: "0f" + "00",
	}
	if err := SaveFeedSyncState(dir, saved); err != nil {
		t.Fatalf("SaveFeedSyncState: %v", err)
	}
	if saved.Version != FeedSyncStateVersion {
		t.Fatalf("saved version = %d, want %d", saved.Version, FeedSyncStateVersion)
	}
	if saved.UpdatedAt == "" {
		t.Fatal("saved UpdatedAt is empty")
	}

	loaded, err := LoadFeedSyncState(dir)
	if err != nil {
		t.Fatalf("LoadFeedSyncState: %v", err)
	}
	if loaded == nil {
		t.Fatal("loaded state is nil")
	}
	if loaded.LinkKey != saved.LinkKey || loaded.Fingerprint != saved.Fingerprint {
		t.Fatalf("loaded = %+v, want link key %q fingerprint %q", loaded, saved.LinkKey, saved.Fingerprint)
	}
	if loaded.Cursor == nil || *loaded.Cursor != *saved.Cursor {
		t.Fatalf("loaded cursor = %+v, want %+v", loaded.Cursor, saved.Cursor)
	}

	// A cleared cursor persists as an absent field.
	saved.Cursor = nil
	if err := SaveFeedSyncState(dir, saved); err != nil {
		t.Fatalf("SaveFeedSyncState without cursor: %v", err)
	}
	loaded, err = LoadFeedSyncState(dir)
	if err != nil {
		t.Fatalf("LoadFeedSyncState: %v", err)
	}
	if loaded.Cursor != nil {
		t.Fatalf("loaded cursor = %+v, want nil", loaded.Cursor)
	}
}

func TestLoadFeedSyncStateMissing(t *testing.T) {
	loaded, err := LoadFeedSyncState(t.TempDir())
	if err != nil {
		t.Fatalf("LoadFeedSyncState: %v", err)
	}
	if loaded != nil {
		t.Fatalf("loaded = %+v, want nil for a missing file", loaded)
	}
}

func TestLoadFeedSyncStateDiscardsIncompatibleVersion(t *testing.T) {
	dir := t.TempDir()
	data, err := json.Marshal(FeedSyncState{Version: FeedSyncStateVersion + 1, LinkKey: "link"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, feedSyncFile), data, 0600); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadFeedSyncState(dir)
	if err != nil {
		t.Fatalf("LoadFeedSyncState: %v", err)
	}
	if loaded != nil {
		t.Fatalf("loaded = %+v, want nil for an incompatible version", loaded)
	}
}

func TestLoadFeedSyncStateCorruptFileErrors(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, feedSyncFile), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFeedSyncState(dir); err == nil {
		t.Fatal("LoadFeedSyncState succeeded on corrupt JSON")
	}
}

func TestSaveFeedSyncStateRequiresLinkKey(t *testing.T) {
	if err := SaveFeedSyncState(t.TempDir(), &FeedSyncState{}); err == nil {
		t.Fatal("SaveFeedSyncState accepted an empty link key")
	}
	if err := SaveFeedSyncState(t.TempDir(), nil); err == nil {
		t.Fatal("SaveFeedSyncState accepted nil state")
	}
}

func TestClearFeedSyncState(t *testing.T) {
	dir := t.TempDir()
	if err := ClearFeedSyncState(dir); err != nil {
		t.Fatalf("ClearFeedSyncState on missing file: %v", err)
	}
	if err := SaveFeedSyncState(dir, &FeedSyncState{LinkKey: "link"}); err != nil {
		t.Fatal(err)
	}
	if err := ClearFeedSyncState(dir); err != nil {
		t.Fatalf("ClearFeedSyncState: %v", err)
	}
	loaded, err := LoadFeedSyncState(dir)
	if err != nil || loaded != nil {
		t.Fatalf("after clear: loaded=%+v err=%v, want nil/nil", loaded, err)
	}
}
