package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/enboxorg/meshd/internal/dwn"
)

// FeedSyncStateVersion identifies the feedsync.json schema. Files written by
// an incompatible version are discarded on load.
const FeedSyncStateVersion = 1

const feedSyncFile = "feedsync.json"

// FeedSyncState is the persisted replication-feed checkpoint of the daemon's
// Messages feed subscription: the resume cursor plus the remote feed
// fingerprint recorded at the last successful full state load.
//
// LinkKey binds the checkpoint to one replication link identity
// (tenant^endpoint^projectionId^authorizationEpoch). Grant churn or an
// endpoint change produces a different link key, so a stale checkpoint is
// discarded instead of resumed against the wrong stream authorization.
type FeedSyncState struct {
	Version     int                `json:"version"`
	LinkKey     string             `json:"linkKey"`
	Cursor      *dwn.ProgressToken `json:"cursor,omitempty"`
	Fingerprint string             `json:"fingerprint,omitempty"`
	UpdatedAt   string             `json:"updatedAt,omitempty"`
}

// SaveFeedSyncState persists the feed checkpoint atomically, stamping Version
// and UpdatedAt.
func SaveFeedSyncState(stateDir string, fs *FeedSyncState) error {
	if fs == nil {
		return fmt.Errorf("feed sync state is required")
	}
	if fs.LinkKey == "" {
		return fmt.Errorf("feed sync state requires a link key")
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	fs.Version = FeedSyncStateVersion
	fs.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)

	data, err := json.MarshalIndent(fs, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	target := filepath.Join(stateDir, feedSyncFile)
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	// Same sudo TUN handoff rule as network.json: a root daemon must leave
	// the file readable by the profile owner's non-root CLI.
	alignOwnerToDir(stateDir, tmp)
	if err := os.Rename(tmp, target); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// LoadFeedSyncState loads the persisted feed checkpoint. It returns nil, nil
// when no checkpoint exists or the file was written by an incompatible
// version.
func LoadFeedSyncState(stateDir string) (*FeedSyncState, error) {
	data, err := os.ReadFile(filepath.Join(stateDir, feedSyncFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read: %w", err)
	}

	var fs FeedSyncState
	if err := json.Unmarshal(data, &fs); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	if fs.Version != FeedSyncStateVersion {
		return nil, nil
	}
	return &fs, nil
}

// ClearFeedSyncState removes the persisted feed checkpoint (for network
// leave). Missing files are not an error.
func ClearFeedSyncState(stateDir string) error {
	err := os.Remove(filepath.Join(stateDir, feedSyncFile))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
