package engine

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/enboxorg/meshd/internal/control"
)

// MeshSnapshot is the daemon-facing, materialized view of the latest complete
// control-plane state. A failed refresh updates LastAttemptAt and LastError but
// preserves the last successful generation, RefreshedAt, Self, and Peers.
type MeshSnapshot struct {
	Generation    uint64
	RefreshedAt   time.Time
	LastAttemptAt time.Time
	LastError     string
	Self          *PeerSnapshot
	Peers         []PeerSnapshot
}

// meshSnapshotStore serializes publishers and atomically exposes immutable
// snapshots to readers. Values stored in current are never mutated.
type meshSnapshotStore struct {
	mu      sync.Mutex
	current atomic.Pointer[MeshSnapshot]
}

// MeshSnapshot returns a deep copy of the engine's current materialized view.
// It returns nil before the first refresh attempt.
func (e *Engine) MeshSnapshot() *MeshSnapshot {
	if e == nil || e.snapshots == nil {
		return nil
	}
	return e.snapshots.load()
}

func (s *meshSnapshotStore) load() *MeshSnapshot {
	if s == nil {
		return nil
	}
	return cloneMeshSnapshot(s.current.Load())
}

func (s *meshSnapshotStore) record(resp *control.MapResponse, err error) {
	if s == nil {
		return
	}
	now := time.Now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	previous := s.current.Load()
	if err != nil {
		next := cloneMeshSnapshot(previous)
		if next == nil {
			next = &MeshSnapshot{}
		}
		next.LastAttemptAt = now
		next.LastError = err.Error()
		s.current.Store(next)
		return
	}

	generation := uint64(1)
	if previous != nil {
		generation = previous.Generation + 1
	}
	s.current.Store(meshSnapshotFromMapResponse(resp, generation, now))
}

func meshSnapshotFromMapResponse(resp *control.MapResponse, generation uint64, refreshedAt time.Time) *MeshSnapshot {
	snapshot := &MeshSnapshot{
		Generation:    generation,
		RefreshedAt:   refreshedAt,
		LastAttemptAt: refreshedAt,
	}
	if resp == nil {
		return snapshot
	}
	if resp.Node != nil {
		self := peerSnapshotFromControlNode(resp.Node)
		snapshot.Self = &self
	}
	if len(resp.Peers) > 0 {
		snapshot.Peers = make([]PeerSnapshot, 0, len(resp.Peers))
		for _, peer := range resp.Peers {
			if peer == nil {
				continue
			}
			snapshot.Peers = append(snapshot.Peers, peerSnapshotFromControlNode(peer))
		}
		if len(snapshot.Peers) == 0 {
			snapshot.Peers = nil
		}
	}
	return snapshot
}

func peerSnapshotFromControlNode(node *control.Node) PeerSnapshot {
	snapshot := PeerSnapshot{
		NodeDID:        node.DID,
		Name:           node.Name,
		OwnerDID:       node.MemberDID,
		MemberRecordID: node.MemberRecordID,
		Label:          node.Label,
		ExpiresAt:      node.ExpiresAt,
		Online:         node.Online,
	}
	if node.MeshIP.IsValid() {
		snapshot.MeshIP = node.MeshIP.String()
	}
	if !node.LastSeen.IsZero() {
		lastSeen := node.LastSeen
		snapshot.LastSeen = &lastSeen
	}
	return snapshot
}

func cloneMeshSnapshot(snapshot *MeshSnapshot) *MeshSnapshot {
	if snapshot == nil {
		return nil
	}
	clone := *snapshot
	if snapshot.Self != nil {
		self := clonePeerSnapshot(*snapshot.Self)
		clone.Self = &self
	}
	if snapshot.Peers != nil {
		clone.Peers = make([]PeerSnapshot, len(snapshot.Peers))
		for i := range snapshot.Peers {
			clone.Peers[i] = clonePeerSnapshot(snapshot.Peers[i])
		}
	}
	return &clone
}

func clonePeerSnapshot(snapshot PeerSnapshot) PeerSnapshot {
	clone := snapshot
	if snapshot.LastSeen != nil {
		lastSeen := *snapshot.LastSeen
		clone.LastSeen = &lastSeen
	}
	return clone
}
