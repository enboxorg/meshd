package engine

import (
	"strings"
	"time"

	"github.com/enboxorg/meshnet/tailcfg"
	"github.com/enboxorg/meshnet/types/netmap"
)

// PeerSnapshot is the tray- and status-facing view of a node in the latest
// successful control-plane snapshot. MeshIP is the node's assigned mesh
// address. LastSeen is nil when the control plane has never observed it.
type PeerSnapshot struct {
	NodeDID        string
	Name           string
	MeshIP         string
	OwnerDID       string
	MemberRecordID string
	Label          string
	ExpiresAt      string
	Online         bool
	LastSeen       *time.Time
}

// PeerSnapshots returns peers from the latest successful control-plane
// snapshot. Before the first materialized snapshot is available, it falls back
// to the latest network map for compatibility.
func (e *Engine) PeerSnapshots() []PeerSnapshot {
	if e == nil {
		return nil
	}
	if snapshot := e.MeshSnapshot(); snapshot != nil && snapshot.Generation > 0 {
		return snapshot.Peers
	}
	if e.backend == nil {
		return nil
	}
	return peerSnapshotsFromNetMap(e.backend.NetMap())
}

func peerSnapshotsFromNetMap(nm *netmap.NetworkMap) []PeerSnapshot {
	if nm == nil || len(nm.Peers) == 0 {
		return nil
	}

	peers := make([]PeerSnapshot, 0, len(nm.Peers))
	for _, peer := range nm.Peers {
		if !peer.Valid() {
			continue
		}

		snapshot := PeerSnapshot{
			Name:   peerSnapshotName(peer),
			Online: peer.Online().GetOr(false),
		}
		addresses := peer.Addresses()
		for i := 0; i < addresses.Len(); i++ {
			addr := addresses.At(i).Addr()
			if addr.IsValid() {
				snapshot.MeshIP = addr.String()
				break
			}
		}
		if lastSeen, ok := peer.LastSeen().GetOk(); ok {
			snapshot.LastSeen = &lastSeen
		}
		peers = append(peers, snapshot)
	}

	if len(peers) == 0 {
		return nil
	}
	return peers
}

func peerSnapshotName(peer tailcfg.NodeView) string {
	hostinfo := peer.Hostinfo()
	if hostinfo.Valid() && hostinfo.Hostname() != "" {
		return hostinfo.Hostname()
	}
	return strings.TrimSuffix(peer.Name(), ".")
}
