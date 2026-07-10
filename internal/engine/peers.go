package engine

import (
	"strings"
	"time"

	"github.com/enboxorg/meshnet/tailcfg"
	"github.com/enboxorg/meshnet/types/netmap"
)

// PeerSnapshot is the tray- and status-facing view of a peer in the latest
// network map. MeshIP is the first valid address assigned directly to the
// peer. LastSeen is nil when the control plane has never observed the peer.
type PeerSnapshot struct {
	Name     string
	MeshIP   string
	Online   bool
	LastSeen *time.Time
}

// PeerSnapshots returns peers from the latest network map received by the
// engine. It returns nil until a network map is available.
func (e *Engine) PeerSnapshots() []PeerSnapshot {
	if e == nil || e.backend == nil {
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
