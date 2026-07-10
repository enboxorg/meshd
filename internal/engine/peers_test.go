package engine

import (
	"net/netip"
	"testing"
	"time"

	"github.com/enboxorg/meshnet/tailcfg"
	"github.com/enboxorg/meshnet/types/netmap"
)

func TestPeerSnapshotsFromNetMap(t *testing.T) {
	online := true
	lastSeen := time.Date(2026, 7, 10, 12, 30, 0, 0, time.UTC)
	nm := &netmap.NetworkMap{
		Peers: []tailcfg.NodeView{
			(&tailcfg.Node{
				Name:      "server.mesh.local.",
				Hostinfo:  (&tailcfg.Hostinfo{Hostname: "server"}).View(),
				Addresses: []netip.Prefix{netip.MustParsePrefix("10.200.0.8/32")},
				Online:    &online,
				LastSeen:  &lastSeen,
			}).View(),
			(&tailcfg.Node{
				Name:      "nas.mesh.local.",
				Addresses: []netip.Prefix{netip.MustParsePrefix("10.200.0.9/32")},
			}).View(),
			{},
		},
	}

	got := peerSnapshotsFromNetMap(nm)
	if len(got) != 2 {
		t.Fatalf("PeerSnapshots length = %d, want 2", len(got))
	}
	if got[0].Name != "server" || got[0].MeshIP != "10.200.0.8" || !got[0].Online {
		t.Fatalf("first peer = %+v", got[0])
	}
	if got[0].LastSeen == nil || !got[0].LastSeen.Equal(lastSeen) {
		t.Fatalf("first peer LastSeen = %v, want %v", got[0].LastSeen, lastSeen)
	}
	if got[1].Name != "nas.mesh.local" || got[1].MeshIP != "10.200.0.9" || got[1].Online {
		t.Fatalf("second peer = %+v", got[1])
	}
	if got[1].LastSeen != nil {
		t.Fatalf("second peer LastSeen = %v, want nil", got[1].LastSeen)
	}
}

func TestPeerSnapshotsFromNetMapEmpty(t *testing.T) {
	if got := peerSnapshotsFromNetMap(nil); got != nil {
		t.Fatalf("nil map snapshots = %v, want nil", got)
	}
	if got := peerSnapshotsFromNetMap(&netmap.NetworkMap{}); got != nil {
		t.Fatalf("empty map snapshots = %v, want nil", got)
	}
	if got := (*Engine)(nil).PeerSnapshots(); got != nil {
		t.Fatalf("nil engine snapshots = %v, want nil", got)
	}
}
