package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enboxorg/meshd/internal/daemon"
	"github.com/enboxorg/meshd/internal/did"
	"github.com/enboxorg/meshd/internal/engine"
	"github.com/enboxorg/meshd/internal/state"
)

func TestPeerListRowsFromDaemonStatus(t *testing.T) {
	refreshedAt := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
	ns := &state.NetworkState{
		NetworkRecordID: "network-1",
		NetworkName:     "home",
		MeshCIDR:        "10.200.0.0/16",
		NodeDID:         "did:jwk:self",
		OwnerDID:        "did:jwk:wallet",
	}
	status := &daemon.Status{
		Running:         true,
		NetworkRecordID: "network-1",
		OwnerDID:        "did:jwk:wallet",
		Snapshot: &daemon.SnapshotStatus{
			Generation:  7,
			RefreshedAt: refreshedAt,
			LastError:   "remote refresh timed out",
		},
		Self: &daemon.PeerStatus{
			NodeDID:        "did:jwk:self",
			OwnerDID:       "did:jwk:wallet",
			MemberRecordID: "member-self",
			Name:           "laptop-host",
			Label:          "macbook",
			MeshIP:         "10.200.0.5",
			ExpiresAt:      "2026-08-01T00:00:00Z",
			Online:         true,
		},
		Peers: []daemon.PeerStatus{
			{
				NodeDID:   "did:jwk:peer",
				OwnerDID:  "did:jwk:peer-owner",
				Name:      "server-host",
				Label:     "server",
				MeshIP:    "10.200.0.8",
				ExpiresAt: "2026-08-02T00:00:00Z",
			},
			// Defensive duplicate suppression keeps self first even if a
			// transitional daemon accidentally includes it in Peers.
			{NodeDID: "did:jwk:self", MeshIP: "10.200.0.99"},
		},
	}

	rows, warning, ok := peerListRowsFromDaemonStatus(ns, status)
	if !ok {
		t.Fatal("peerListRowsFromDaemonStatus rejected ready matching snapshot")
	}
	want := []peerListRow{
		{
			NodeDID: "did:jwk:self",
			MeshIP:  "10.200.0.5",
			Device:  "this device",
			Owner:   "did:jwk:wallet",
			Label:   "macbook",
			Expires: "2026-08-01T00:00:00Z",
			Path:    "network/member/node",
		},
		{
			NodeDID: "did:jwk:peer",
			MeshIP:  "10.200.0.8",
			Device:  "peer",
			Owner:   "did:jwk:peer-owner",
			Label:   "server",
			Expires: "2026-08-02T00:00:00Z",
			Path:    "network/node",
		},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("rows = %#v, want %#v", rows, want)
	}
	if !strings.Contains(warning, refreshedAt) || !strings.Contains(warning, "remote refresh timed out") {
		t.Fatalf("warning = %q, want last-good timestamp and refresh error", warning)
	}
}

func TestPeerListRowsFromDaemonStatusRejectsUntrustedOrUnreadySnapshot(t *testing.T) {
	readyStatus := func() *daemon.Status {
		return &daemon.Status{
			Running:         true,
			NetworkRecordID: "network-1",
			Self:            &daemon.PeerStatus{NodeDID: "did:jwk:self", MeshIP: "10.200.0.5"},
			Snapshot: &daemon.SnapshotStatus{
				Generation:  1,
				RefreshedAt: "2026-07-11T12:00:00.123456789Z",
			},
		}
	}
	readyState := func() *state.NetworkState {
		return &state.NetworkState{
			NetworkRecordID: "network-1",
			MeshCIDR:        "10.200.0.0/16",
			NodeDID:         "did:jwk:self",
		}
	}

	tests := []struct {
		name   string
		mutate func(*state.NetworkState, *daemon.Status) (*state.NetworkState, *daemon.Status)
	}{
		{
			name: "absent daemon status",
			mutate: func(ns *state.NetworkState, _ *daemon.Status) (*state.NetworkState, *daemon.Status) {
				return ns, nil
			},
		},
		{
			name: "old daemon response",
			mutate: func(ns *state.NetworkState, status *daemon.Status) (*state.NetworkState, *daemon.Status) {
				status.Self = nil
				status.Snapshot = nil
				return ns, status
			},
		},
		{
			name: "legacy state without node DID",
			mutate: func(ns *state.NetworkState, status *daemon.Status) (*state.NetworkState, *daemon.Status) {
				ns.NodeDID = ""
				return ns, status
			},
		},
		{
			name: "network mismatch",
			mutate: func(ns *state.NetworkState, status *daemon.Status) (*state.NetworkState, *daemon.Status) {
				status.NetworkRecordID = "other-network"
				return ns, status
			},
		},
		{
			name: "self mismatch",
			mutate: func(ns *state.NetworkState, status *daemon.Status) (*state.NetworkState, *daemon.Status) {
				status.Self.NodeDID = "did:jwk:other-profile"
				return ns, status
			},
		},
		{
			name: "zero generation",
			mutate: func(ns *state.NetworkState, status *daemon.Status) (*state.NetworkState, *daemon.Status) {
				status.Snapshot.Generation = 0
				return ns, status
			},
		},
		{
			name: "missing refresh time",
			mutate: func(ns *state.NetworkState, status *daemon.Status) (*state.NetworkState, *daemon.Status) {
				status.Snapshot.RefreshedAt = ""
				return ns, status
			},
		},
		{
			name: "malformed refresh time",
			mutate: func(ns *state.NetworkState, status *daemon.Status) (*state.NetworkState, *daemon.Status) {
				status.Snapshot.RefreshedAt = "not-a-time"
				return ns, status
			},
		},
		{
			name: "not running",
			mutate: func(ns *state.NetworkState, status *daemon.Status) (*state.NetworkState, *daemon.Status) {
				status.Running = false
				return ns, status
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ns, status := tc.mutate(readyState(), readyStatus())
			if rows, warning, ok := peerListRowsFromDaemonStatus(ns, status); ok || rows != nil || warning != "" {
				t.Fatalf("result = (%+v, %q, %v), want remote fallback", rows, warning, ok)
			}
		})
	}
}

func TestDaemonStatusesFromMeshSnapshot(t *testing.T) {
	refreshedAt := time.Date(2026, 7, 11, 12, 0, 0, 123456789, time.FixedZone("offset", -7*60*60))
	lastAttemptAt := refreshedAt.Add(2 * time.Minute)
	lastSeen := refreshedAt.Add(-time.Minute)
	snapshot := &engine.MeshSnapshot{
		Generation:    9,
		RefreshedAt:   refreshedAt,
		LastAttemptAt: lastAttemptAt,
		LastError:     "latest refresh failed",
		Self: &engine.PeerSnapshot{
			NodeDID:        "did:jwk:self",
			Name:           "laptop-host",
			MeshIP:         "10.200.0.5",
			OwnerDID:       "did:jwk:wallet",
			MemberRecordID: "member-self",
			Label:          "laptop",
			ExpiresAt:      "2026-08-01T00:00:00Z",
			Online:         true,
			LastSeen:       &lastSeen,
		},
		Peers: []engine.PeerSnapshot{{
			NodeDID:   "did:jwk:peer",
			Name:      "server-host",
			MeshIP:    "10.200.0.8",
			OwnerDID:  "did:jwk:peer-owner",
			Label:     "server",
			ExpiresAt: "2026-08-02T00:00:00Z",
		}},
	}

	self, peers, freshness := daemonStatusesFromMeshSnapshot(snapshot)
	if self == nil {
		t.Fatal("self status = nil")
	}
	if self.NodeDID != "did:jwk:self" || self.OwnerDID != "did:jwk:wallet" ||
		self.MemberRecordID != "member-self" || self.Label != "laptop" ||
		self.ExpiresAt != "2026-08-01T00:00:00Z" || !self.Online ||
		self.LastSeen != lastSeen.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("self status = %+v", self)
	}
	if len(peers) != 1 || peers[0].NodeDID != "did:jwk:peer" ||
		peers[0].OwnerDID != "did:jwk:peer-owner" || peers[0].Label != "server" {
		t.Fatalf("peer statuses = %+v", peers)
	}
	if freshness == nil || freshness.Generation != 9 ||
		freshness.RefreshedAt != refreshedAt.UTC().Format(time.RFC3339Nano) ||
		freshness.LastAttemptAt != lastAttemptAt.UTC().Format(time.RFC3339Nano) ||
		freshness.LastError != "latest refresh failed" {
		t.Fatalf("freshness = %+v", freshness)
	}

	if self, peers, freshness := daemonStatusesFromMeshSnapshot(nil); self != nil || peers != nil || freshness != nil {
		t.Fatalf("nil snapshot = (%+v, %+v, %+v), want nils", self, peers, freshness)
	}
}

func TestCmdPeerListUsesDaemonSnapshotBeforeIdentity(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv("MESHD_STATE_DIR", stateDir)
	ns := &state.NetworkState{
		NetworkRecordID: "network-1",
		NetworkName:     "home",
		MeshCIDR:        "10.200.0.0/16",
		NodeDID:         "did:jwk:self",
		OwnerDID:        "did:jwk:wallet",
	}
	if err := state.SaveNetworkState(stateDir, ns); err != nil {
		t.Fatalf("SaveNetworkState: %v", err)
	}

	var identityLoads atomic.Int32
	var statusLoads atomic.Int32
	output, err := captureStdout(t, func() error {
		return cmdPeerListWithDependencies(context.Background(), nil, "", peerListCommandDependencies{
			loadIdentity: func(string) (*did.DID, error) {
				identityLoads.Add(1)
				return nil, errors.New("identity must not be loaded")
			},
			loadDaemonStatus: func(context.Context, string) (*daemon.Status, error) {
				statusLoads.Add(1)
				return &daemon.Status{
					Running:         true,
					NetworkRecordID: "network-1",
					Self: &daemon.PeerStatus{
						NodeDID:  "did:jwk:self",
						OwnerDID: "did:jwk:wallet",
						Label:    "laptop",
						MeshIP:   "10.200.0.5",
					},
					Peers: []daemon.PeerStatus{{
						NodeDID: "did:jwk:peer",
						Label:   "server",
						MeshIP:  "10.200.0.8",
					}},
					Snapshot: &daemon.SnapshotStatus{
						Generation:  1,
						RefreshedAt: time.Now().UTC().Format(time.RFC3339Nano),
					},
				}, nil
			},
		})
	})
	if err != nil {
		t.Fatalf("cmdPeerListWithDependencies: %v", err)
	}
	if got := identityLoads.Load(); got != 0 {
		t.Fatalf("identity loads = %d, want zero", got)
	}
	if got := statusLoads.Load(); got != 1 {
		t.Fatalf("daemon status loads = %d, want one", got)
	}
	for _, want := range []string{"Peers in \"home\"", "did:jwk:self", "this device", "did:jwk:peer", "server"} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}

func TestCmdPeerListFallsBackToIdentityForMismatchedSnapshot(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv("MESHD_STATE_DIR", stateDir)
	if err := state.SaveNetworkState(stateDir, &state.NetworkState{
		NetworkRecordID: "network-1",
		NetworkName:     "home",
		NodeDID:         "did:jwk:self",
	}); err != nil {
		t.Fatalf("SaveNetworkState: %v", err)
	}

	wantErr := errors.New("identity fallback reached")
	var identityLoads atomic.Int32
	err := cmdPeerListWithDependencies(context.Background(), nil, "", peerListCommandDependencies{
		loadIdentity: func(string) (*did.DID, error) {
			identityLoads.Add(1)
			return nil, wantErr
		},
		loadDaemonStatus: func(context.Context, string) (*daemon.Status, error) {
			return &daemon.Status{
				Running:         true,
				NetworkRecordID: "other-network",
				Self:            &daemon.PeerStatus{NodeDID: "did:jwk:self"},
				Snapshot: &daemon.SnapshotStatus{
					Generation:  1,
					RefreshedAt: time.Now().UTC().Format(time.RFC3339Nano),
				},
			}, nil
		},
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("cmdPeerListWithDependencies error = %v, want identity fallback", err)
	}
	if got := identityLoads.Load(); got != 1 {
		t.Fatalf("identity loads = %d, want one", got)
	}
}
