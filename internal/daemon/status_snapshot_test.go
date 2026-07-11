package daemon

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestStatusEndpointRichSnapshot(t *testing.T) {
	sock := testSocketPath(t)
	wantPeer := PeerStatus{
		Name:           "peer-a",
		MeshIP:         "10.200.0.2",
		Online:         true,
		NodeDID:        "did:example:peer-a",
		OwnerDID:       "did:example:peer-owner",
		MemberRecordID: "member-peer-a",
		Label:          "build-server",
		ExpiresAt:      "2026-07-18T02:34:11.140123456Z",
		LastSeen:       "2026-07-11T17:40:05.123456789Z",
	}
	wantSelf := PeerStatus{
		Name:           "this device",
		MeshIP:         "10.200.0.1",
		Online:         true,
		NodeDID:        "did:example:self",
		OwnerDID:       "did:example:self-owner",
		MemberRecordID: "member-self",
		Label:          "laptop",
		ExpiresAt:      "2026-07-18T02:34:11.140123456Z",
		LastSeen:       "2026-07-11T17:40:06.987654321Z",
	}
	wantSnapshot := SnapshotStatus{
		Generation:    42,
		RefreshedAt:   "2026-07-11T17:40:06.987654321Z",
		LastAttemptAt: "2026-07-11T17:40:07.123456789Z",
		LastError:     "refresh deferred by rate limit",
	}

	srv := NewServer(sock, func() Status {
		return Status{
			MeshIP:          wantSelf.MeshIP,
			Network:         "test-net",
			NetworkRecordID: "network-1",
			Peers:           []PeerStatus{wantPeer},
			Self:            &wantSelf,
			Snapshot:        &wantSnapshot,
		}
	}, nil)
	if err := srv.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer srv.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	status, err := NewClient(sock).GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus() error: %v", err)
	}

	if len(status.Peers) != 1 || status.Peers[0] != wantPeer {
		t.Fatalf("Peers = %+v, want %+v", status.Peers, []PeerStatus{wantPeer})
	}
	if status.Self == nil || *status.Self != wantSelf {
		t.Fatalf("Self = %+v, want %+v", status.Self, wantSelf)
	}
	if status.Snapshot == nil || *status.Snapshot != wantSnapshot {
		t.Fatalf("Snapshot = %+v, want %+v", status.Snapshot, wantSnapshot)
	}
}

func TestClientGetStatusLegacyResponse(t *testing.T) {
	sock := testSocketPath(t)
	listener, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("Listen() error: %v", err)
	}
	legacyJSON := []byte(`{
		"running": true,
		"meshIP": "10.200.0.1",
		"network": "test-net",
		"networkRecordID": "network-1",
		"peers": [{"name":"peer-a","meshIP":"10.200.0.2","online":true}],
		"routingRequired": false,
		"routingReady": false,
		"pid": 123
	}`)
	httpServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(legacyJSON)
	})}
	go func() {
		_ = httpServer.Serve(listener)
	}()
	defer httpServer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	status, err := NewClient(sock).GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus() legacy response error: %v", err)
	}
	if status.Self != nil || status.Snapshot != nil {
		t.Fatalf("legacy response additions = self %+v, snapshot %+v; want nil", status.Self, status.Snapshot)
	}
	wantPeer := PeerStatus{Name: "peer-a", MeshIP: "10.200.0.2", Online: true}
	if len(status.Peers) != 1 || status.Peers[0] != wantPeer {
		t.Fatalf("legacy Peers = %+v, want %+v", status.Peers, []PeerStatus{wantPeer})
	}
}

func TestPeerStatusLegacyJSONShape(t *testing.T) {
	peer := PeerStatus{Name: "peer-a", MeshIP: "10.200.0.2", Online: true}
	got, err := json.Marshal(peer)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}
	want := `{"name":"peer-a","meshIP":"10.200.0.2","online":true}`
	if string(got) != want {
		t.Fatalf("legacy PeerStatus JSON = %s, want %s", got, want)
	}
}
