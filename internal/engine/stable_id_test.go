package engine

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/enboxorg/meshd/internal/control"
)

func TestConvertUsesControlStableID(t *testing.T) {
	node := &control.Node{
		ID:       42,
		StableID: "dwn-immutable-node",
		Name:     "node",
		DID:      "did:jwk:node",
		Key:      testWireGuardKey(),
		MeshIP:   netip.MustParseAddr("10.200.0.42"),
	}

	converted, err := NewConverter("test").convertNode(node)
	if err != nil {
		t.Fatalf("convertNode: %v", err)
	}
	if got := string(converted.StableID); got != node.StableID {
		t.Fatalf("StableID = %q, want %q", got, node.StableID)
	}
}

func TestConvertNodeUsesStaticStableIDFallback(t *testing.T) {
	node := &control.Node{
		ID:     42,
		Name:   "node",
		Key:    testWireGuardKey(),
		MeshIP: netip.MustParseAddr("10.200.0.42"),
	}

	converted, err := NewConverter("test").convertNode(node)
	if err != nil {
		t.Fatalf("convertNode: %v", err)
	}
	if got, want := string(converted.StableID), "dwn-42"; got != want {
		t.Fatalf("StableID = %q, want %q", got, want)
	}
}

func TestConvertRejectsInvalidNodeIdentities(t *testing.T) {
	newNode := func(id int64, stableID, name string) *control.Node {
		return &control.Node{
			ID:       id,
			StableID: stableID,
			Name:     name,
			DID:      "did:jwk:" + name,
			Key:      testWireGuardKey(),
			MeshIP:   netip.MustParseAddr("10.200.0.42"),
		}
	}
	tests := []struct {
		name    string
		resp    *control.MapResponse
		wantErr string
	}{
		{
			name:    "nonpositive ID",
			resp:    &control.MapResponse{Node: newNode(0, "dwn-self", "self")},
			wantErr: "invalid NodeID 0",
		},
		{
			name: "duplicate NodeID",
			resp: &control.MapResponse{
				Node:  newNode(1, "dwn-self", "self"),
				Peers: []*control.Node{newNode(1, "dwn-peer", "peer")},
			},
			wantErr: "duplicate NodeID 1",
		},
		{
			name: "duplicate StableID",
			resp: &control.MapResponse{
				Node:  newNode(1, "dwn-shared", "self"),
				Peers: []*control.Node{newNode(2, "dwn-shared", "peer")},
			},
			wantErr: `duplicate StableID "dwn-shared"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewConverter("test").Convert(tt.resp)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Convert error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}
