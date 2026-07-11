package engine

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/enboxorg/meshd/internal/control"
)

func TestMeshSnapshotStorePublishesRichSnapshotAndDeepCopies(t *testing.T) {
	lastSeen := time.Now().UTC().Add(-time.Minute)
	resp := &control.MapResponse{
		Node: &control.Node{
			DID:            "did:example:self",
			Name:           "laptop",
			Label:          "My Laptop",
			MemberDID:      "did:example:owner",
			MemberRecordID: "member-self",
			ExpiresAt:      "2026-08-01T00:00:00Z",
			MeshIP:         netip.MustParseAddr("10.200.0.1"),
			Online:         true,
			LastSeen:       lastSeen,
		},
		Peers: []*control.Node{
			{
				DID:            "did:example:peer",
				Name:           "server",
				Label:          "Home Server",
				MemberDID:      "did:example:member",
				MemberRecordID: "member-peer",
				ExpiresAt:      "2026-09-01T00:00:00Z",
				MeshIP:         netip.MustParseAddr("10.200.0.2"),
				Online:         true,
				LastSeen:       lastSeen.Add(-time.Minute),
			},
			nil,
		},
	}
	store := &meshSnapshotStore{}
	before := time.Now().UTC()
	store.record(resp, nil)
	after := time.Now().UTC()

	got := store.load()
	if got == nil {
		t.Fatal("snapshot is nil")
	}
	if got.Generation != 1 {
		t.Fatalf("Generation = %d, want 1", got.Generation)
	}
	if got.RefreshedAt.Before(before) || got.RefreshedAt.After(after) {
		t.Fatalf("RefreshedAt = %v, want between %v and %v", got.RefreshedAt, before, after)
	}
	if !got.LastAttemptAt.Equal(got.RefreshedAt) {
		t.Fatalf("LastAttemptAt = %v, want RefreshedAt %v", got.LastAttemptAt, got.RefreshedAt)
	}
	if got.LastError != "" {
		t.Fatalf("LastError = %q, want empty", got.LastError)
	}
	if got.Self == nil {
		t.Fatal("Self is nil")
	}
	wantSelf := PeerSnapshot{
		NodeDID:        "did:example:self",
		Name:           "laptop",
		MeshIP:         "10.200.0.1",
		OwnerDID:       "did:example:owner",
		MemberRecordID: "member-self",
		Label:          "My Laptop",
		ExpiresAt:      "2026-08-01T00:00:00Z",
		Online:         true,
		LastSeen:       &lastSeen,
	}
	if !reflect.DeepEqual(*got.Self, wantSelf) {
		t.Fatalf("Self = %#v, want %#v", *got.Self, wantSelf)
	}
	if len(got.Peers) != 1 {
		t.Fatalf("Peers length = %d, want 1", len(got.Peers))
	}
	if got.Peers[0].NodeDID != "did:example:peer" ||
		got.Peers[0].OwnerDID != "did:example:member" ||
		got.Peers[0].MemberRecordID != "member-peer" ||
		got.Peers[0].Label != "Home Server" ||
		got.Peers[0].ExpiresAt != "2026-09-01T00:00:00Z" ||
		got.Peers[0].MeshIP != "10.200.0.2" ||
		!got.Peers[0].Online {
		t.Fatalf("peer = %#v", got.Peers[0])
	}

	// Neither the source MapResponse nor a returned snapshot may alias the
	// immutable value retained by the store.
	resp.Node.Label = "mutated source"
	resp.Peers[0].Label = "mutated source peer"
	got.Self.Label = "mutated result"
	got.Peers[0].Label = "mutated result peer"
	*got.Self.LastSeen = time.Time{}
	*got.Peers[0].LastSeen = time.Time{}

	again := store.load()
	if again.Self.Label != "My Laptop" || again.Peers[0].Label != "Home Server" {
		t.Fatalf("stored labels were mutated: Self=%q Peer=%q", again.Self.Label, again.Peers[0].Label)
	}
	if again.Self.LastSeen == nil || !again.Self.LastSeen.Equal(lastSeen) {
		t.Fatalf("stored self LastSeen = %v, want %v", again.Self.LastSeen, lastSeen)
	}
	if again.Peers[0].LastSeen == nil || !again.Peers[0].LastSeen.Equal(lastSeen.Add(-time.Minute)) {
		t.Fatalf("stored peer LastSeen = %v", again.Peers[0].LastSeen)
	}
}

func TestMeshSnapshotLivenessIsDerivedFromLastSeenAtReadTime(t *testing.T) {
	now := time.Now().UTC()
	fresh := now.Add(-control.DefaultPeerStaleThreshold + time.Minute)
	stale := now.Add(-control.DefaultPeerStaleThreshold - time.Minute)
	store := &meshSnapshotStore{}
	store.record(&control.MapResponse{
		Node: &control.Node{
			DID:      "did:example:self",
			Online:   false,
			LastSeen: fresh,
		},
		Peers: []*control.Node{
			{
				DID:      "did:example:fresh",
				Online:   false,
				LastSeen: fresh,
			},
			{
				DID:      "did:example:stale",
				Online:   true,
				LastSeen: stale,
			},
			{
				DID:    "did:example:never-seen",
				Online: true,
			},
		},
	}, nil)

	engine := &Engine{snapshots: store}
	snapshot := engine.MeshSnapshot()
	if snapshot == nil || snapshot.Self == nil || !snapshot.Self.Online {
		t.Fatalf("fresh self liveness = %#v, want online", snapshot)
	}
	if len(snapshot.Peers) != 3 {
		t.Fatalf("Peers length = %d, want 3", len(snapshot.Peers))
	}
	if !snapshot.Peers[0].Online || snapshot.Peers[1].Online || snapshot.Peers[2].Online {
		t.Fatalf("peer liveness = %#v, want fresh only online", snapshot.Peers)
	}

	peers := engine.PeerSnapshots()
	if len(peers) != 3 || !peers[0].Online || peers[1].Online || peers[2].Online {
		t.Fatalf("PeerSnapshots liveness = %#v, want fresh only online", peers)
	}

	// The same materialized snapshot ages offline without another remote
	// refresh; only the daemon-facing copy is changed.
	refreshSnapshotLiveness(snapshot, now.Add(2*control.DefaultPeerStaleThreshold))
	if snapshot.Self.Online || snapshot.Peers[0].Online {
		t.Fatalf("aged snapshot remained online: Self=%#v Peers=%#v", snapshot.Self, snapshot.Peers)
	}
}

func TestMeshSnapshotProjectionAppliesMembershipExpiry(t *testing.T) {
	now := time.Now().UTC()
	freshSeen := now.Add(-time.Minute)
	store := &meshSnapshotStore{}
	store.record(&control.MapResponse{
		Node: &control.Node{
			DID:       "did:example:self",
			ExpiresAt: now.Add(-time.Minute).Format(time.RFC3339Nano),
			LastSeen:  freshSeen,
			Online:    true,
		},
		Peers: []*control.Node{
			{
				DID:       "did:example:expired",
				ExpiresAt: now.Add(-time.Second).Format(time.RFC3339Nano),
				LastSeen:  freshSeen,
				Online:    true,
			},
			{
				DID:       "did:example:active",
				ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
				LastSeen:  freshSeen,
				Online:    true,
			},
		},
	}, nil)

	snapshot := store.load()
	if snapshot == nil || snapshot.Self == nil || snapshot.Self.Online {
		t.Fatalf("expired self projection = %#v, want retained but offline", snapshot)
	}
	if len(snapshot.Peers) != 1 || snapshot.Peers[0].NodeDID != "did:example:active" || !snapshot.Peers[0].Online {
		t.Fatalf("expiry-filtered peers = %#v, want only active peer", snapshot.Peers)
	}
}

func TestMeshSnapshotStoreFailurePreservesLastGood(t *testing.T) {
	store := &meshSnapshotStore{}
	first := &control.MapResponse{
		Node: &control.Node{
			DID:    "did:example:self",
			Label:  "first",
			MeshIP: netip.MustParseAddr("10.200.0.1"),
		},
		Peers: []*control.Node{{
			DID:    "did:example:peer",
			Label:  "peer-first",
			MeshIP: netip.MustParseAddr("10.200.0.2"),
		}},
	}
	store.record(first, nil)
	success := store.load()

	refreshErr := errors.New("remote refresh unavailable")
	store.record(nil, refreshErr)
	failed := store.load()
	if failed.Generation != success.Generation {
		t.Fatalf("failed Generation = %d, want %d", failed.Generation, success.Generation)
	}
	if !failed.RefreshedAt.Equal(success.RefreshedAt) {
		t.Fatalf("failed RefreshedAt = %v, want %v", failed.RefreshedAt, success.RefreshedAt)
	}
	if !reflect.DeepEqual(failed.Self, success.Self) || !reflect.DeepEqual(failed.Peers, success.Peers) {
		t.Fatalf("failure replaced last-good data: failed=%#v success=%#v", failed, success)
	}
	if failed.LastAttemptAt.Before(success.LastAttemptAt) {
		t.Fatalf("failed LastAttemptAt = %v, before successful attempt %v", failed.LastAttemptAt, success.LastAttemptAt)
	}
	if failed.LastError != refreshErr.Error() {
		t.Fatalf("LastError = %q, want %q", failed.LastError, refreshErr)
	}

	second := &control.MapResponse{Node: &control.Node{
		DID:    "did:example:self",
		Label:  "second",
		MeshIP: netip.MustParseAddr("10.200.0.1"),
	}}
	store.record(second, nil)
	recovered := store.load()
	if recovered.Generation != success.Generation+1 {
		t.Fatalf("recovered Generation = %d, want %d", recovered.Generation, success.Generation+1)
	}
	if recovered.LastError != "" {
		t.Fatalf("recovered LastError = %q, want empty", recovered.LastError)
	}
	if recovered.Self == nil || recovered.Self.Label != "second" {
		t.Fatalf("recovered Self = %#v", recovered.Self)
	}
	if !recovered.RefreshedAt.Equal(recovered.LastAttemptAt) {
		t.Fatalf("recovered timestamps differ: refreshed=%v attempted=%v", recovered.RefreshedAt, recovered.LastAttemptAt)
	}
}

func TestMeshSnapshotStoreRecordsFailureBeforeFirstSuccess(t *testing.T) {
	store := &meshSnapshotStore{}
	store.record(nil, errors.New("bootstrap failed"))

	got := (&Engine{snapshots: store}).MeshSnapshot()
	if got == nil {
		t.Fatal("snapshot is nil")
	}
	if got.Generation != 0 || !got.RefreshedAt.IsZero() || got.Self != nil || got.Peers != nil {
		t.Fatalf("bootstrap failure snapshot = %#v", got)
	}
	if got.LastAttemptAt.IsZero() || got.LastError != "bootstrap failed" {
		t.Fatalf("bootstrap failure metadata = %#v", got)
	}
}

func TestMapResponseFuncPublishesOnlyAfterSuccessfulConversion(t *testing.T) {
	store := &meshSnapshotStore{}
	converter := NewConverter("mesh.test")
	successResp := &control.MapResponse{}

	successFn := mapResponseFunc(
		func(context.Context) (*control.MapResponse, error) { return successResp, nil },
		converter,
		store.record,
	)
	if _, err := successFn(context.Background()); err != nil {
		t.Fatalf("successful conversion: %v", err)
	}
	success := store.load()
	if success == nil || success.Generation != 1 || success.LastError != "" {
		t.Fatalf("successful snapshot = %#v", success)
	}

	conversionFailureFn := mapResponseFunc(
		func(context.Context) (*control.MapResponse, error) { return nil, nil },
		converter,
		store.record,
	)
	if _, err := conversionFailureFn(context.Background()); err == nil {
		t.Fatal("nil MapResponse conversion unexpectedly succeeded")
	}
	afterConversionFailure := store.load()
	if afterConversionFailure.Generation != success.Generation ||
		!afterConversionFailure.RefreshedAt.Equal(success.RefreshedAt) {
		t.Fatalf("conversion failure replaced last good snapshot: %#v", afterConversionFailure)
	}
	if !strings.Contains(afterConversionFailure.LastError, "nil MapResponse") {
		t.Fatalf("conversion LastError = %q", afterConversionFailure.LastError)
	}

	loadFailure := errors.New("DWN unavailable")
	loadFailureFn := mapResponseFunc(
		func(context.Context) (*control.MapResponse, error) { return nil, loadFailure },
		converter,
		store.record,
	)
	if _, err := loadFailureFn(context.Background()); !errors.Is(err, loadFailure) {
		t.Fatalf("load failure = %v, want wrapped %v", err, loadFailure)
	}
	afterLoadFailure := store.load()
	if afterLoadFailure.Generation != success.Generation ||
		!afterLoadFailure.RefreshedAt.Equal(success.RefreshedAt) {
		t.Fatalf("load failure replaced last good snapshot: %#v", afterLoadFailure)
	}
	if !strings.Contains(afterLoadFailure.LastError, "loading DWN state") {
		t.Fatalf("load LastError = %q", afterLoadFailure.LastError)
	}
}

func TestMeshSnapshotStoreConcurrentReadersAndPublishers(t *testing.T) {
	store := &meshSnapshotStore{}
	resp := &control.MapResponse{
		Node: &control.Node{
			DID:    "did:example:self",
			Label:  "self",
			MeshIP: netip.MustParseAddr("10.200.0.1"),
		},
		Peers: []*control.Node{{
			DID:      "did:example:peer",
			Label:    "peer",
			MeshIP:   netip.MustParseAddr("10.200.0.2"),
			Online:   true,
			LastSeen: time.Date(2026, 7, 11, 15, 0, 0, 0, time.UTC),
		}},
	}

	const publishers = 4
	const successesPerPublisher = 100
	const readers = 8
	var wg sync.WaitGroup
	errs := make(chan string, readers*successesPerPublisher)

	for range publishers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range successesPerPublisher {
				store.record(resp, nil)
				if i%10 == 0 {
					store.record(nil, errors.New("transient refresh failure"))
				}
			}
		}()
	}
	for range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range successesPerPublisher * 2 {
				got := store.load()
				if got == nil || got.Generation == 0 {
					continue
				}
				if got.Self == nil || got.Self.NodeDID != "did:example:self" {
					errs <- "successful snapshot missing self"
					continue
				}
				if len(got.Peers) != 1 || got.Peers[0].NodeDID != "did:example:peer" {
					errs <- "successful snapshot has invalid peers"
					continue
				}
				// Mutating a reader's copy must be race-free and isolated.
				got.Self.Label = "reader mutation"
				got.Peers[0].Label = "reader mutation"
				*got.Peers[0].LastSeen = time.Time{}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	got := store.load()
	wantGeneration := uint64(publishers * successesPerPublisher)
	if got.Generation != wantGeneration {
		t.Fatalf("Generation = %d, want %d", got.Generation, wantGeneration)
	}
	if got.Self.Label != "self" || got.Peers[0].Label != "peer" || got.Peers[0].LastSeen.IsZero() {
		t.Fatalf("reader mutation reached stored snapshot: %#v", got)
	}
}
