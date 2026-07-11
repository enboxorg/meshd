package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/enboxorg/meshd/internal/trayapp"
)

func TestPlanPeerMenuRefreshLifecycle(t *testing.T) {
	keys := make([]string, 4)
	a := testPeerView("a", "alpha", "10.200.0.2", true)
	b := testPeerView("b", "beta", "10.200.0.3", false)

	plan := planPeerMenu(true, []trayapp.PeerView{a, b}, keys)
	assertPeerMenuSlot(t, plan.Slots[0], a)
	assertPeerMenuSlot(t, plan.Slots[1], b)
	keys = peerMenuPlanKeys(plan)

	// Reordering the input preserves each peer's native slot.
	plan = planPeerMenu(true, []trayapp.PeerView{b, a}, keys)
	assertPeerMenuSlot(t, plan.Slots[0], a)
	assertPeerMenuSlot(t, plan.Slots[1], b)

	// An online-state title update changes presentation without changing its key.
	aOnline := a
	aOnline.Online = false
	aOnline.Title = "○ alpha · 10.200.0.2"
	plan = planPeerMenu(true, []trayapp.PeerView{aOnline, b}, peerMenuPlanKeys(plan))
	assertPeerMenuSlot(t, plan.Slots[0], aOnline)

	// Rename and IP changes receive new keys but reuse freed fixed slots.
	aRenamed := testPeerView("a-renamed", "atlas", "10.200.0.2", false)
	bMoved := testPeerView("b-moved", "beta", "10.200.0.30", false)
	plan = planPeerMenu(true, []trayapp.PeerView{aRenamed, bMoved}, peerMenuPlanKeys(plan))
	assertPeerMenuSlot(t, plan.Slots[0], aRenamed)
	assertPeerMenuSlot(t, plan.Slots[1], bMoved)

	// Dropping a peer clears its slot; a later addition uses that free slot
	// without growing the native menu or moving the surviving peer.
	plan = planPeerMenu(true, []trayapp.PeerView{bMoved}, peerMenuPlanKeys(plan))
	if plan.Slots[0].Visible {
		t.Fatalf("removed peer slot = %+v, want hidden", plan.Slots[0])
	}
	assertPeerMenuSlot(t, plan.Slots[1], bMoved)
	c := testPeerView("c", "charlie", "10.200.0.4", true)
	plan = planPeerMenu(true, []trayapp.PeerView{bMoved, c}, peerMenuPlanKeys(plan))
	assertPeerMenuSlot(t, plan.Slots[0], c)
	assertPeerMenuSlot(t, plan.Slots[1], bMoved)
	if got := len(plan.Slots); got != len(keys) {
		t.Fatalf("slot count grew to %d, want fixed %d", got, len(keys))
	}
}

func TestPlanPeerMenuCapAndOverflow(t *testing.T) {
	peers := make([]trayapp.PeerView, maxPeerMenuSlots+3)
	for index := range peers {
		ip := fmt.Sprintf("10.200.1.%d", index+1)
		peers[index] = testPeerView(fmt.Sprintf("peer-%02d", index), fmt.Sprintf("peer-%02d", index), ip, index%2 == 0)
	}

	plan := planPeerMenu(true, peers, make([]string, maxPeerMenuSlots))
	if got, want := plan.Title, fmt.Sprintf("Peers (%d)", len(peers)); got != want {
		t.Fatalf("title = %q, want %q", got, want)
	}
	if got := len(plan.Slots); got != maxPeerMenuSlots {
		t.Fatalf("slot count = %d, want %d", got, maxPeerMenuSlots)
	}
	for index, slot := range plan.Slots {
		if !slot.Visible {
			t.Fatalf("slot %d hidden below cap", index)
		}
	}
	if !plan.OverflowVisible || !strings.Contains(plan.OverflowTitle, "3 more peers") || !strings.Contains(plan.OverflowTitle, "dashboard") {
		t.Fatalf("overflow = visible %t title %q", plan.OverflowVisible, plan.OverflowTitle)
	}

	// A refresh with a much larger list must keep exactly the initialized pool.
	morePeers := append(append([]trayapp.PeerView{}, peers...), peers...)
	plan = planPeerMenu(true, morePeers, peerMenuPlanKeys(plan))
	if got := len(plan.Slots); got != maxPeerMenuSlots {
		t.Fatalf("slot count after growth = %d, want %d", got, maxPeerMenuSlots)
	}
}

func TestPlanPeerMenuEmptyStates(t *testing.T) {
	for _, tc := range []struct {
		name       string
		connected  bool
		emptyTitle string
	}{
		{name: "disconnected", emptyTitle: "Connect to view peers"},
		{name: "connected", connected: true, emptyTitle: "No peers"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := planPeerMenu(tc.connected, nil, make([]string, maxPeerMenuSlots))
			if plan.Title != "Peers" || !plan.EmptyVisible || plan.EmptyTitle != tc.emptyTitle || plan.OverflowVisible {
				t.Fatalf("empty plan = %+v", plan)
			}
		})
	}
}

func TestPlanPeerMenuCurrentIPFollowsKeyedPeer(t *testing.T) {
	a := testPeerView("a", "alpha", "10.200.0.2", true)
	b := testPeerView("b", "beta", "10.200.0.3", true)
	plan := planPeerMenu(true, []trayapp.PeerView{a, b}, make([]string, 2))

	// Input order can change independently of the sorted model; the click IP
	// remains attached to the peer key already occupying each native slot.
	plan = planPeerMenu(true, []trayapp.PeerView{b, a}, peerMenuPlanKeys(plan))
	if got := plan.Slots[0].MeshIP; got != a.MeshIP {
		t.Fatalf("alpha slot IP = %q, want %q", got, a.MeshIP)
	}
	if got := plan.Slots[1].MeshIP; got != b.MeshIP {
		t.Fatalf("beta slot IP = %q, want %q", got, b.MeshIP)
	}
}

func testPeerView(key, name, ip string, online bool) trayapp.PeerView {
	indicator := "○"
	if online {
		indicator = "●"
	}
	return trayapp.PeerView{
		Key:    key,
		Name:   name,
		MeshIP: ip,
		Online: online,
		Title:  fmt.Sprintf("%s %s · %s", indicator, name, ip),
	}
}

func peerMenuPlanKeys(plan peerMenuPlan) []string {
	keys := make([]string, len(plan.Slots))
	for index, slot := range plan.Slots {
		keys[index] = slot.Key
	}
	return keys
}

func assertPeerMenuSlot(t *testing.T, got peerMenuEntry, want trayapp.PeerView) {
	t.Helper()
	if !got.Visible || got.Key != want.Key || got.Title != want.Title || got.MeshIP != want.MeshIP || got.Tooltip != "Copy "+want.MeshIP {
		t.Fatalf("slot = %+v, want peer %+v", got, want)
	}
}
