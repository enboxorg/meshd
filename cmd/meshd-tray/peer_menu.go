package main

import (
	"fmt"

	"github.com/enboxorg/meshd/internal/trayapp"
)

const maxPeerMenuSlots = 64

// peerMenuEntry is the presentation and click binding for one preallocated
// native menu item. Key identifies a peer across refreshes so input reordering
// does not move an existing peer to a different native item.
type peerMenuEntry struct {
	Key     string
	Title   string
	Tooltip string
	MeshIP  string
	Visible bool
}

type peerMenuPlan struct {
	Title           string
	EmptyTitle      string
	EmptyVisible    bool
	Slots           []peerMenuEntry
	OverflowTitle   string
	OverflowVisible bool
}

// planPeerMenu maps the current peers onto an already-created set of slots.
// It never grows that set. Existing keys keep their slot, while new keys take
// the lowest free slot. peers is already deterministically sorted by Model.View.
func planPeerMenu(connected bool, peers []trayapp.PeerView, previousKeys []string) peerMenuPlan {
	plan := peerMenuPlan{
		Title:        "Peers",
		EmptyTitle:   "Connect to view peers",
		EmptyVisible: true,
		Slots:        make([]peerMenuEntry, len(previousKeys)),
	}
	if connected {
		plan.EmptyTitle = "No peers"
	}
	if !connected || len(peers) == 0 || len(previousKeys) == 0 {
		return plan
	}

	plan.Title = fmt.Sprintf("Peers (%d)", len(peers))
	plan.EmptyVisible = false

	visibleCount := min(len(peers), len(previousKeys))
	visiblePeers := peers[:visibleCount]
	peerByKey := make(map[string]trayapp.PeerView, visibleCount)
	peerOrder := make([]string, 0, visibleCount)
	for _, peer := range visiblePeers {
		// PeerView.Key is name+IP today. Duplicate status rows are unusual but
		// still deserve separate menu rows, so disambiguate them deterministically.
		key := uniquePeerMenuKey(peer.Key, peerByKey)
		peerByKey[key] = peer
		peerOrder = append(peerOrder, key)
	}

	assigned := make(map[string]struct{}, visibleCount)
	for index, key := range previousKeys {
		peer, ok := peerByKey[key]
		if !ok {
			continue
		}
		plan.Slots[index] = peerMenuEntryFor(key, peer)
		assigned[key] = struct{}{}
	}

	freeIndex := 0
	for _, key := range peerOrder {
		if _, ok := assigned[key]; ok {
			continue
		}
		for freeIndex < len(plan.Slots) && plan.Slots[freeIndex].Visible {
			freeIndex++
		}
		if freeIndex == len(plan.Slots) {
			break
		}
		plan.Slots[freeIndex] = peerMenuEntryFor(key, peerByKey[key])
		assigned[key] = struct{}{}
	}

	if overflow := len(peers) - visibleCount; overflow > 0 {
		plan.OverflowVisible = true
		plan.OverflowTitle = fmt.Sprintf("%d more peers — open the dashboard to view all", overflow)
	}
	return plan
}

func uniquePeerMenuKey(base string, existing map[string]trayapp.PeerView) string {
	if _, ok := existing[base]; !ok {
		return base
	}
	for duplicate := 2; ; duplicate++ {
		key := fmt.Sprintf("%s\x00%d", base, duplicate)
		if _, ok := existing[key]; !ok {
			return key
		}
	}
}

func peerMenuEntryFor(key string, peer trayapp.PeerView) peerMenuEntry {
	return peerMenuEntry{
		Key:     key,
		Title:   peer.Title,
		Tooltip: "Copy " + peer.MeshIP,
		MeshIP:  peer.MeshIP,
		Visible: true,
	}
}
