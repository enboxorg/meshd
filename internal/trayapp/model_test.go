package trayapp

import (
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/enboxorg/meshd/internal/daemon"
)

func TestModelViewDisconnected(t *testing.T) {
	view := (Model{}).View()
	if view.Connected || view.StatusTitle != "Disconnected" {
		t.Fatalf("view = %+v, want disconnected", view)
	}
	if !view.ConnectEnabled || view.DisconnectEnabled || view.CopyIPEnabled {
		t.Fatalf("disconnected actions = %+v", view)
	}
}

func TestModelViewConnected(t *testing.T) {
	model := Model{Status: &daemon.Status{
		Running:         true,
		Network:         "home",
		MeshIP:          "10.200.0.7",
		RoutingRequired: true,
		RoutingReady:    true,
		Peers: []daemon.PeerStatus{
			{Name: "zeta", MeshIP: "10.200.0.9"},
			{Name: "Alpha", MeshIP: "10.200.0.2", Online: true},
			{Name: "no-address", Online: true},
		},
	}}
	view := model.View()
	if !view.Connected || view.StatusTitle != "Connected to home · 10.200.0.7" {
		t.Fatalf("view = %+v", view)
	}
	if view.ConnectEnabled || !view.DisconnectEnabled || !view.CopyIPEnabled {
		t.Fatalf("connected actions = %+v", view)
	}
	gotPeerTitles := []string{view.Peers[0].Title, view.Peers[1].Title}
	wantPeerTitles := []string{"● Alpha · 10.200.0.2", "○ zeta · 10.200.0.9"}
	if !reflect.DeepEqual(gotPeerTitles, wantPeerTitles) {
		t.Fatalf("peer titles = %v, want %v", gotPeerTitles, wantPeerTitles)
	}
}

func TestModelViewSyncingRoutes(t *testing.T) {
	view := (Model{Status: &daemon.Status{
		Running:         true,
		Network:         "home",
		MeshIP:          "10.200.0.7",
		RoutingRequired: true,
		RoutingReady:    false,
		RoutingPhase:    "syncing",
		Peers:           []daemon.PeerStatus{{Name: "peer", MeshIP: "10.200.0.8"}},
	}}).View()

	if view.Connected || view.StatusTitle != "Syncing home…" || view.Tooltip != "meshd — Syncing home" {
		t.Fatalf("syncing view = %+v", view)
	}
	if view.ConnectEnabled || !view.DisconnectEnabled || view.CopyIPEnabled || len(view.Peers) != 0 {
		t.Fatalf("syncing actions = %+v", view)
	}
}

func TestModelViewRoutingError(t *testing.T) {
	view := (Model{
		Status: &daemon.Status{
			Running:         true,
			Network:         "home",
			MeshIP:          "10.200.0.7",
			RoutingRequired: true,
			RoutingReady:    false,
			RoutingPhase:    "error",
			RoutingError:    "installing peer routes: permission denied",
			Peers:           []daemon.PeerStatus{{Name: "peer", MeshIP: "10.200.0.8"}},
		},
		LastError: "meshd up timed out",
	}).View()

	if view.Connected || view.StatusTitle != "Connection error" {
		t.Fatalf("routing error view = %+v", view)
	}
	if view.ConnectEnabled || !view.DisconnectEnabled || view.CopyIPEnabled || len(view.Peers) != 0 {
		t.Fatalf("routing error actions = %+v", view)
	}
	for _, want := range []string{"meshd up timed out", "installing peer routes: permission denied"} {
		if !strings.Contains(view.Error, want) || !strings.Contains(view.Tooltip, want) {
			t.Fatalf("routing error view does not surface %q: %+v", want, view)
		}
	}
}

func TestModelViewClearsLiveRoutingErrorAfterRecovery(t *testing.T) {
	model := Model{Status: &daemon.Status{
		Running:         true,
		RoutingRequired: true,
		RoutingPhase:    "error",
		RoutingError:    "configuring OS routes: permission denied",
	}}
	if view := model.View(); view.Error == "" || view.StatusTitle != "Connection error" {
		t.Fatalf("routing error view = %+v", view)
	}

	model.Status = &daemon.Status{
		Running:         true,
		RoutingRequired: true,
		RoutingReady:    true,
		RoutingPhase:    "ready",
	}
	view := model.View()
	if !view.Connected || view.Error != "" || strings.Contains(view.Tooltip, "permission denied") {
		t.Fatalf("recovered routing view = %+v", view)
	}
}

func TestModelViewDegradedRouting(t *testing.T) {
	view := (Model{Status: &daemon.Status{
		Running:         true,
		Network:         "home",
		MeshIP:          "10.200.0.7",
		RoutingRequired: true,
		RoutingReady:    true,
		RoutingPhase:    "error",
		RoutingError:    "refreshing control map: temporarily unavailable",
		Peers:           []daemon.PeerStatus{{Name: "peer", MeshIP: "10.200.0.8"}},
	}}).View()

	if !view.Connected || view.StatusTitle != "Connected to home · 10.200.0.7 — Degraded" {
		t.Fatalf("degraded view = %+v", view)
	}
	if view.ConnectEnabled || !view.DisconnectEnabled || !view.CopyIPEnabled || len(view.Peers) != 1 {
		t.Fatalf("degraded actions = %+v", view)
	}
	if !strings.Contains(view.Error, "temporarily unavailable") ||
		!strings.Contains(view.Tooltip, "temporarily unavailable") {
		t.Fatalf("degraded view does not surface routing error: %+v", view)
	}
}

func TestModelViewUserspaceReady(t *testing.T) {
	view := (Model{Status: &daemon.Status{
		Running:         true,
		Network:         "home",
		MeshIP:          "10.200.0.7",
		RoutingRequired: false,
		RoutingReady:    true,
		RoutingPhase:    "userspace",
	}}).View()

	if !view.Connected || view.StatusTitle != "Connected to home · 10.200.0.7" {
		t.Fatalf("userspace view = %+v", view)
	}
}

func TestModelViewTransitions(t *testing.T) {
	for _, tc := range []struct {
		name      string
		operation Operation
		title     string
	}{
		{name: "connect", operation: OperationConnecting, title: "Connecting…"},
		{name: "disconnect", operation: OperationDisconnecting, title: "Disconnecting…"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			view := (Model{Operation: tc.operation}).View()
			if view.StatusTitle != tc.title || view.ConnectEnabled || view.DisconnectEnabled {
				t.Fatalf("transition view = %+v", view)
			}
		})
	}
}

func TestModelViewIncludesErrorInTooltip(t *testing.T) {
	view := (Model{LastError: "vault password required"}).View()
	if view.Error != "vault password required" || view.Tooltip != "meshd — Disconnected: vault password required" {
		t.Fatalf("error view = %+v", view)
	}
}

func TestModelViewSanitizesAndCapsLabels(t *testing.T) {
	longName := "peer\n\t\u202e" + strings.Repeat("界", maxPeerNameRunes+20)
	view := (Model{Status: &daemon.Status{
		Running:      true,
		Network:      "home\n\u202e network",
		RoutingReady: true,
		Peers: []daemon.PeerStatus{{
			Name:   longName,
			MeshIP: "10.200.0.8",
		}},
	}}).View()
	if strings.ContainsAny(view.StatusTitle, "\n\r\t") || strings.ContainsRune(view.StatusTitle, '\u202e') {
		t.Fatalf("unsafe network title = %q", view.StatusTitle)
	}
	if len(view.Peers) != 1 {
		t.Fatalf("peers = %+v", view.Peers)
	}
	peer := view.Peers[0]
	if strings.ContainsAny(peer.Name, "\n\r\t") || strings.ContainsRune(peer.Name, '\u202e') {
		t.Fatalf("unsafe peer name = %q", peer.Name)
	}
	if got := utf8.RuneCountInString(peer.Name); got > maxPeerNameRunes {
		t.Fatalf("peer name has %d runes, max %d", got, maxPeerNameRunes)
	}
	if !strings.HasSuffix(peer.Title, " · 10.200.0.8") {
		t.Fatalf("peer title lost mesh IP: %q", peer.Title)
	}
}
