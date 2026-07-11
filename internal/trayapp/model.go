// Package trayapp contains the platform-neutral behavior for the meshd
// menu-bar companion.
package trayapp

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/enboxorg/meshd/internal/daemon"
)

const (
	maxNetworkNameRunes = 64
	maxPeerNameRunes    = 48
)

// Operation is a user-requested connection transition in progress.
type Operation uint8

const (
	OperationNone Operation = iota
	OperationConnecting
	OperationDisconnecting
)

// Model is the latest daemon and user-action state rendered by the tray.
type Model struct {
	Status    *daemon.Status
	Operation Operation
	LastError string
}

// View is a presentation-ready, immutable snapshot of Model.
type View struct {
	Connected         bool
	StatusTitle       string
	Tooltip           string
	MeshIP            string
	ConnectEnabled    bool
	DisconnectEnabled bool
	CopyIPEnabled     bool
	Peers             []PeerView
	Error             string
}

// PeerView is one clickable peer row.
type PeerView struct {
	Key    string
	Title  string
	Name   string
	MeshIP string
	Online bool
}

// View builds the current menu presentation.
func (m Model) View() View {
	running := m.Status != nil && m.Status.Running
	routingError := running && strings.EqualFold(strings.TrimSpace(m.Status.RoutingPhase), "error")
	connectionError := routingError && !m.Status.RoutingReady
	degraded := routingError && m.Status.RoutingReady
	connected := running && m.Status.RoutingReady
	view := View{
		Connected:         connected,
		ConnectEnabled:    !running && m.Operation == OperationNone,
		DisconnectEnabled: running && m.Operation == OperationNone,
		Error:             modelError(m.LastError, routingError, m.Status),
	}

	switch m.Operation {
	case OperationConnecting:
		view.StatusTitle = "Connecting…"
		view.Tooltip = "meshd — Connecting"
	case OperationDisconnecting:
		view.StatusTitle = "Disconnecting…"
		view.Tooltip = "meshd — Disconnecting"
	case OperationNone:
		switch {
		case connectionError:
			view.StatusTitle = "Connection error"
			view.Tooltip = "meshd — Connection error"
		case connected:
			view.MeshIP = strings.TrimSpace(m.Status.MeshIP)
			view.StatusTitle = connectedTitle(m.Status.Network, view.MeshIP)
			if degraded {
				view.StatusTitle += " — Degraded"
			}
			view.Tooltip = "meshd — " + view.StatusTitle
			view.CopyIPEnabled = view.MeshIP != ""
			view.Peers = peerViews(m.Status.Peers)
		case running:
			view.StatusTitle = syncingTitle(m.Status.Network)
			view.Tooltip = "meshd — " + strings.TrimSuffix(view.StatusTitle, "…")
		default:
			view.StatusTitle = "Disconnected"
			view.Tooltip = "meshd — Disconnected"
		}
	}
	if view.Error != "" {
		view.Tooltip += ": " + view.Error
	}
	return view
}

func modelError(lastError string, routingError bool, status *daemon.Status) string {
	lastError = strings.TrimSpace(lastError)
	if !routingError || status == nil {
		return lastError
	}
	routeError := strings.TrimSpace(status.RoutingError)
	if routeError == "" || routeError == lastError {
		return lastError
	}
	if lastError == "" {
		return routeError
	}
	return lastError + "; " + routeError
}

func syncingTitle(network string) string {
	network = safeMenuLabel(network, maxNetworkNameRunes)
	if network != "" {
		return "Syncing " + network + "…"
	}
	return "Syncing…"
}

func connectedTitle(network, meshIP string) string {
	network = safeMenuLabel(network, maxNetworkNameRunes)
	meshIP = strings.TrimSpace(meshIP)
	switch {
	case network != "" && meshIP != "":
		return fmt.Sprintf("Connected to %s · %s", network, meshIP)
	case network != "":
		return "Connected to " + network
	case meshIP != "":
		return "Connected · " + meshIP
	default:
		return "Connected"
	}
}

func peerViews(peers []daemon.PeerStatus) []PeerView {
	views := make([]PeerView, 0, len(peers))
	for _, peer := range peers {
		ip := strings.TrimSpace(peer.MeshIP)
		if ip == "" {
			continue
		}
		name := safeMenuLabel(peer.Name, maxPeerNameRunes)
		if name == "" {
			name = ip
		}
		indicator := "○"
		if peer.Online {
			indicator = "●"
		}
		views = append(views, PeerView{
			Key:    name + "\x00" + ip,
			Title:  fmt.Sprintf("%s %s · %s", indicator, name, ip),
			Name:   name,
			MeshIP: ip,
			Online: peer.Online,
		})
	}
	sort.Slice(views, func(i, j int) bool {
		left, right := strings.ToLower(views[i].Name), strings.ToLower(views[j].Name)
		if left == right {
			return views[i].MeshIP < views[j].MeshIP
		}
		return left < right
	})
	return views
}

func safeMenuLabel(value string, maxRunes int) string {
	var label strings.Builder
	spacePending := false
	for _, r := range strings.TrimSpace(value) {
		if unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Categories["Cf"], r) {
			spacePending = label.Len() > 0
			continue
		}
		if spacePending {
			label.WriteByte(' ')
			spacePending = false
		}
		label.WriteRune(r)
	}
	return truncateRunes(label.String(), maxRunes)
}

func truncateRunes(value string, maxRunes int) string {
	runes := []rune(value)
	if maxRunes <= 0 {
		return ""
	}
	if len(runes) <= maxRunes {
		return value
	}
	if maxRunes == 1 {
		return "…"
	}
	return string(runes[:maxRunes-1]) + "…"
}
