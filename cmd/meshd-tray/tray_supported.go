//go:build darwin || windows

package main

import (
	"context"
	"fmt"
	"sync"
	"time"
	"unicode/utf8"

	"fyne.io/systray"

	"github.com/enboxorg/meshd/internal/trayapp"
	"github.com/enboxorg/meshd/internal/trayicon"
)

const statusPollInterval = 3 * time.Second

type trayUI struct {
	service *trayapp.Service
	ctx     context.Context
	cancel  context.CancelFunc

	mu    sync.Mutex
	model trayapp.Model

	workerMu      sync.Mutex
	workers       sync.WaitGroup
	workersClosed bool

	renderMu   sync.Mutex
	exiting    bool
	status     *systray.MenuItem
	error      *systray.MenuItem
	dashboard  *systray.MenuItem
	copyIP     *systray.MenuItem
	peers      *systray.MenuItem
	peersTitle string
	connect    *systray.MenuItem
	disconnect *systray.MenuItem
	quit       *systray.MenuItem

	peerEmpty         *systray.MenuItem
	peerEmptyTitle    string
	peerEmptyShown    bool
	peerOverflow      *systray.MenuItem
	peerOverflowTitle string
	peerOverflowShown bool
	peerItems         []*peerMenuSlot
	peerSignature     string
	iconInitialized   bool
	iconConnected     bool
}

type peerMenuSlot struct {
	item *systray.MenuItem

	mu    sync.RWMutex
	entry peerMenuEntry
}

func (slot *peerMenuSlot) setEntry(entry peerMenuEntry) {
	slot.mu.Lock()
	slot.entry = entry
	slot.mu.Unlock()
}

func (slot *peerMenuSlot) clear() {
	slot.setEntry(peerMenuEntry{})
}

func (slot *peerMenuSlot) Entry() peerMenuEntry {
	slot.mu.RLock()
	defer slot.mu.RUnlock()
	return slot.entry
}

func (slot *peerMenuSlot) MeshIP() string {
	return slot.Entry().MeshIP
}

func runTray(profile string) error {
	ctx, cancel := context.WithCancel(context.Background())
	ui := &trayUI{service: trayapp.NewService(profile), ctx: ctx, cancel: cancel}
	systray.Run(ui.onReady, ui.onExit)
	return nil
}

func (ui *trayUI) onReady() {
	systray.SetTitle("")
	ui.status = systray.AddMenuItem("Disconnected", "meshd connection status")
	ui.status.Disable()
	ui.error = systray.AddMenuItem("", "Last meshd-tray error")
	ui.error.Disable()
	ui.error.Hide()
	systray.AddSeparator()
	ui.dashboard = systray.AddMenuItem("Open Dashboard…", "Open the active network in your browser")
	ui.copyIP = systray.AddMenuItem("Copy Mesh IP", "Copy this device's mesh IP")
	ui.peers = systray.AddMenuItem("Peers", "Click a peer to copy its mesh IP")
	ui.peersTitle = "Peers"
	ui.peerEmpty = ui.peers.AddSubMenuItem("Connect to view peers", "")
	ui.peerEmpty.Disable()
	ui.peerEmptyTitle = "Connect to view peers"
	ui.peerEmptyShown = true
	ui.initializePeerSlots()
	systray.AddSeparator()
	ui.connect = systray.AddMenuItem("Connect", "Start meshd")
	ui.disconnect = systray.AddMenuItem("Disconnect", "Stop meshd")
	systray.AddSeparator()
	ui.quit = systray.AddMenuItem("Quit", "Quit meshd-tray")

	ui.render()
	ui.startWorker(ui.staticClicks)
	ui.startWorker(ui.pollLoop)
}

func (ui *trayUI) onExit() {
	ui.beginExit()
	ui.workers.Wait()
}

func (ui *trayUI) staticClicks() {
	for {
		select {
		case <-ui.ctx.Done():
			return
		case _, ok := <-ui.dashboard.ClickedCh:
			if !ok {
				return
			}
			ui.startWorker(ui.openDashboard)
		case _, ok := <-ui.copyIP.ClickedCh:
			if !ok {
				return
			}
			ui.startWorker(ui.copyOwnIP)
		case _, ok := <-ui.connect.ClickedCh:
			if !ok {
				return
			}
			ui.startOperation(trayapp.OperationConnecting, 2*time.Minute, ui.service.Connect)
		case _, ok := <-ui.disconnect.ClickedCh:
			if !ok {
				return
			}
			ui.startOperation(trayapp.OperationDisconnecting, 15*time.Second, ui.service.Disconnect)
		case _, ok := <-ui.quit.ClickedCh:
			if !ok {
				return
			}
			ui.beginExit()
			systray.Quit()
			return
		}
	}
}

func (ui *trayUI) pollLoop() {
	ui.refreshStatus()
	ticker := time.NewTicker(statusPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ui.ctx.Done():
			return
		case <-ticker.C:
			ui.refreshStatus()
		}
	}
}

func (ui *trayUI) refreshStatus() {
	ctx, cancel := context.WithTimeout(ui.ctx, 2*time.Second)
	defer cancel()
	status, err := ui.service.Status(ctx)
	if err != nil {
		status = nil
	}
	ui.mu.Lock()
	ui.model.Status = status
	ui.mu.Unlock()
	ui.render()
}

func (ui *trayUI) startOperation(operation trayapp.Operation, timeout time.Duration, action func(context.Context) error) {
	ui.mu.Lock()
	if ui.model.Operation != trayapp.OperationNone {
		ui.mu.Unlock()
		return
	}
	ui.model.Operation = operation
	ui.model.LastError = ""
	ui.mu.Unlock()
	ui.render()

	ui.startWorker(func() {
		ctx, cancel := context.WithTimeout(ui.ctx, timeout)
		defer cancel()
		err := action(ctx)
		ui.mu.Lock()
		ui.model.Operation = trayapp.OperationNone
		if err != nil {
			ui.model.LastError = err.Error()
		}
		ui.mu.Unlock()
		ui.refreshStatus()
	})
}

func (ui *trayUI) openDashboard() {
	ui.mu.Lock()
	status := ui.model.Status
	ui.mu.Unlock()
	ui.recordError(ui.service.OpenDashboard(status))
}

func (ui *trayUI) copyOwnIP() {
	ui.mu.Lock()
	ip := ""
	if ui.model.Status != nil {
		ip = ui.model.Status.MeshIP
	}
	ui.mu.Unlock()
	ui.copyIPToClipboard(ip)
}

func (ui *trayUI) copyIPToClipboard(ip string) {
	ctx, cancel := context.WithTimeout(ui.ctx, 5*time.Second)
	defer cancel()
	ui.recordError(ui.service.CopyText(ctx, ip))
}

func (ui *trayUI) recordError(err error) {
	ui.mu.Lock()
	if err == nil {
		ui.model.LastError = ""
	} else {
		ui.model.LastError = err.Error()
	}
	ui.mu.Unlock()
	ui.render()
}

func (ui *trayUI) render() {
	ui.mu.Lock()
	view := ui.model.View()
	ui.mu.Unlock()

	ui.renderMu.Lock()
	defer ui.renderMu.Unlock()
	if ui.exiting || ui.status == nil {
		return
	}
	if !ui.iconInitialized || ui.iconConnected != view.Connected {
		systray.SetTemplateIcon(trayicon.TemplatePNG(view.Connected), trayicon.WindowsICO(view.Connected))
		ui.iconInitialized = true
		ui.iconConnected = view.Connected
	}
	systray.SetTooltip(view.Tooltip)
	ui.status.SetTitle(view.StatusTitle)
	setEnabled(ui.connect, view.ConnectEnabled)
	setEnabled(ui.disconnect, view.DisconnectEnabled)
	setEnabled(ui.copyIP, view.CopyIPEnabled)
	if view.Error == "" {
		ui.error.Hide()
	} else {
		ui.error.SetTitle("Error: " + truncate(view.Error, 120))
		ui.error.Show()
	}
	ui.renderPeers(view.Connected, view.Peers)
}

func (ui *trayUI) renderPeers(connected bool, peers []trayapp.PeerView) {
	signature := fmt.Sprintf("%t:%v", connected, peers)
	if signature == ui.peerSignature {
		return
	}
	ui.peerSignature = signature

	previousKeys := make([]string, len(ui.peerItems))
	for index, slot := range ui.peerItems {
		previousKeys[index] = slot.Entry().Key
	}
	plan := planPeerMenu(connected, peers, previousKeys)

	if ui.peersTitle != plan.Title {
		ui.peers.SetTitle(plan.Title)
		ui.peersTitle = plan.Title
	}
	if ui.peerEmptyTitle != plan.EmptyTitle {
		ui.peerEmpty.SetTitle(plan.EmptyTitle)
		ui.peerEmptyTitle = plan.EmptyTitle
	}
	if ui.peerEmptyShown != plan.EmptyVisible {
		setVisible(ui.peerEmpty, plan.EmptyVisible)
		ui.peerEmptyShown = plan.EmptyVisible
	}
	for index, entry := range plan.Slots {
		ui.renderPeerSlot(ui.peerItems[index], entry)
	}
	if ui.peerOverflowTitle != plan.OverflowTitle {
		ui.peerOverflow.SetTitle(plan.OverflowTitle)
		ui.peerOverflowTitle = plan.OverflowTitle
	}
	if ui.peerOverflowShown != plan.OverflowVisible {
		setVisible(ui.peerOverflow, plan.OverflowVisible)
		ui.peerOverflowShown = plan.OverflowVisible
	}
}

func (ui *trayUI) initializePeerSlots() {
	ui.peerItems = make([]*peerMenuSlot, 0, maxPeerMenuSlots)
	for range maxPeerMenuSlots {
		item := ui.peers.AddSubMenuItem("", "")
		item.Disable()
		item.Hide()
		slot := &peerMenuSlot{item: item}
		ui.peerItems = append(ui.peerItems, slot)
		ui.startWorker(func() { ui.peerClicks(slot) })
	}
	ui.peerOverflow = ui.peers.AddSubMenuItem("", "")
	ui.peerOverflow.Disable()
	ui.peerOverflow.Hide()
}

func (ui *trayUI) renderPeerSlot(slot *peerMenuSlot, next peerMenuEntry) {
	current := slot.Entry()
	if !next.Visible {
		// Clear the click binding before disabling the native item so an event
		// already in flight can never copy a peer that has just disappeared.
		slot.clear()
		setEnabled(slot.item, false)
		if current.Visible {
			setVisible(slot.item, false)
		}
		return
	}

	remapped := current.Key != next.Key || current.MeshIP != next.MeshIP
	if remapped {
		// Keep an existing native menu item inert for the whole remap. This
		// makes the title and the IP observed by its click worker change as one
		// logical operation without adding or removing an NSMenuItem.
		slot.clear()
		setEnabled(slot.item, false)
	}
	if current.Title != next.Title || remapped {
		slot.item.SetTitle(next.Title)
	}
	if current.Tooltip != next.Tooltip || remapped {
		slot.item.SetTooltip(next.Tooltip)
	}
	slot.setEntry(next)
	if !current.Visible {
		setVisible(slot.item, true)
	}
	setEnabled(slot.item, true)
}

func (ui *trayUI) peerClicks(slot *peerMenuSlot) {
	for {
		select {
		case <-ui.ctx.Done():
			return
		case _, ok := <-slot.item.ClickedCh:
			if !ok {
				return
			}
			if meshIP := slot.MeshIP(); meshIP != "" {
				ui.copyIPToClipboard(meshIP)
			}
		}
	}
}

func (ui *trayUI) startWorker(work func()) bool {
	ui.workerMu.Lock()
	defer ui.workerMu.Unlock()
	if ui.workersClosed || ui.ctx.Err() != nil {
		return false
	}
	ui.workers.Add(1)
	go func() {
		defer ui.workers.Done()
		work()
	}()
	return true
}

func (ui *trayUI) beginExit() {
	ui.renderMu.Lock()
	if !ui.exiting {
		ui.exiting = true
		ui.cancel()
	}
	ui.renderMu.Unlock()

	ui.workerMu.Lock()
	ui.workersClosed = true
	ui.workerMu.Unlock()
}

func setEnabled(item *systray.MenuItem, enabled bool) {
	if enabled && item.Disabled() {
		item.Enable()
	} else if !enabled && !item.Disabled() {
		item.Disable()
	}
}

func setVisible(item *systray.MenuItem, visible bool) {
	if visible {
		item.Show()
	} else {
		item.Hide()
	}
}

func truncate(value string, maxRunes int) string {
	if utf8.RuneCountInString(value) <= maxRunes {
		return value
	}
	runes := []rune(value)
	return string(runes[:maxRunes-1]) + "…"
}
