//go:build darwin || windows

package main

import (
	"context"
	"testing"
	"time"
)

func TestTrayWorkerLifecycleStopsAndRejectsNewWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ui := &trayUI{ctx: ctx, cancel: cancel}
	started := make(chan struct{})
	stopped := make(chan struct{})
	if !ui.startWorker(func() {
		close(started)
		<-ctx.Done()
		close(stopped)
	}) {
		t.Fatal("initial worker was rejected")
	}
	<-started

	ui.beginExit()
	ui.workers.Wait()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop after tray exit")
	}
	if ui.startWorker(func() {}) {
		t.Fatal("worker started after tray exit")
	}
}

func TestPeerMenuSlotConcurrentUpdate(t *testing.T) {
	slot := &peerMenuSlot{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			slot.setEntry(peerMenuEntry{Key: "peer", MeshIP: "10.200.0.8", Visible: true})
			slot.clear()
		}
	}()
	for i := 0; i < 1000; i++ {
		_ = slot.MeshIP()
	}
	<-done
}
