package engine

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enboxorg/meshd/internal/control"
	"github.com/enboxorg/meshnet/types/key"
	"github.com/enboxorg/meshnet/types/netmap"
)

type liveMembershipNode struct {
	id      int64
	stable  string
	name    string
	did     string
	meshIP  netip.Addr
	private key.NodePrivate
}

func TestMinimalLiveThirdNodeConnectivity(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	derpMap, stopDERP := startLocalDERP(t)
	defer stopDERP()
	disco := NewInMemoryDiscoRegistry()

	nodeA := newLiveMembershipNode(101, "a", "10.200.0.2")
	nodeB := newLiveMembershipNode(102, "b", "10.200.0.3")
	nodeC := newLiveMembershipNode(103, "c", "10.200.0.4")
	var includeA atomic.Bool

	mapFor := func(self liveMembershipNode, initialPeer liveMembershipNode) func(context.Context) (*netmap.NetworkMap, error) {
		return func(context.Context) (*netmap.NetworkMap, error) {
			peers := []liveMembershipNode{initialPeer}
			if includeA.Load() && self.did != nodeA.did && initialPeer.did != nodeA.did {
				peers = append(peers, nodeA)
			}
			return liveMembershipMap(t, self, peers, derpMap)
		}
	}

	stackB, err := newMinimalStack(t, logger, nodeB.private, mapFor(nodeB, nodeC), disco)
	if err != nil {
		t.Fatalf("creating stack B: %v", err)
	}
	defer stackB.close()
	stackC, err := newMinimalStack(t, logger, nodeC.private, mapFor(nodeC, nodeB), disco)
	if err != nil {
		t.Fatalf("creating stack C: %v", err)
	}
	defer stackC.close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := stackB.start(ctx); err != nil {
		t.Fatalf("starting B: %v", err)
	}
	if err := stackC.start(ctx); err != nil {
		t.Fatalf("starting C: %v", err)
	}
	waitForMinimalPeerCount(t, ctx, stackB, 1)
	waitForMinimalPeerCount(t, ctx, stackC, 1)
	assertMinimalTCPEcho(t, ctx, stackB, stackC, nodeC.meshIP, 10001)

	// The control-layer identity test catches the former rank-based allocator.
	// Here, add A while B and C remain running to verify meshnet applies the
	// corrected live membership update without breaking existing connectivity.
	includeA.Store(true)
	stackA, err := newMinimalStack(t, logger, nodeA.private, func(context.Context) (*netmap.NetworkMap, error) {
		return liveMembershipMap(t, nodeA, []liveMembershipNode{nodeB, nodeC}, derpMap)
	}, disco)
	if err != nil {
		t.Fatalf("creating stack A: %v", err)
	}
	defer stackA.close()
	if err := stackA.start(ctx); err != nil {
		t.Fatalf("starting A: %v", err)
	}
	if stackB.control == nil || stackC.control == nil {
		t.Fatal("existing stacks did not expose their control clients")
	}
	stackB.control.Notify()
	stackC.control.Notify()

	waitForMinimalPeerCount(t, ctx, stackA, 2)
	waitForMinimalPeerCount(t, ctx, stackB, 2)
	waitForMinimalPeerCount(t, ctx, stackC, 2)
	assertMinimalTCPEcho(t, ctx, stackB, stackA, nodeA.meshIP, 10002)
	assertMinimalTCPEcho(t, ctx, stackC, stackA, nodeA.meshIP, 10003)
	assertMinimalTCPEcho(t, ctx, stackB, stackC, nodeC.meshIP, 10004)
}

func newLiveMembershipNode(id int64, name, meshIP string) liveMembershipNode {
	return liveMembershipNode{
		id:      id,
		stable:  fmt.Sprintf("dwn-test-%s", name),
		name:    "node-" + name,
		did:     "did:jwk:" + name,
		meshIP:  netip.MustParseAddr(meshIP),
		private: key.NewNode(),
	}
}

func liveMembershipMap(
	t *testing.T,
	self liveMembershipNode,
	peers []liveMembershipNode,
	derpMap *control.DERPMap,
) (*netmap.NetworkMap, error) {
	t.Helper()
	toControlNode := func(node liveMembershipNode) *control.Node {
		return &control.Node{
			ID:            node.id,
			StableID:      node.stable,
			Name:          node.name,
			DID:           node.did,
			Key:           pubKeyToBase64(node.private.Public()),
			MeshIP:        node.meshIP,
			PreferredDERP: 900,
			Online:        true,
		}
	}
	controlPeers := make([]*control.Node, 0, len(peers))
	for _, peer := range peers {
		controlPeers = append(controlPeers, toControlNode(peer))
	}
	return NewConverter("live-membership-test").Convert(
		control.BuildStaticMapResponse(toControlNode(self), controlPeers, derpMap),
	)
}

func waitForMinimalPeerCount(t *testing.T, ctx context.Context, stack *minimalStack, want int) {
	t.Helper()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if nm := stack.backend.NetMap(); nm != nil && len(nm.Peers) == want {
			allDisco := true
			for _, peer := range nm.Peers {
				if peer.DiscoKey().IsZero() {
					allDisco = false
					break
				}
			}
			if allDisco {
				return
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("waiting for %d peers: %v", want, ctx.Err())
		case <-ticker.C:
		}
	}
}

func assertMinimalTCPEcho(
	t *testing.T,
	ctx context.Context,
	from, to *minimalStack,
	toIP netip.Addr,
	port uint16,
) {
	t.Helper()
	listener, err := to.ns.ListenTCP("tcp4", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		t.Fatalf("listen on %d: %v", port, err)
	}
	defer listener.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		payload, err := io.ReadAll(io.LimitReader(conn, 32))
		if err == nil {
			_, err = conn.Write(payload)
		}
		serverDone <- err
	}()

	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := from.ns.DialContextTCP(dialCtx, netip.AddrPortFrom(toIP, port))
	if err != nil {
		t.Fatalf("dial %s:%d: %v", toIP, port, err)
	}
	payload := []byte("meshd live membership")
	if _, err := conn.Write(payload); err != nil {
		conn.Close()
		t.Fatalf("write to %s:%d: %v", toIP, port, err)
	}
	if err := conn.CloseWrite(); err != nil {
		conn.Close()
		t.Fatalf("close write to %s:%d: %v", toIP, port, err)
	}
	got, err := io.ReadAll(conn)
	conn.Close()
	if err != nil {
		t.Fatalf("read echo from %s:%d: %v", toIP, port, err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo from %s:%d = %q, want %q", toIP, port, got, payload)
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server on %s:%d: %v", toIP, port, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("server on %s:%d did not finish", toIP, port)
	}
}
