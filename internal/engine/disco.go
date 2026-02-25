package engine

import (
	"sync"

	"github.com/enboxorg/meshnet/types/key"
)

// InMemoryDiscoRegistry is a shared in-memory disco key registry.
//
// In normal Tailscale, the control server distributes disco keys between peers.
// In dwn-mesh, engines use this registry to exchange disco keys. For engines
// running in the same process (tests, embedded use), a single shared registry
// is sufficient. For engines on different machines, disco keys will be
// exchanged via DWN endpoint records.
type InMemoryDiscoRegistry struct {
	mu   sync.RWMutex
	keys map[key.NodePublic]key.DiscoPublic
}

// NewInMemoryDiscoRegistry creates a new shared disco key registry.
func NewInMemoryDiscoRegistry() *InMemoryDiscoRegistry {
	return &InMemoryDiscoRegistry{
		keys: make(map[key.NodePublic]key.DiscoPublic),
	}
}

// SetDisco publishes the disco key for a node.
func (r *InMemoryDiscoRegistry) SetDisco(nodeKey key.NodePublic, disco key.DiscoPublic) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys[nodeKey] = disco
}

// GetDisco returns the disco key for a node, or a zero key if unknown.
func (r *InMemoryDiscoRegistry) GetDisco(nodeKey key.NodePublic) key.DiscoPublic {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.keys[nodeKey]
}
