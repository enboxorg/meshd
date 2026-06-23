package engine

import (
	"sync"

	"github.com/enboxorg/meshnet/wgengine/router"
)

type synchronizedRouter struct {
	mu sync.Mutex
	r  router.Router
}

func newSynchronizedRouter(r router.Router) *synchronizedRouter {
	if r == nil {
		return nil
	}
	return &synchronizedRouter{r: r}
}

func (r *synchronizedRouter) Up() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.r.Up()
}

func (r *synchronizedRouter) Set(cfg *router.Config) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.r.Set(cfg)
}

func (r *synchronizedRouter) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.r.Close()
}
