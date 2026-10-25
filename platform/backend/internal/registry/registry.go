package registry

import (
	"sync"

	"github.com/nestho/cisbenchmarks/platform/backend/internal/audit"
)

type Registry struct {
	mu   sync.RWMutex
	items map[string]*audit.Benchmark
}

func New() *Registry { return &Registry{items: map[string]*audit.Benchmark{}} }

func (r *Registry) Register(bm *audit.Benchmark) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items[bm.ID] = bm
}

func (r *Registry) Get(id string) (*audit.Benchmark, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	bm, ok := r.items[id]
	return bm, ok
}

func (r *Registry) List() []*audit.Benchmark {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*audit.Benchmark, 0, len(r.items))
	for _, bm := range r.items {
		out = append(out, bm)
	}
	return out
}