package registry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/nestho/hardenx/platform/backend/internal/audit"
)

// CatalogEntry represents a benchmark index record from benchmarks/catalog.json.
type CatalogEntry struct {
	ID            string   `json:"id"`
	Title         string   `json:"title"`
	Version       string   `json:"version"`
	Category      string   `json:"category"`
	Technology    string   `json:"technology"`
	OS            string   `json:"os"`
	Profiles      []string `json:"profiles"`
	ControlsCount int      `json:"controls_count"`
	PDFPath       string   `json:"pdf_path"`
	YAMLPath      string   `json:"yaml_path"`
}

type Registry struct {
	mu        sync.RWMutex
	items     map[string]*audit.Benchmark
	lazyFiles map[string]string       // id -> yaml absolute or relative path
	stubs     map[string]*audit.Benchmark // id -> metadata stub for listing without loading all files into RAM
}

func New() *Registry {
	return &Registry{
		items:     map[string]*audit.Benchmark{},
		lazyFiles: map[string]string{},
		stubs:     map[string]*audit.Benchmark{},
	}
}

func (r *Registry) Register(bm *audit.Benchmark) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items[bm.ID] = bm
	r.stubs[bm.ID] = bm
}

// LoadCatalog reads benchmarks/catalog.json and registers lazy loaders for all companion benchmarks.
func (r *Registry) LoadCatalog(catalogPath string, rootDir string) (int, error) {
	data, err := os.ReadFile(catalogPath)
	if err != nil {
		return 0, err
	}

	var entries []CatalogEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return 0, fmt.Errorf("parse catalog.json: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	loaded := 0
	for _, entry := range entries {
		if entry.ID == "" || entry.YAMLPath == "" {
			continue
		}

		absYaml := entry.YAMLPath
		if !filepath.IsAbs(absYaml) && rootDir != "" {
			absYaml = filepath.Join(rootDir, entry.YAMLPath)
		}

		r.lazyFiles[entry.ID] = absYaml
		r.stubs[entry.ID] = &audit.Benchmark{
			ID:         entry.ID,
			Title:      entry.Title,
			Version:    entry.Version,
			Technology: entry.Technology,
			OS:         entry.OS,
		}
		loaded++
	}

	return loaded, nil
}

// Get returns the benchmark, loading it from disk on-demand if indexed lazily.
func (r *Registry) Get(id string) (*audit.Benchmark, bool) {
	r.mu.RLock()
	bm, ok := r.items[id]
	yamlPath, isLazy := r.lazyFiles[id]
	r.mu.RUnlock()

	if ok && len(bm.Controls) > 0 {
		return bm, true
	}

	if !isLazy {
		return nil, false
	}

	// Load from disk
	loadedBm, err := audit.Load(yamlPath)
	if err != nil {
		return nil, false
	}

	r.mu.Lock()
	r.items[id] = loadedBm
	r.stubs[id] = loadedBm
	r.mu.Unlock()

	return loadedBm, true
}

func (r *Registry) List() []*audit.Benchmark {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*audit.Benchmark, 0, len(r.stubs))
	for _, bm := range r.stubs {
		out = append(out, bm)
	}
	return out
}
