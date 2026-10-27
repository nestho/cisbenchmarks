package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/nestho/hardenx/platform/backend/internal/api"
	"github.com/nestho/hardenx/platform/backend/internal/app"
	"github.com/nestho/hardenx/platform/backend/internal/config"
)

func main() {
	cfg := config.Load()
	a := app.New()

	// Auto-discover benchmarks catalog
	catalogCandidates := []string{"benchmarks/catalog.json", "../../benchmarks/catalog.json", "../benchmarks/catalog.json"}
	for _, cand := range catalogCandidates {
		if _, err := os.Stat(cand); err == nil {
			rootDir := filepath.Dir(filepath.Dir(cand))
			if count, err := a.Registry.LoadCatalog(cand, rootDir); err == nil {
				log.Printf("Auto-discovered %d CIS benchmarks from %s", count, cand)
			}
			break
		}
	}

	r := api.NewRouter(a)
	log.Printf("HardenX backend listening on %s", cfg.Addr)
	if err := r.Run(cfg.Addr); err != nil {
		log.Fatal(err)
	}
}
