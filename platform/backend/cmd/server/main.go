package main

import (
	"log"

	"github.com/nestho/cisbenchmarks/platform/backend/internal/api"
	"github.com/nestho/cisbenchmarks/platform/backend/internal/config"
)

func main() {
	cfg := config.Load()
	r := api.NewRouter(cfg)
	log.Printf("OpenCompliance listening on %s", cfg.Addr)
	if err := r.Run(cfg.Addr); err != nil {
		log.Fatal(err)
	}
}
