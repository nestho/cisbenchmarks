package main

import (
	"log"

	"github.com/nestho/hardenx/platform/backend/internal/api"
	"github.com/nestho/hardenx/platform/backend/internal/app"
	"github.com/nestho/hardenx/platform/backend/internal/config"
)

func main() {
	cfg := config.Load()
	a := app.New()
	r := api.NewRouter(a)
	log.Printf("OpenCompliance listening on %s", cfg.Addr)
	if err := r.Run(cfg.Addr); err != nil {
		log.Fatal(err)
	}
}
