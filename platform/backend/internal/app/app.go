package app

import (
	"github.com/nestho/hardenx/platform/backend/internal/registry"
	"github.com/nestho/hardenx/platform/backend/internal/scans"
)

type App struct {
	Registry *registry.Registry
	Scans    *scans.Store
}

func New() *App {
	return &App{Registry: registry.New(), Scans: scans.NewStore()}
}