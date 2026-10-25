package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/nestho/cisbenchmarks/platform/backend/internal/app"
	"github.com/nestho/cisbenchmarks/platform/backend/internal/audit"
	"github.com/nestho/cisbenchmarks/platform/backend/internal/connector"
	"github.com/nestho/cisbenchmarks/platform/backend/internal/reporting"
	"github.com/nestho/cisbenchmarks/platform/backend/internal/runner"
	"github.com/nestho/cisbenchmarks/platform/backend/internal/scans"
)

func NewRouter(a *app.App) *gin.Engine {
	r := gin.Default()
	r.GET("/health", Health)
	r.GET("/api/v1/benchmarks", func(c *gin.Context) { listBenchmarks(c, a) })
	r.GET("/api/v1/benchmarks/:id", func(c *gin.Context) { getBenchmark(c, a) })
	r.POST("/api/v1/benchmarks", func(c *gin.Context) { uploadBenchmark(c, a) })
	r.POST("/api/v1/scans", func(c *gin.Context) { createScan(c, a) })
	r.GET("/api/v1/scans", func(c *gin.Context) { listScans(c, a) })
	r.GET("/api/v1/scans/:id", func(c *gin.Context) { getScan(c, a) })
	r.GET("/api/v1/scans/:id/report", func(c *gin.Context) { getReport(c, a) })
	return r
}

func Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "opencompliance"})
}

func listBenchmarks(c *gin.Context, a *app.App) {
	out := a.Registry.List()
	c.JSON(http.StatusOK, gin.H{"data": out})
}

func getBenchmark(c *gin.Context, a *app.App) {
	id := c.Param("id")
	bm, ok := a.Registry.Get(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, bm)
}

func uploadBenchmark(c *gin.Context, a *app.App) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	tmp := filepath.Join(os.TempDir(), file.Filename)
	if err := c.SaveUploadedFile(file, tmp); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer os.Remove(tmp)

	var bm *audit.Benchmark
	if ext := filepath.Ext(file.Filename); ext == ".yaml" || ext == ".yml" {
		bm, err = audit.Load(tmp)
	} else {
		bm, err = audit.LoadNessus(tmp)
	}
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	a.Registry.Register(bm)
	c.JSON(http.StatusCreated, bm)
}

type scanRequest struct {
	BenchmarkID string         `json:"benchmark_id"`
	Profile     string         `json:"profile"`
	Asset       map[string]any `json:"asset"`
}

func createScan(c *gin.Context, a *app.App) {
	var req scanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	bm, ok := a.Registry.Get(req.BenchmarkID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "benchmark not found"})
		return
	}
	if req.Profile == "" {
		req.Profile = "level1"
	}
	id := uuid.New().String()
	job := &scans.Job{
		ID:          id,
		BenchmarkID: req.BenchmarkID,
		Profile:     req.Profile,
		Status:      "running",
		Asset:       req.Asset,
		CreatedAt:   time.Now(),
	}
	a.Scans.Create(job)

	go func() {
		var conn connector.Connector
		var err error
		proto := strings.ToLower(str(req.Asset, "protocol"))
		targetType := strings.ToLower(str(req.Asset, "type"))

		if proto == "winrm" || targetType == "windows" {
			port := intFrom(req.Asset, "port")
			https := boolFrom(req.Asset, "https")
			if port == 0 {
				if https {
					port = 5986
				} else {
					port = 5985
				}
			}
			winCfg := connector.WinRMConfig{
				Host:     str(req.Asset, "host"),
				Port:     port,
				User:     str(req.Asset, "user"),
				Password: str(req.Asset, "password"),
				HTTPS:    https,
				Insecure: boolFrom(req.Asset, "insecure"),
			}
			conn, err = connector.NewWinRM(winCfg)
		} else {
			port := intFrom(req.Asset, "port")
			if port == 0 {
				port = 22
			}
			cfg := connector.SSHConfig{
				Host:     str(req.Asset, "host"),
				Port:     port,
				User:     str(req.Asset, "user"),
				Password: str(req.Asset, "password"),
				KeyPath:  str(req.Asset, "key_path"),
			}
			conn, err = connector.NewSSH(cfg)
		}

		if err != nil {
			a.Scans.Update(id, func(j *scans.Job) {
				j.Status = "error"
				j.Results = []runner.Result{{Status: "error", Error: err.Error()}}
				t := time.Now()
				j.FinishedAt = &t
			})
			return
		}
		defer conn.Close()
		rn := runner.New(conn)
		results := rn.Run(c.Request.Context(), bm)
		a.Scans.Update(id, func(j *scans.Job) {
			j.Status = "completed"
			j.Results = results
			t := time.Now()
			j.FinishedAt = &t
		})
	}()

	c.JSON(http.StatusAccepted, gin.H{"id": id, "status": "running"})
}

func listScans(c *gin.Context, a *app.App) {
	c.JSON(http.StatusOK, gin.H{"data": a.Scans.List()})
}

func getScan(c *gin.Context, a *app.App) {
	id := c.Param("id")
	job, ok := a.Scans.Get(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, job)
}

func getReport(c *gin.Context, a *app.App) {
	id := c.Param("id")
	job, ok := a.Scans.Get(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	html, err := reporting.RenderHTML(job)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
}

func str(m map[string]any, k string) string {
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func intFrom(m map[string]any, k string) int {
	if v, ok := m[k]; ok {
		switch x := v.(type) {
		case float64:
			return int(x)
		case int:
			return x
		}
	}
	return 0
}

func boolFrom(m map[string]any, k string) bool {
	if v, ok := m[k]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

