package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/nestho/hardenx/platform/backend/internal/app"
	"github.com/nestho/hardenx/platform/backend/internal/audit"
	"github.com/nestho/hardenx/platform/backend/internal/connector"
	"github.com/nestho/hardenx/platform/backend/internal/remediation"
	"github.com/nestho/hardenx/platform/backend/internal/reporting"
	"github.com/nestho/hardenx/platform/backend/internal/runner"
	"github.com/nestho/hardenx/platform/backend/internal/scans"
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
	r.GET("/api/v1/scans/:id/remediation/:format", func(c *gin.Context) { getRemediation(c, a) })

	// Serve frontend SPA if built
	frontendCandidates := []string{
		"platform/frontend/dist",
		"../frontend/dist",
		"../../platform/frontend/dist",
	}
	for _, dir := range frontendCandidates {
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			r.Static("/assets", filepath.Join(dir, "assets"))
			r.StaticFile("/", filepath.Join(dir, "index.html"))
			r.NoRoute(func(c *gin.Context) {
				if !strings.HasPrefix(c.Request.URL.Path, "/api/") {
					c.File(filepath.Join(dir, "index.html"))
				}
			})
			break
		}
	}

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
		} else if proto == "postgres" || proto == "postgresql" || targetType == "postgres" || targetType == "postgresql" {
			dbCfg := connector.DBConfig{
				Type:     connector.DBPostgreSQL,
				Host:     str(req.Asset, "host"),
				Port:     intFrom(req.Asset, "port"),
				User:     str(req.Asset, "user"),
				Password: str(req.Asset, "password"),
				Database: str(req.Asset, "database"),
				SSLMode:  str(req.Asset, "sslmode"),
			}
			conn, err = connector.NewSQLConnector(dbCfg)
		} else if proto == "mysql" || proto == "mariadb" || targetType == "mysql" || targetType == "mariadb" {
			dbCfg := connector.DBConfig{
				Type:     connector.DBMySQL,
				Host:     str(req.Asset, "host"),
				Port:     intFrom(req.Asset, "port"),
				User:     str(req.Asset, "user"),
				Password: str(req.Asset, "password"),
				Database: str(req.Asset, "database"),
			}
			conn, err = connector.NewSQLConnector(dbCfg)
		} else if proto == "mssql" || proto == "sqlserver" || targetType == "mssql" || targetType == "sqlserver" {
			dbCfg := connector.DBConfig{
				Type:     connector.DBMSSQL,
				Host:     str(req.Asset, "host"),
				Port:     intFrom(req.Asset, "port"),
				User:     str(req.Asset, "user"),
				Password: str(req.Asset, "password"),
				Database: str(req.Asset, "database"),
				SSLMode:  str(req.Asset, "sslmode"),
			}
			conn, err = connector.NewSQLConnector(dbCfg)
		} else if proto == "mongo" || proto == "mongodb" || targetType == "mongo" || targetType == "mongodb" {
			mongoCfg := connector.MongoConfig{
				Host:     str(req.Asset, "host"),
				Port:     intFrom(req.Asset, "port"),
				User:     str(req.Asset, "user"),
				Password: str(req.Asset, "password"),
				Database: str(req.Asset, "database"),
				AuthDB:   str(req.Asset, "authdb"),
			}
			conn, err = connector.NewMongoConnector(mongoCfg)
		} else if proto == "network" || proto == "cisco" || proto == "fortios" || proto == "panos" || proto == "junos" || targetType == "network" {
			port := intFrom(req.Asset, "port")
			if port == 0 {
				port = 22
			}
			devType := connector.DeviceGeneric
			if proto == "cisco" || strings.Contains(strings.ToLower(str(req.Asset, "os")), "cisco") {
				devType = connector.DeviceCiscoIOS
			} else if proto == "fortios" {
				devType = connector.DeviceFortiOS
			} else if proto == "panos" {
				devType = connector.DevicePanOS
			} else if proto == "junos" {
				devType = connector.DeviceJunOS
			}
			netCfg := connector.NetworkSSHConfig{
				Host:       str(req.Asset, "host"),
				Port:       port,
				User:       str(req.Asset, "user"),
				Password:   str(req.Asset, "password"),
				KeyPath:    str(req.Asset, "key_path"),
				DeviceType: devType,
			}
			conn, err = connector.NewNetworkSSH(netCfg)
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

func getRemediation(c *gin.Context, a *app.App) {
	id := c.Param("id")
	format := strings.ToLower(c.Param("format"))
	job, ok := a.Scans.Get(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "scan job not found"})
		return
	}
	bm, _ := a.Registry.Get(job.BenchmarkID)

	switch format {
	case "ansible", "yml", "yaml":
		content := remediation.GenerateAnsiblePlaybook(job, bm)
		c.Header("Content-Disposition", "attachment; filename=remediation_"+id+".yml")
		c.Data(http.StatusOK, "text/yaml; charset=utf-8", []byte(content))
	case "powershell", "ps1":
		content := remediation.GeneratePowerShellScript(job, bm)
		c.Header("Content-Disposition", "attachment; filename=remediation_"+id+".ps1")
		c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(content))
	case "bash", "sh":
		content := remediation.GenerateBashScript(job, bm)
		c.Header("Content-Disposition", "attachment; filename=remediation_"+id+".sh")
		c.Data(http.StatusOK, "text/x-shellscript; charset=utf-8", []byte(content))
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported format. Use ansible, powershell, or bash"})
	}
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

