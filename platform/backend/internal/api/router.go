package api

import (
	"github.com/gin-gonic/gin"
)

func NewRouter(cfg interface{}) *gin.Engine {
	r := gin.Default()
	r.GET("/health", Health)
	r.GET("/api/v1/benchmarks", ListBenchmarks)
	return r
}
