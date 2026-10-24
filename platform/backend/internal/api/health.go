package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "opencompliance"})
}

func ListBenchmarks(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"data": []interface{}{}})
}
