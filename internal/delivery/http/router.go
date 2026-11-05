// Package http expone la única superficie HTTP de Audit: /health, /ready y
// /health/deps, en un puerto que no se publica fuera de la red de Docker. Audit
// no tiene endpoints de negocio.
package http

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Pingable define el contrato para verificar la disponibilidad de la base propia.
type Pingable interface {
	Ping(ctx context.Context) error
}

// NewRouter construye el motor Gin con las rutas de salud. checks son las
// dependencias que /health/deps reporta.
func NewRouter(db Pingable, checks ...DependencyCheck) *gin.Engine {
	engine := gin.New()
	engine.Use(gin.Recovery())

	engine.GET("/health", healthCheck)
	engine.GET("/ready", readyCheck(db))
	engine.GET("/health/deps", DepsHealthHandler(checks...))

	return engine
}

func healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func readyCheck(db Pingable) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := db.Ping(c.Request.Context()); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "error", "detail": "base de datos inalcanzable"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
}
