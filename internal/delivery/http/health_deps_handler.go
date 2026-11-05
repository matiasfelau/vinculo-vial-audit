package http

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	depUp   = "up"
	depDown = "down"
)

// DependencyCheck es una dependencia que /health/deps reporta bajo su nombre: la
// base, el consumidor de cada cola o el circuito de cada bucket de S3.
type DependencyCheck struct {
	Name    string
	Healthy func(ctx context.Context) bool
}

// DepsHealthHandler expone GET /health/deps: 200 con status "ok" si todas las
// dependencias están arriba, y 503 con status "degraded" si alguna no. Reporta
// solo el nombre y el estado de cada dependencia, sin detalles internos. No
// interviene en /ready.
func DepsHealthHandler(checks ...DependencyCheck) gin.HandlerFunc {
	return func(c *gin.Context) {
		deps := gin.H{}
		var caidas []string

		for _, check := range checks {
			if check.Healthy(c.Request.Context()) {
				deps[check.Name] = depUp
				continue
			}
			deps[check.Name] = depDown
			caidas = append(caidas, check.Name+" no disponible")
		}

		body := gin.H{"status": "ok", "deps": deps}
		if len(caidas) > 0 {
			body["status"] = "degraded"
			body["error"] = strings.Join(caidas, "; ")
			c.JSON(http.StatusServiceUnavailable, body)
			return
		}

		c.JSON(http.StatusOK, body)
	}
}
