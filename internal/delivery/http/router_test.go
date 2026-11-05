package http

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

type fakePingable struct{ err error }

func (f fakePingable) Ping(context.Context) error { return f.err }

func up(context.Context) bool   { return true }
func down(context.Context) bool { return false }

func get(t *testing.T, router *gin.Engine, path string) (int, map[string]any) {
	t.Helper()

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("el cuerpo no es JSON: %v (%s)", err, rec.Body.String())
	}
	return rec.Code, body
}

func TestHealthResponde200(t *testing.T) {
	gin.SetMode(gin.TestMode)

	code, body := get(t, NewRouter(fakePingable{}), "/health")

	if code != http.StatusOK || body["status"] != "ok" {
		t.Fatalf("code = %d, body = %v", code, body)
	}
}

func TestReadyDependeDeLaBase(t *testing.T) {
	gin.SetMode(gin.TestMode)

	code, _ := get(t, NewRouter(fakePingable{}), "/ready")
	if code != http.StatusOK {
		t.Errorf("con la base arriba: code = %d", code)
	}

	code, body := get(t, NewRouter(fakePingable{err: errors.New("conexión rechazada a 10.0.0.5")}), "/ready")
	if code != http.StatusServiceUnavailable {
		t.Errorf("con la base caída: code = %d", code)
	}
	if detail, _ := body["detail"].(string); strings.Contains(detail, "10.0.0.5") {
		t.Errorf("la respuesta no debe exponer detalles internos: %v", body)
	}
}

func TestDepsHealthTodasArribaResponde200(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := NewRouter(fakePingable{},
		DependencyCheck{Name: "database", Healthy: up},
		DependencyCheck{Name: "recorded_consumer", Healthy: up},
		DependencyCheck{Name: "audit_bucket", Healthy: up},
	)

	code, body := get(t, router, "/health/deps")

	if code != http.StatusOK || body["status"] != "ok" {
		t.Fatalf("code = %d, body = %v", code, body)
	}
	deps := body["deps"].(map[string]any)
	if deps["database"] != "up" || deps["recorded_consumer"] != "up" || deps["audit_bucket"] != "up" {
		t.Errorf("deps = %v", deps)
	}
}

func TestDepsHealthConUnaCaidaResponde503Degraded(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := NewRouter(fakePingable{},
		DependencyCheck{Name: "database", Healthy: up},
		DependencyCheck{Name: "delivered_consumer", Healthy: down},
		DependencyCheck{Name: "evidence_bucket", Healthy: down},
	)

	code, body := get(t, router, "/health/deps")

	if code != http.StatusServiceUnavailable || body["status"] != "degraded" {
		t.Fatalf("code = %d, body = %v", code, body)
	}
	deps := body["deps"].(map[string]any)
	if deps["delivered_consumer"] != "down" || deps["evidence_bucket"] != "down" || deps["database"] != "up" {
		t.Errorf("deps = %v", deps)
	}
	detail, _ := body["error"].(string)
	if !strings.Contains(detail, "delivered_consumer") || !strings.Contains(detail, "evidence_bucket") {
		t.Errorf("error = %q", detail)
	}
}

func TestSoloExponeLasRutasDeSalud(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := NewRouter(fakePingable{})

	for _, path := range []string{"/api/v1/alerts", "/internal/audit", "/records", "/metrics"} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: code = %d, Audit no tiene superficie más allá de /health y /ready", path, rec.Code)
		}
	}
}
