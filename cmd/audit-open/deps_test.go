package main

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// forbiddenDeps son los paquetes que audit-open no puede importar, directa ni
// transitivamente: red, base de datos, AWS y broker. audit-open corre fuera de
// línea con la clave privada en memoria; ninguna dependencia puede abrir un
// socket.
var forbiddenDeps = []string{
	"net",
	"net/",
	"database/",
	"crypto/tls",
	"github.com/aws/",
	"github.com/jackc/",
	"github.com/rabbitmq/",
	"github.com/gin-gonic/",
	"gorm.io/",
	"github.com/google/uuid",
}

func goBinary() string {
	if path, err := exec.LookPath("go"); err == nil {
		return path
	}
	return filepath.Join(runtime.GOROOT(), "bin", "go")
}

func TestAuditOpenNoImportaRedBaseDeDatosNiAWS(t *testing.T) {
	cmd := exec.Command(goBinary(), "list", "-deps", ".")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps falló: %v\n%s", err, output)
	}

	deps := strings.Fields(string(output))
	if len(deps) == 0 {
		t.Fatal("go list -deps no devolvió dependencias")
	}

	for _, dep := range deps {
		for _, forbidden := range forbiddenDeps {
			if dep == forbidden || (strings.HasSuffix(forbidden, "/") && strings.HasPrefix(dep, forbidden)) {
				t.Errorf("audit-open depende de %s (prohibido: %s)", dep, forbidden)
			}
		}
	}
}
