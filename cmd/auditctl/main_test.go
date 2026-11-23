package main

import (
	"context"
	"strings"
	"testing"
)

// entornoCLI fija las variables que lee config.LoadCLI. Con dsn vacío la base
// queda sin configurar.
func entornoCLI(t *testing.T, dsn, bucket string) {
	t.Helper()
	t.Setenv("DATABASE_URL", dsn)
	t.Setenv("AUDIT_BUCKET", bucket)
	t.Setenv("S3_REGION", "us-east-1")
}

func TestBuildServicesRechazaUnEntornoIncompleto(t *testing.T) {
	casos := []struct {
		nombre, dsn, bucket, faltante string
	}{
		{"sin base", "", "audit-test", "DATABASE_URL"},
		{"sin bucket de Audit", "postgres://audit@127.0.0.1:1/audit", "", "AUDIT_BUCKET"},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			entornoCLI(t, c.dsn, c.bucket)

			services, closeDB, err := buildServices(context.Background())

			if err == nil {
				t.Fatal("buildServices devolvió nil con el entorno incompleto")
			}
			if !strings.Contains(err.Error(), c.faltante) {
				t.Errorf("el error %q no nombra la variable faltante %s", err, c.faltante)
			}
			if closeDB != nil || services.Exporter != nil || services.Holder != nil {
				t.Error("con error no debe devolver servicios ni función de cierre")
			}
		})
	}
}

func TestBuildServicesFallaSiLaBaseNoEsAlcanzableYNoFiltraLaContrasena(t *testing.T) {
	const password = "clave-que-no-debe-aparecer"
	entornoCLI(t, "postgres://audit:"+password+"@127.0.0.1:1/audit?sslmode=disable&connect_timeout=1", "audit-test")

	services, closeDB, err := buildServices(context.Background())

	if err == nil {
		t.Fatal("buildServices devolvió nil con la base inalcanzable")
	}
	if strings.Contains(err.Error(), password) {
		t.Errorf("el error filtra la contraseña de la base: %v", err)
	}
	if closeDB != nil || services.Exporter != nil || services.Holder != nil {
		t.Error("con error no debe devolver servicios ni función de cierre")
	}
}
