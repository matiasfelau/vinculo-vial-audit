//go:build integration

package main

import (
	"context"
	"testing"

	"github.com/matiasfelau/vinculo-vial-audit/internal/repository/postgres/postgrestest"
)

// El cliente de S3 se construye sin red: buildServices solo necesita una base real.
func TestBuildServicesArmaExportadorYHolderConLaBaseConfigurada(t *testing.T) {
	db := postgrestest.New(t)
	entornoCLI(t, postgrestest.DSN(t, postgrestest.Schema(t, db)), "audit-test")

	services, closeDB, err := buildServices(context.Background())
	if err != nil {
		t.Fatalf("buildServices falló con un entorno válido: %v", err)
	}
	if services.Exporter == nil || services.Holder == nil {
		t.Fatalf("faltan servicios: %+v", services)
	}
	if closeDB == nil {
		t.Fatal("no devolvió la función que cierra el pool de la base")
	}
	closeDB()
}
