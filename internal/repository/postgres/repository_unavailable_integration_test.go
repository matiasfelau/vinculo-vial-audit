//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-audit/internal/domain"
	"github.com/matiasfelau/vinculo-vial-audit/internal/repository/postgres"
	"github.com/matiasfelau/vinculo-vial-audit/internal/repository/postgres/postgrestest"
)

// contextoVencido devuelve un contexto cuyo deadline ya pasó. Es determinista:
// un WithTimeout de 1 ns puede no haber vencido todavía cuando se lo evalúa.
func contextoVencido(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Hour))
	t.Cleanup(cancel)
	return ctx
}

// Con el plazo de consulta vencido, toda operación tiene que informar
// ErrRepositoryUnavailable: los consumidores lo reintentan por .retry en vez de
// mandar el mensaje a la .dlq.
func TestTodaOperacionConPlazoVencidoEsIndisponibilidad(t *testing.T) {
	db := postgrestest.New(t)
	repo := postgres.NewAuditRepository(db, postgres.WithQueryTimeout(5*time.Second))
	ctx := contextoVencido(t)
	id := uuid.New()
	ahora := time.Now().UTC()

	operaciones := []struct {
		nombre string
		run    func() error
	}{
		{"Insert", func() error { _, err := repo.Insert(ctx, newRecord(ahora, time.Hour)); return err }},
		{"Get", func() error { _, err := repo.Get(ctx, id); return err }},
		{"MarkDelivered", func() error { _, err := repo.MarkDelivered(ctx, id, delivery(id)); return err }},
		{"DiscardRecorded", func() error { _, err := repo.DiscardRecorded(ctx, id, ahora); return err }},
		{"HasTombstone", func() error { _, err := repo.HasTombstone(ctx, id); return err }},
		{"DeleteTombstonesBefore", func() error { _, err := repo.DeleteTombstonesBefore(ctx, ahora); return err }},
		{"ListExpired", func() error { _, err := repo.ListExpired(ctx, ahora, uuid.Nil, 10); return err }},
		{"DeleteExpired", func() error { _, err := repo.DeleteExpired(ctx, id, ahora); return err }},
		{"ListForExport", func() error {
			_, err := repo.ListForExport(ctx, domain.ExportFilter{AlertID: &id})
			return err
		}},
		{"SetJudicialHold", func() error { _, err := repo.SetJudicialHold(ctx, id, true); return err }},
	}

	for _, op := range operaciones {
		t.Run(op.nombre, func(t *testing.T) {
			if err := op.run(); !errors.Is(err, domain.ErrRepositoryUnavailable) {
				t.Errorf("%s con el plazo vencido devolvió %v, esperaba ErrRepositoryUnavailable", op.nombre, err)
			}
		})
	}
}

// Ping solo se compara contra nil (/ready y /health/deps), así que con el plazo
// vencido basta con que falle.
func TestPingConPlazoVencidoFalla(t *testing.T) {
	db := postgrestest.New(t)
	repo := postgres.NewAuditRepository(db, postgres.WithQueryTimeout(5*time.Second))

	if err := repo.Ping(contextoVencido(t)); err == nil {
		t.Error("Ping no falló con el plazo vencido")
	}
}

// Una fila con la evidencia corrupta nunca se devuelve a medias: la lectura y la
// exportación fallan en vez de entregar un registro sin sus fotos.
func TestUnaFilaConEvidenciaIlegibleSeRechazaEnLecturaYExportacion(t *testing.T) {
	repo, db := newRepo(t)
	registro := newRecord(base, time.Hour)
	mustInsert(t, repo, registro)
	// Es JSON válido (la columna es jsonb) pero no es una lista de ítems.
	if err := db.Exec(`UPDATE audit_records SET evidence = '{"no":"es una lista"}'::jsonb WHERE alert_id = ?`, registro.AlertID).Error; err != nil {
		t.Fatal(err)
	}

	if _, err := repo.Get(context.Background(), registro.AlertID); err == nil {
		t.Error("Get devolvió un registro con evidencia ilegible")
	}
	_, err := repo.ListForExport(context.Background(), domain.ExportFilter{AlertID: &registro.AlertID})
	if err == nil {
		t.Fatal("ListForExport devolvió un registro con evidencia ilegible")
	}
	if errors.Is(err, domain.ErrRepositoryUnavailable) {
		t.Error("una fila ilegible no es indisponibilidad de la base: no debe reintentarse")
	}
}

func TestMigrateSobreUnaBaseCerradaFalla(t *testing.T) {
	db := postgrestest.New(t)
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatal(err)
	}

	if err := postgres.Migrate(db); err == nil {
		t.Error("Migrate no falló con la base cerrada")
	}
}

func TestPingConLaBaseCerradaFalla(t *testing.T) {
	repo, db := newRepo(t)
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatal(err)
	}

	if err := repo.Ping(context.Background()); err == nil {
		t.Error("Ping no falló con la base cerrada")
	}
}
