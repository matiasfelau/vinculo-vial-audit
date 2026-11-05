//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/matiasfelau/vinculo-vial-audit/internal/domain"
	"github.com/matiasfelau/vinculo-vial-audit/internal/manifest"
	"github.com/matiasfelau/vinculo-vial-audit/internal/repository/postgres"
	"github.com/matiasfelau/vinculo-vial-audit/internal/repository/postgres/postgrestest"
)

// Estas pruebas corren contra PostgreSQL real (DATABASE_URL) con:
//
//	go test -tags integration ./internal/repository/postgres/...
//
// Cada prueba usa su propio esquema, migrado con las migraciones reales.

var base = time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)

func newRecord(createdAt time.Time, retention time.Duration) domain.Record {
	return domain.Record{
		AlertID:        uuid.New(),
		AlertType:      domain.AlertTypeCrashed,
		AlertCreatedAt: createdAt,
		DNIEncAudit:    "ZG5p",
		PatEncAudit:    "cGF0",
		AuditKeyID:     "2026-11",
		Status:         domain.StatusRecorded,
		RecordedAt:     createdAt,
		DestroyAt:      createdAt.Add(retention),
	}
}

func newRepo(t *testing.T) (*postgres.AuditRepository, *gorm.DB) {
	t.Helper()
	db := postgrestest.New(t)
	return postgres.NewAuditRepository(db, postgres.WithQueryTimeout(5*time.Second)), db
}

func mustInsert(t *testing.T, repo *postgres.AuditRepository, record domain.Record) {
	t.Helper()
	inserted, err := repo.Insert(context.Background(), record)
	if err != nil || !inserted {
		t.Fatalf("no se pudo insertar el registro: inserted=%v err=%v", inserted, err)
	}
}

func TestMigrateCreaLaTablaYEsIdempotente(t *testing.T) {
	_, db := newRepo(t)

	if err := postgres.Migrate(db); err != nil {
		t.Fatalf("una segunda migración no debe fallar: %v", err)
	}

	var applied int64
	if err := db.Raw("SELECT count(*) FROM schema_migrations").Scan(&applied).Error; err != nil || applied != 1 {
		t.Fatalf("migraciones registradas = %d (err %v), esperaba 1", applied, err)
	}

	columns := map[string]string{}
	rows, err := db.Raw(`SELECT column_name, data_type || ':' || is_nullable || ':' || coalesce(character_maximum_length::text, '')
		FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'audit_records'`).Rows()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var name, spec string
		if err := rows.Scan(&name, &spec); err != nil {
			t.Fatal(err)
		}
		columns[name] = spec
	}

	want := map[string]string{
		"alert_id":         "uuid:NO:",
		"alert_type":       "character varying:NO:32",
		"alert_created_at": "timestamp with time zone:NO:",
		"dni_enc_audit":    "text:NO:",
		"pat_enc_audit":    "text:NO:",
		"audit_key_id":     "character varying:NO:32",
		"status":           "character varying:NO:16",
		"recorded_at":      "timestamp with time zone:NO:",
		"delivered_at":     "timestamp with time zone:YES:",
		"evidence":         "jsonb:YES:",
		"manifest_key":     "text:YES:",
		"manifest_sha256":  "character varying:YES:64",
		"destroy_at":       "timestamp with time zone:NO:",
		"judicial_hold":    "boolean:NO:",
	}
	for name, spec := range want {
		if columns[name] != spec {
			t.Errorf("columna %s = %q, esperaba %q", name, columns[name], spec)
		}
	}
	if len(columns) != len(want) {
		t.Errorf("la tabla tiene %d columnas, esperaba %d", len(columns), len(want))
	}

	for _, index := range []string{"idx_audit_records_alert_created_at", "idx_audit_records_destroy_at"} {
		var found int64
		db.Raw("SELECT count(*) FROM pg_indexes WHERE schemaname = current_schema() AND indexname = ?", index).Scan(&found)
		if found != 1 {
			t.Errorf("falta el índice %s", index)
		}
	}
}

func TestMigrateConcurrenteNoDuplicaNiFalla(t *testing.T) {
	_, db := newRepo(t)
	// Se vuelve a un esquema vacío para que las réplicas compitan por aplicar.
	if err := db.Exec("DROP TABLE audit_records; DROP TABLE schema_migrations; DROP FUNCTION audit_records_forbid_origin_update()").Error; err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = postgres.Migrate(db)
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("réplica %d: %v", i, err)
		}
	}
	var applied int64
	db.Raw("SELECT count(*) FROM schema_migrations").Scan(&applied)
	if applied != 1 {
		t.Errorf("migraciones registradas = %d, esperaba 1", applied)
	}
}

func TestInsertConOnConflictNoCambiaElRegistroExistente(t *testing.T) {
	repo, _ := newRepo(t)
	original := newRecord(base, time.Hour)
	mustInsert(t, repo, original)

	repetido := original
	repetido.DNIEncAudit = "b3Rybw=="
	repetido.AuditKeyID = "otra"
	inserted, err := repo.Insert(context.Background(), repetido)

	if err != nil {
		t.Fatalf("un insert repetido no debe fallar: %v", err)
	}
	if inserted {
		t.Error("un insert repetido no debe reportar una inserción")
	}
	got, err := repo.Get(context.Background(), original.AlertID)
	if err != nil {
		t.Fatal(err)
	}
	if got.DNIEncAudit != "ZG5p" || got.AuditKeyID != "2026-11" {
		t.Errorf("el registro cambió: %+v", got)
	}
}

func TestInsertYGetRedondeanLosDatos(t *testing.T) {
	repo, _ := newRepo(t)
	record := newRecord(base.Add(123456*time.Microsecond), 1095*24*time.Hour)
	mustInsert(t, repo, record)

	got, err := repo.Get(context.Background(), record.AlertID)

	if err != nil {
		t.Fatal(err)
	}
	if got.Status != domain.StatusRecorded || got.JudicialHold || got.DeliveredAt != nil || got.Evidence != nil || got.ManifestKey != nil {
		t.Errorf("valores iniciales incorrectos: %+v", got)
	}
	if !got.AlertCreatedAt.Equal(record.AlertCreatedAt) || !got.DestroyAt.Equal(record.DestroyAt) {
		t.Errorf("fechas = %v / %v, esperaba %v / %v", got.AlertCreatedAt, got.DestroyAt, record.AlertCreatedAt, record.DestroyAt)
	}
	if got.DNIEncAudit != record.DNIEncAudit || got.PatEncAudit != record.PatEncAudit {
		t.Error("los criptogramas deben guardarse tal como llegan")
	}
}

func TestGetInexistenteDevuelveErrRecordNotFound(t *testing.T) {
	repo, _ := newRepo(t)

	_, err := repo.Get(context.Background(), uuid.New())

	if !errors.Is(err, domain.ErrRecordNotFound) {
		t.Fatalf("esperaba ErrRecordNotFound, obtuvo %v", err)
	}
}

func delivery(id uuid.UUID) domain.Delivery {
	return domain.Delivery{
		DeliveredAt: base.Add(time.Minute),
		Evidence: []manifest.EvidenceItem{
			{Role: "GENERAL", Index: 0, Key: manifest.PhotoKey(id.String(), "GENERAL", 0), SHA256: strings.Repeat("a", 64)},
			{Role: "PLATE", Index: 0, Key: manifest.PhotoKey(id.String(), "PLATE", 0), SHA256: strings.Repeat("b", 64)},
		},
		ManifestKey:    manifest.ManifestKey(id.String()),
		ManifestSHA256: strings.Repeat("c", 64),
	}
}

func TestMarkDeliveredActualizaLaFilaYLaEvidencia(t *testing.T) {
	repo, _ := newRepo(t)
	record := newRecord(base, time.Hour)
	mustInsert(t, repo, record)

	updated, err := repo.MarkDelivered(context.Background(), record.AlertID, delivery(record.AlertID))

	if err != nil || !updated {
		t.Fatalf("updated=%v err=%v", updated, err)
	}
	got, _ := repo.Get(context.Background(), record.AlertID)
	if got.Status != domain.StatusDelivered || got.DeliveredAt == nil || !got.DeliveredAt.Equal(base.Add(time.Minute)) {
		t.Errorf("registro = %+v", got)
	}
	if len(got.Evidence) != 2 || got.Evidence[1].Role != "PLATE" || got.Evidence[0].SHA256 != strings.Repeat("a", 64) {
		t.Errorf("evidencia = %+v", got.Evidence)
	}
	if got.ManifestKey == nil || *got.ManifestKey != manifest.ManifestKey(record.AlertID.String()) || got.ManifestSHA256 == nil {
		t.Errorf("manifiesto = %v / %v", got.ManifestKey, got.ManifestSHA256)
	}
	if got.DNIEncAudit != record.DNIEncAudit || !got.DestroyAt.Equal(record.DestroyAt) {
		t.Error("la entrega no debe tocar los datos de origen")
	}
}

func TestMarkDeliveredSobreUnRegistroYaEntregadoNoHaceNada(t *testing.T) {
	repo, _ := newRepo(t)
	record := newRecord(base, time.Hour)
	mustInsert(t, repo, record)
	if _, err := repo.MarkDelivered(context.Background(), record.AlertID, delivery(record.AlertID)); err != nil {
		t.Fatal(err)
	}

	other := delivery(record.AlertID)
	other.ManifestSHA256 = strings.Repeat("d", 64)
	updated, err := repo.MarkDelivered(context.Background(), record.AlertID, other)

	if err != nil || updated {
		t.Fatalf("updated=%v err=%v, esperaba false sin error", updated, err)
	}
	got, _ := repo.Get(context.Background(), record.AlertID)
	if *got.ManifestSHA256 != strings.Repeat("c", 64) {
		t.Error("una segunda entrega no debe pisar la primera")
	}
}

func TestDeleteRecordedSoloBorraRegistrosRecorded(t *testing.T) {
	repo, _ := newRepo(t)
	pending, delivered := newRecord(base, time.Hour), newRecord(base, time.Hour)
	mustInsert(t, repo, pending)
	mustInsert(t, repo, delivered)
	if _, err := repo.MarkDelivered(context.Background(), delivered.AlertID, delivery(delivered.AlertID)); err != nil {
		t.Fatal(err)
	}

	deletedPending, err := repo.DeleteRecorded(context.Background(), pending.AlertID)
	if err != nil || !deletedPending {
		t.Fatalf("el RECORDED debía borrarse: %v, %v", deletedPending, err)
	}
	deletedDelivered, err := repo.DeleteRecorded(context.Background(), delivered.AlertID)
	if err != nil || deletedDelivered {
		t.Fatalf("un DELIVERED nunca se borra antes de su vencimiento: %v, %v", deletedDelivered, err)
	}

	if _, err := repo.Get(context.Background(), pending.AlertID); !errors.Is(err, domain.ErrRecordNotFound) {
		t.Error("el RECORDED sigue existiendo")
	}
	if _, err := repo.Get(context.Background(), delivered.AlertID); err != nil {
		t.Errorf("el DELIVERED desapareció: %v", err)
	}
}

func TestLosDatosDeOrigenSonInmutables(t *testing.T) {
	repo, db := newRepo(t)
	record := newRecord(base, time.Hour)
	mustInsert(t, repo, record)

	columnas := map[string]any{
		"dni_enc_audit":    "b3Rybw==",
		"pat_enc_audit":    "b3Rybw==",
		"audit_key_id":     "otra",
		"alert_type":       domain.AlertTypeParkedOnGarage,
		"alert_created_at": base.Add(time.Hour),
		"recorded_at":      base.Add(time.Hour),
		"destroy_at":       base.Add(24 * time.Hour),
	}
	for columna, valor := range columnas {
		t.Run(columna, func(t *testing.T) {
			err := db.Exec("UPDATE audit_records SET "+columna+" = ? WHERE alert_id = ?", valor, record.AlertID).Error

			if err == nil || !strings.Contains(err.Error(), "inmutables") {
				t.Fatalf("esperaba que el trigger rechace el cambio, obtuvo %v", err)
			}
		})
	}

	if err := db.Exec("UPDATE audit_records SET judicial_hold = true WHERE alert_id = ?", record.AlertID).Error; err != nil {
		t.Errorf("judicial_hold sí puede cambiar: %v", err)
	}
}

func TestElEstadoSoloAdmiteRecordedODelivered(t *testing.T) {
	repo, db := newRepo(t)
	record := newRecord(base, time.Hour)
	mustInsert(t, repo, record)

	if err := db.Exec("UPDATE audit_records SET status = 'ARCHIVED' WHERE alert_id = ?", record.AlertID).Error; err == nil {
		t.Fatal("el CHECK de status debía rechazar un estado desconocido")
	}
}

func TestListExpiredRespetaVencimientoRetencionJudicialCursorYLimite(t *testing.T) {
	repo, _ := newRepo(t)
	now := base.Add(48 * time.Hour)
	vencidos := make([]uuid.UUID, 0, 3)
	for i := 0; i < 3; i++ {
		r := newRecord(base, time.Hour)
		mustInsert(t, repo, r)
		vencidos = append(vencidos, r.AlertID)
	}
	vigente := newRecord(base, 72*time.Hour)
	mustInsert(t, repo, vigente)
	retenido := newRecord(base, time.Hour)
	mustInsert(t, repo, retenido)
	if found, err := repo.SetJudicialHold(context.Background(), retenido.AlertID, true); err != nil || !found {
		t.Fatalf("hold: %v, %v", found, err)
	}

	all, err := repo.ListExpired(context.Background(), now, uuid.Nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("vencidos = %d, esperaba 3 (sin el vigente ni el retenido)", len(all))
	}
	for _, id := range all {
		if id == vigente.AlertID || id == retenido.AlertID {
			t.Errorf("%s no debía listarse", id)
		}
	}

	page1, _ := repo.ListExpired(context.Background(), now, uuid.Nil, 2)
	page2, _ := repo.ListExpired(context.Background(), now, page1[len(page1)-1], 2)
	if len(page1) != 2 || len(page2) != 1 {
		t.Fatalf("páginas = %d y %d, esperaba 2 y 1", len(page1), len(page2))
	}
	seen := map[uuid.UUID]bool{}
	for _, id := range append(page1, page2...) {
		seen[id] = true
	}
	for _, id := range vencidos {
		if !seen[id] {
			t.Errorf("la paginación omitió %s", id)
		}
	}
}

func TestDeleteExpiredNoBorraVigentesNiRetenidos(t *testing.T) {
	repo, _ := newRepo(t)
	now := base.Add(48 * time.Hour)
	vencido, vigente, retenido := newRecord(base, time.Hour), newRecord(base, 72*time.Hour), newRecord(base, time.Hour)
	for _, r := range []domain.Record{vencido, vigente, retenido} {
		mustInsert(t, repo, r)
	}
	if _, err := repo.SetJudicialHold(context.Background(), retenido.AlertID, true); err != nil {
		t.Fatal(err)
	}

	for id, want := range map[uuid.UUID]bool{vencido.AlertID: true, vigente.AlertID: false, retenido.AlertID: false} {
		deleted, err := repo.DeleteExpired(context.Background(), id, now)
		if err != nil || deleted != want {
			t.Errorf("DeleteExpired(%s) = %v, %v; esperaba %v", id, deleted, err, want)
		}
	}
}

func TestSetJudicialHoldSobreRegistroInexistente(t *testing.T) {
	repo, _ := newRepo(t)

	found, err := repo.SetJudicialHold(context.Background(), uuid.New(), true)

	if err != nil || found {
		t.Fatalf("found=%v err=%v, esperaba false sin error", found, err)
	}
}

func TestListForExportPorAlertIDYPorRango(t *testing.T) {
	repo, _ := newRepo(t)
	first, second, third := newRecord(base, time.Hour), newRecord(base.Add(24*time.Hour), time.Hour), newRecord(base.Add(48*time.Hour), time.Hour)
	for _, r := range []domain.Record{first, second, third} {
		mustInsert(t, repo, r)
	}

	byID, err := repo.ListForExport(context.Background(), domain.ExportFilter{AlertID: &second.AlertID})
	if err != nil || len(byID) != 1 || byID[0].AlertID != second.AlertID {
		t.Fatalf("por alert_id: %+v, %v", byID, err)
	}

	byRange, err := repo.ListForExport(context.Background(), domain.ExportFilter{From: base, To: base.Add(24 * time.Hour)})
	if err != nil || len(byRange) != 2 {
		t.Fatalf("por rango: %d registros, %v; esperaba 2 (extremos incluidos)", len(byRange), err)
	}
	if byRange[0].AlertID != first.AlertID || byRange[1].AlertID != second.AlertID {
		t.Error("el rango debe ordenarse por alert_created_at")
	}

	if _, err := repo.ListForExport(context.Background(), domain.ExportFilter{}); err == nil {
		t.Error("un filtro vacío no debe exportar toda la tabla")
	}
}

func TestLaConsultaQueExcedeSuPlazoEsIndisponibilidad(t *testing.T) {
	repo, _ := newRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()

	_, err := repo.Get(ctx, uuid.New())

	if !errors.Is(err, domain.ErrRepositoryUnavailable) {
		t.Fatalf("esperaba ErrRepositoryUnavailable, obtuvo %v", err)
	}
}

func TestPing(t *testing.T) {
	repo, _ := newRepo(t)

	if err := repo.Ping(context.Background()); err != nil {
		t.Fatalf("la base responde: %v", err)
	}
}
