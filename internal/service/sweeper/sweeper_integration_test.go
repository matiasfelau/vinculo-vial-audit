//go:build integration

package sweeper_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-audit/internal/domain"
	"github.com/matiasfelau/vinculo-vial-audit/internal/manifest"
	"github.com/matiasfelau/vinculo-vial-audit/internal/repository/postgres"
	"github.com/matiasfelau/vinculo-vial-audit/internal/repository/postgres/postgrestest"
	"github.com/matiasfelau/vinculo-vial-audit/internal/service/hold"
	"github.com/matiasfelau/vinculo-vial-audit/internal/service/sweeper"
	"github.com/matiasfelau/vinculo-vial-audit/internal/testsupport"
)

// Sweeper contra PostgreSQL real y un reloj simulado: el tiempo avanza sin esperar.
// Los objetos viven en un bucket en memoria que respeta la retención con el mismo reloj.

const (
	integrationRetention          = 24 * time.Hour
	integrationTombstoneRetention = 7 * 24 * time.Hour
)

var integrationBase = time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)

type simulation struct {
	repo    *postgres.AuditRepository
	objects *testsupport.MemoryObjects
	now     time.Time
}

func newSimulation(t *testing.T) *simulation {
	t.Helper()

	sim := &simulation{
		repo:    postgres.NewAuditRepository(postgrestest.New(t), postgres.WithQueryTimeout(5*time.Second)),
		objects: testsupport.NewMemoryObjects(),
		now:     integrationBase,
	}
	sim.objects.Now = func() time.Time { return sim.now }
	return sim
}

func (s *simulation) sweeper(batch int) *sweeper.Sweeper {
	return sweeper.New(s.repo, s.objects, batch, integrationTombstoneRetention, sweeper.WithClock(func() time.Time { return s.now }))
}

// add crea un registro de la alerta creada en integrationBase, con sus objetos
// bloqueados hasta destroy_at si está entregado.
func (s *simulation) add(t *testing.T, delivered bool) uuid.UUID {
	t.Helper()

	id := uuid.New()
	record := domain.Record{
		AlertID: id, AlertType: domain.AlertTypeCrashed, AlertCreatedAt: integrationBase,
		DNIEncAudit: "ZG5p", PatEncAudit: "cGF0", AuditKeyID: "2026-11",
		Status: domain.StatusRecorded, RecordedAt: integrationBase, DestroyAt: integrationBase.Add(integrationRetention),
	}
	if result, err := s.repo.Insert(context.Background(), record); err != nil || result != domain.InsertCreated {
		t.Fatalf("insert: %v, %v", result, err)
	}
	if !delivered {
		return id
	}

	items := []manifest.EvidenceItem{{Role: "GENERAL", Index: 0, Key: manifest.PhotoKey(id.String(), "GENERAL", 0), SHA256: "a"}}
	if _, err := s.repo.MarkDelivered(context.Background(), id, domain.Delivery{
		DeliveredAt: integrationBase, Evidence: items, ManifestKey: manifest.ManifestKey(id.String()), ManifestSHA256: "b",
	}); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{items[0].Key, manifest.ManifestKey(id.String())} {
		if err := s.objects.PutLocked(context.Background(), key, []byte("x"), "t", record.DestroyAt); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

func (s *simulation) exists(t *testing.T, id uuid.UUID) bool {
	t.Helper()
	_, err := s.repo.Get(context.Background(), id)
	return err == nil
}

func (s *simulation) objectsOf(id uuid.UUID) int {
	return len(s.objects.Versions(manifest.ManifestKey(id.String())))
}

func TestSweeperConRelojSimuladoDestruyeSoloAlVencer(t *testing.T) {
	sim := newSimulation(t)
	id := sim.add(t, true)

	sim.now = integrationBase.Add(integrationRetention - time.Second)
	result, err := sim.sweeper(10).RunOnce(context.Background())
	if err != nil || result.Destroyed != 0 || !sim.exists(t, id) || sim.objectsOf(id) == 0 {
		t.Fatalf("antes de destroy_at no se destruye nada: %+v, %v", result, err)
	}

	sim.now = integrationBase.Add(integrationRetention)
	result, err = sim.sweeper(10).RunOnce(context.Background())
	if err != nil || result.Destroyed != 1 {
		t.Fatalf("en destroy_at debe destruirse: %+v, %v", result, err)
	}
	if sim.exists(t, id) || sim.objectsOf(id) != 0 {
		t.Error("la fila y los objetos debían destruirse")
	}
}

func TestSweeperNoBorraConRetencionJudicialYLoRetomaAlLevantarla(t *testing.T) {
	sim := newSimulation(t)
	id := sim.add(t, true)
	holder := hold.New(sim.repo, sim.objects)
	if _, err := holder.Hold(context.Background(), id, true); err != nil {
		t.Fatalf("hold -on: %v", err)
	}

	sim.now = integrationBase.Add(integrationRetention + 24*time.Hour)
	result, err := sim.sweeper(10).RunOnce(context.Background())
	if err != nil || result.Destroyed != 0 {
		t.Fatalf("con retención judicial no se destruye: %+v, %v", result, err)
	}
	if !sim.exists(t, id) || sim.objectsOf(id) == 0 {
		t.Fatal("el registro retenido debe conservarse con sus objetos")
	}

	if _, err := holder.Hold(context.Background(), id, false); err != nil {
		t.Fatalf("hold -off: %v", err)
	}
	result, err = sim.sweeper(10).RunOnce(context.Background())
	if err != nil || result.Destroyed != 1 || sim.exists(t, id) {
		t.Fatalf("sin retención judicial el registro vencido se destruye: %+v, %v", result, err)
	}
}

func TestSweeperDestruyeRegistrosRecordedHuerfanos(t *testing.T) {
	sim := newSimulation(t)
	orphan := sim.add(t, false)

	sim.now = integrationBase.Add(integrationRetention)
	result, err := sim.sweeper(10).RunOnce(context.Background())

	if err != nil || result.Destroyed != 1 || sim.exists(t, orphan) {
		t.Fatalf("un RECORDED vencido que nunca recibió su discarded debe destruirse: %+v, %v", result, err)
	}
}

func TestSweeperPaginaSobreMuchosRegistrosVencidos(t *testing.T) {
	sim := newSimulation(t)
	var ids []uuid.UUID
	for i := 0; i < 7; i++ {
		ids = append(ids, sim.add(t, i%2 == 0))
	}
	keep := sim.add(t, true)
	sim.now = integrationBase.Add(integrationRetention)
	if _, err := sim.repo.SetJudicialHold(context.Background(), keep, true); err != nil {
		t.Fatal(err)
	}

	result, err := sim.sweeper(3).RunOnce(context.Background())

	if err != nil || result.Destroyed != 7 {
		t.Fatalf("resultado = %+v, %v; esperaba 7 destruidos paginando de a 3", result, err)
	}
	for _, id := range ids {
		if sim.exists(t, id) {
			t.Errorf("%s sigue existiendo", id)
		}
	}
	if !sim.exists(t, keep) {
		t.Error("el registro con retención judicial no debía destruirse")
	}
}

func TestSweeperReintentaCuandoS3TodaviaRetiene(t *testing.T) {
	sim := newSimulation(t)
	id := sim.add(t, true)
	sim.now = integrationBase.Add(integrationRetention)
	// La fila ya venció, pero el reloj de S3 va atrasado: rechaza el borrado.
	sim.objects.Now = func() time.Time { return integrationBase }

	result, err := sim.sweeper(10).RunOnce(context.Background())
	if err != nil || result.Retained != 1 || result.Destroyed != 0 || !sim.exists(t, id) {
		t.Fatalf("resultado = %+v, %v", result, err)
	}

	sim.objects.Now = func() time.Time { return sim.now }
	result, err = sim.sweeper(10).RunOnce(context.Background())
	if err != nil || result.Destroyed != 1 || sim.exists(t, id) {
		t.Fatalf("la vuelta siguiente debía destruirlo: %+v, %v", result, err)
	}
}

func TestSweeperDepuraTombstonesConRelojSimulado(t *testing.T) {
	sim := newSimulation(t)
	id := sim.add(t, false)
	if discarded, err := sim.repo.DiscardRecorded(context.Background(), id, integrationBase); err != nil || !discarded {
		t.Fatalf("descarte: %v, %v", discarded, err)
	}

	sim.now = integrationBase.Add(integrationTombstoneRetention)
	result, err := sim.sweeper(10).RunOnce(context.Background())
	if err != nil || result.TombstonesDeleted != 0 {
		t.Fatalf("en el límite el tombstone se conserva: %+v, %v", result, err)
	}
	if tombstoned, _ := sim.repo.HasTombstone(context.Background(), id); !tombstoned {
		t.Fatal("el tombstone debía conservarse")
	}

	sim.now = integrationBase.Add(integrationTombstoneRetention + time.Second)
	result, err = sim.sweeper(10).RunOnce(context.Background())
	if err != nil || result.TombstonesDeleted != 1 {
		t.Fatalf("pasada la retención el tombstone se depura: %+v, %v", result, err)
	}
	if tombstoned, _ := sim.repo.HasTombstone(context.Background(), id); tombstoned {
		t.Error("el tombstone debía depurarse")
	}
}
