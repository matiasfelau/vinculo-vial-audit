package sweeper

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-audit/internal/domain"
	"github.com/matiasfelau/vinculo-vial-audit/internal/manifest"
	"github.com/matiasfelau/vinculo-vial-audit/internal/testsupport"
)

var clock = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

const tombstoneRetention = 7 * 24 * time.Hour

type fixture struct {
	store   *testsupport.MemoryStore
	objects *testsupport.MemoryObjects
	now     time.Time
	sweeper *Sweeper
}

func newFixture(batchSize int) *fixture {
	f := &fixture{store: testsupport.NewMemoryStore(), objects: testsupport.NewMemoryObjects(), now: clock}
	f.objects.Now = func() time.Time { return f.now }
	f.sweeper = New(f.store, f.objects, batchSize, tombstoneRetention)
	f.sweeper.now = func() time.Time { return f.now }
	return f
}

// add crea un registro con su foto y su manifiesto bloqueados hasta destroyAt.
func (f *fixture) add(status domain.Status, destroyAt time.Time, hold bool) uuid.UUID {
	id := uuid.New()
	f.store.Put(domain.Record{AlertID: id, Status: status, DestroyAt: destroyAt, JudicialHold: hold})
	if status == domain.StatusDelivered {
		_ = f.objects.PutLocked(context.Background(), manifest.PhotoKey(id.String(), "GENERAL", 0), []byte("foto"), "image/jpeg", destroyAt)
		_ = f.objects.PutLocked(context.Background(), manifest.ManifestKey(id.String()), []byte("{}"), "application/json", destroyAt)
	}
	return id
}

func (f *fixture) exists(id uuid.UUID) bool {
	_, ok := f.store.Lookup(id)
	return ok
}

func TestRunOnceDestruyeObjetosYFilaDeLosVencidos(t *testing.T) {
	f := newFixture(10)
	vencido := f.add(domain.StatusDelivered, clock.Add(-time.Hour), false)
	vigente := f.add(domain.StatusDelivered, clock.Add(time.Hour), false)
	f.now = clock.Add(0)

	result, err := f.sweeper.RunOnce(context.Background())

	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if result.Destroyed != 1 {
		t.Errorf("destruidos = %d, esperaba 1", result.Destroyed)
	}
	if f.exists(vencido) {
		t.Error("la fila vencida no se borró")
	}
	if len(f.objects.Versions(manifest.ManifestKey(vencido.String()))) != 0 {
		t.Error("los objetos vencidos no se borraron")
	}
	if !f.exists(vigente) || len(f.objects.Versions(manifest.ManifestKey(vigente.String()))) == 0 {
		t.Error("un registro vigente no debe tocarse")
	}
}

func TestRunOnceNoBorraConRetencionJudicial(t *testing.T) {
	f := newFixture(10)
	retenido := f.add(domain.StatusDelivered, clock.Add(-time.Hour), true)

	result, err := f.sweeper.RunOnce(context.Background())

	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if result.Destroyed != 0 {
		t.Errorf("destruidos = %d, esperaba 0", result.Destroyed)
	}
	if !f.exists(retenido) || len(f.objects.Versions(manifest.ManifestKey(retenido.String()))) == 0 {
		t.Error("un registro con retención judicial nunca se borra")
	}
}

func TestRunOnceRetomaUnRegistroDespuesDeLevantarLaRetencionJudicial(t *testing.T) {
	f := newFixture(10)
	id := f.add(domain.StatusDelivered, clock.Add(-time.Hour), true)
	if _, err := f.sweeper.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	record, _ := f.store.Lookup(id)
	record.JudicialHold = false
	f.store.Put(record)

	result, err := f.sweeper.RunOnce(context.Background())

	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if result.Destroyed != 1 || f.exists(id) {
		t.Error("sin retención judicial el registro vencido debe destruirse")
	}
}

func TestRunOnceReintentaCuandoLaRetencionDeS3SigueVigente(t *testing.T) {
	f := newFixture(10)
	// destroy_at ya pasó para la fila, pero S3 (otro reloj) todavía retiene.
	id := f.add(domain.StatusDelivered, clock.Add(-time.Minute), false)
	f.objects.Now = func() time.Time { return clock.Add(-time.Hour) }

	result, err := f.sweeper.RunOnce(context.Background())

	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if result.Retained != 1 || result.Destroyed != 0 {
		t.Errorf("resultado = %+v, esperaba un registro retenido", result)
	}
	if !f.exists(id) {
		t.Error("la fila no debe borrarse mientras S3 retiene los objetos")
	}

	f.objects.Now = func() time.Time { return clock }
	result, err = f.sweeper.RunOnce(context.Background())
	if err != nil || result.Destroyed != 1 || f.exists(id) {
		t.Errorf("la vuelta siguiente debía destruirlo: %+v, %v", result, err)
	}
}

func TestRunOnceIncluyeRegistrosRecordedHuerfanos(t *testing.T) {
	f := newFixture(10)
	huerfano := f.add(domain.StatusRecorded, clock.Add(-time.Hour), false)

	result, err := f.sweeper.RunOnce(context.Background())

	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if result.Destroyed != 1 || f.exists(huerfano) {
		t.Error("un RECORDED vencido que nunca recibió su discarded debe destruirse")
	}
}

func TestRunOnceRetomaSiLaFilaFalloAMitadDeCamino(t *testing.T) {
	f := newFixture(10)
	id := f.add(domain.StatusDelivered, clock.Add(-time.Hour), false)
	f.store.ErrDelete = errors.New("base caída")

	result, err := f.sweeper.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if result.Failed != 1 {
		t.Fatalf("resultado = %+v, esperaba un fallo", result)
	}
	if len(f.objects.Versions(manifest.ManifestKey(id.String()))) != 0 {
		t.Fatal("los objetos debían estar borrados antes de la falla de la fila")
	}
	if !f.exists(id) {
		t.Fatal("la fila debía seguir existiendo tras el fallo")
	}

	f.store.ErrDelete = nil
	result, err = f.sweeper.RunOnce(context.Background())
	if err != nil || result.Destroyed != 1 || f.exists(id) {
		t.Errorf("la vuelta siguiente debía retomar el borrado: %+v, %v", result, err)
	}
}

func TestRunOnceContinuaConLosDemasSiUnoFalla(t *testing.T) {
	f := newFixture(2)
	for i := 0; i < 5; i++ {
		f.add(domain.StatusDelivered, clock.Add(-time.Hour), false)
	}
	failing := f.add(domain.StatusDelivered, clock.Add(-time.Hour), false)
	f.objects.ErrDelete = nil
	// Un registro con legal hold en S3 pero sin marca en la fila: no puede destruirse.
	_, _ = f.objects.SetLegalHold(context.Background(), manifest.RecordPrefix(failing.String()), true)

	result, err := f.sweeper.RunOnce(context.Background())

	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if result.Destroyed != 5 || result.Retained != 1 {
		t.Errorf("resultado = %+v, esperaba 5 destruidos y 1 retenido (paginando de a 2)", result)
	}
}

func TestRunOnceConErrorDeLaBaseAlListarLoDevuelve(t *testing.T) {
	f := newFixture(10)
	f.add(domain.StatusRecorded, clock.Add(-time.Hour), false)
	f.sweeper.store = failingList{err: domain.ErrRepositoryUnavailable}

	_, err := f.sweeper.RunOnce(context.Background())

	if !errors.Is(err, domain.ErrRepositoryUnavailable) {
		t.Fatalf("esperaba ErrRepositoryUnavailable, obtuvo %v", err)
	}
}

type failingList struct{ err error }

func (f failingList) ListExpired(context.Context, time.Time, uuid.UUID, int) ([]uuid.UUID, error) {
	return nil, f.err
}
func (f failingList) Get(context.Context, uuid.UUID) (domain.Record, error) {
	return domain.Record{}, f.err
}
func (f failingList) DeleteExpired(context.Context, uuid.UUID, time.Time) (bool, error) {
	return false, f.err
}
func (f failingList) DeleteTombstonesBefore(context.Context, time.Time) (int64, error) {
	return 0, nil
}

func TestRunOnceConContextoCanceladoSeDetiene(t *testing.T) {
	f := newFixture(10)
	f.add(domain.StatusRecorded, clock.Add(-time.Hour), false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := f.sweeper.RunOnce(ctx)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("esperaba context.Canceled, obtuvo %v", err)
	}
}

func TestRunTerminaAlCancelarElContexto(t *testing.T) {
	f := newFixture(10)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		defer close(done)
		f.sweeper.Run(ctx, time.Hour)
	}()
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run no terminó al cancelarse el contexto")
	}
}

func TestRunOnceDepuraLosTombstonesConMasDeLaRetencion(t *testing.T) {
	f := newFixture(10)
	viejo, limite, reciente := uuid.New(), uuid.New(), uuid.New()
	f.store.AddTombstone(viejo, clock.Add(-tombstoneRetention-time.Second))
	f.store.AddTombstone(limite, clock.Add(-tombstoneRetention))
	f.store.AddTombstone(reciente, clock.Add(-time.Hour))

	result, err := f.sweeper.RunOnce(context.Background())

	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if result.TombstonesDeleted != 1 {
		t.Errorf("tombstones depurados = %d, esperaba 1 (solo el que supera AUDIT_TOMBSTONE_DAYS)", result.TombstonesDeleted)
	}
	if f.store.TombstoneCount() != 2 {
		t.Errorf("quedan %d tombstones, esperaba 2", f.store.TombstoneCount())
	}
}

func TestRunOnceDepuraTombstonesAunSiFallaLaListaDeRegistros(t *testing.T) {
	f := newFixture(10)
	f.store.AddTombstone(uuid.New(), clock.Add(-2*tombstoneRetention))
	f.sweeper.store = tombstonesOnly{MemoryStore: f.store}

	result, err := f.sweeper.RunOnce(context.Background())

	if !errors.Is(err, domain.ErrRepositoryUnavailable) {
		t.Fatalf("esperaba el error de la lista, obtuvo %v", err)
	}
	if result.TombstonesDeleted != 1 {
		t.Errorf("tombstones depurados = %d, esperaba 1", result.TombstonesDeleted)
	}
}

// tombstonesOnly falla al listar registros pero depura tombstones.
type tombstonesOnly struct{ *testsupport.MemoryStore }

func (tombstonesOnly) ListExpired(context.Context, time.Time, uuid.UUID, int) ([]uuid.UUID, error) {
	return nil, domain.ErrRepositoryUnavailable
}

func TestRunOnceNoBorraTombstonesDeAlertasConRegistroVivo(t *testing.T) {
	f := newFixture(10)
	f.add(domain.StatusRecorded, clock.Add(time.Hour), false)

	result, err := f.sweeper.RunOnce(context.Background())

	if err != nil || result.TombstonesDeleted != 0 {
		t.Fatalf("resultado = %+v, %v", result, err)
	}
}
