package sweeper

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-audit/internal/domain"
	"github.com/matiasfelau/vinculo-vial-audit/internal/manifest"
	"github.com/matiasfelau/vinculo-vial-audit/internal/testsupport"
)

// getOverride sustituye la lectura de un registro concreto.
type getOverride struct {
	*testsupport.MemoryStore
	id  uuid.UUID
	get func() (domain.Record, error)
}

func (g getOverride) Get(ctx context.Context, id uuid.UUID) (domain.Record, error) {
	if id == g.id {
		return g.get()
	}
	return g.MemoryStore.Get(ctx, id)
}

func (f *fixture) hasObjects(id uuid.UUID) bool {
	return len(f.objects.Versions(manifest.ManifestKey(id.String()))) > 0
}

func TestRunOnceUnRegistroIlegibleSeCuentaComoFalloYNoDetieneLaVuelta(t *testing.T) {
	f := newFixture(10)
	ilegible := f.add(domain.StatusDelivered, clock.Add(-time.Hour), false)
	sano1 := f.add(domain.StatusDelivered, clock.Add(-time.Hour), false)
	sano2 := f.add(domain.StatusDelivered, clock.Add(-time.Hour), false)
	f.sweeper.store = getOverride{MemoryStore: f.store, id: ilegible, get: func() (domain.Record, error) {
		return domain.Record{}, errors.New("fila ilegible")
	}}

	result, err := f.sweeper.RunOnce(context.Background())

	if err != nil {
		t.Fatalf("un registro que falla no debe cortar la vuelta: %v", err)
	}
	if result.Failed != 1 || result.Destroyed != 2 {
		t.Errorf("resultado = %+v, esperaba 1 fallido y 2 destruidos", result)
	}
	if !f.exists(ilegible) || !f.hasObjects(ilegible) {
		t.Error("el registro que no se pudo leer no debe destruirse")
	}
	if f.exists(sano1) || f.exists(sano2) {
		t.Error("los demás registros vencidos debían destruirse")
	}
}

func TestRunOnceIgnoraUnRegistroQueDesaparecioEntreElListadoYLaLectura(t *testing.T) {
	f := newFixture(10)
	id := f.add(domain.StatusDelivered, clock.Add(-time.Hour), false)
	f.sweeper.store = getOverride{MemoryStore: f.store, id: id, get: func() (domain.Record, error) {
		return domain.Record{}, domain.ErrRecordNotFound
	}}

	result, err := f.sweeper.RunOnce(context.Background())

	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if result != (Result{}) {
		t.Errorf("resultado = %+v, esperaba una vuelta sin novedades (otro proceso ya lo borró)", result)
	}
	if !f.hasObjects(id) {
		t.Error("sin registro confirmado no debe tocarse S3")
	}
}

func TestRunOnceNoDestruyeUnRegistroQueRecibioRetencionJudicialDespuesDeListarse(t *testing.T) {
	f := newFixture(10)
	id := f.add(domain.StatusDelivered, clock.Add(-time.Hour), false)
	// El listado lo trae vencido, pero al leerlo ya tiene la retención judicial.
	f.sweeper.store = getOverride{MemoryStore: f.store, id: id, get: func() (domain.Record, error) {
		return domain.Record{AlertID: id, Status: domain.StatusDelivered, DestroyAt: clock.Add(-time.Hour), JudicialHold: true}, nil
	}}

	result, err := f.sweeper.RunOnce(context.Background())

	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if result.Destroyed != 0 || result.Failed != 0 {
		t.Errorf("resultado = %+v, esperaba que no se destruya ni falle nada", result)
	}
	if !f.exists(id) || !f.hasObjects(id) {
		t.Error("un registro con retención judicial no puede perderse por una carrera con el sweeper")
	}
}

func TestRunOnceSiFallaElBorradoEnS3ConservaLaFilaYLoReintentaDespues(t *testing.T) {
	f := newFixture(10)
	id := f.add(domain.StatusDelivered, clock.Add(-time.Hour), false)
	f.objects.ErrDelete = errors.New("s3 caído")

	result, err := f.sweeper.RunOnce(context.Background())

	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if result.Failed != 1 || result.Destroyed != 0 {
		t.Errorf("resultado = %+v, esperaba 1 fallido y 0 destruidos", result)
	}
	// La fila es la que dirige el reintento: sin ella, los objetos quedarían huérfanos.
	if !f.exists(id) || !f.hasObjects(id) {
		t.Fatal("si S3 falla, ni la fila ni los objetos deben perderse")
	}

	f.objects.ErrDelete = nil
	result, err = f.sweeper.RunOnce(context.Background())

	if err != nil || result.Destroyed != 1 {
		t.Fatalf("la vuelta siguiente debía retomar el registro: %+v, %v", result, err)
	}
	if f.exists(id) || f.hasObjects(id) {
		t.Error("tras el reintento el registro debe estar destruido")
	}
}

// tombstoneFailure falla solo al depurar tombstones.
type tombstoneFailure struct{ *testsupport.MemoryStore }

func (tombstoneFailure) DeleteTombstonesBefore(context.Context, time.Time) (int64, error) {
	return 0, domain.ErrRepositoryUnavailable
}

func TestRunOnceSiFallaLaDepuracionDeTombstonesLoCuentaYSigueDestruyendoRegistros(t *testing.T) {
	f := newFixture(10)
	id := f.add(domain.StatusDelivered, clock.Add(-time.Hour), false)
	f.sweeper.store = tombstoneFailure{MemoryStore: f.store}

	result, err := f.sweeper.RunOnce(context.Background())

	if err != nil {
		t.Fatalf("el fallo de los tombstones no es el de la vuelta: %v", err)
	}
	if result.Failed != 1 || result.Destroyed != 1 || result.TombstonesDeleted != 0 {
		t.Errorf("resultado = %+v, esperaba 1 fallido (tombstones), 1 destruido y 0 depurados", result)
	}
	if f.exists(id) {
		t.Error("el registro vencido debía destruirse aunque fallara la depuración de tombstones")
	}
}

// listCounter cuenta los listados y falla los primeros failFirst.
type listCounter struct {
	*testsupport.MemoryStore
	calls     *atomic.Int32
	failFirst int32
}

func (l listCounter) ListExpired(ctx context.Context, now time.Time, after uuid.UUID, limit int) ([]uuid.UUID, error) {
	if l.calls.Add(1) <= l.failFirst {
		return nil, domain.ErrRepositoryUnavailable
	}
	return l.MemoryStore.ListExpired(ctx, now, after, limit)
}

func TestRunRepiteLaVueltaYSobreviveAUnaVueltaFallida(t *testing.T) {
	f := newFixture(10)
	id := f.add(domain.StatusDelivered, clock.Add(-time.Hour), false)
	calls := &atomic.Int32{}
	// La primera vuelta (la de arranque) falla: el ciclo tiene que seguir.
	f.sweeper.store = listCounter{MemoryStore: f.store, calls: calls, failFirst: 1}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.sweeper.Run(ctx, 5*time.Millisecond)
	}()

	limite := time.Now().Add(5 * time.Second)
	for f.exists(id) && time.Now().Before(limite) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done

	if f.exists(id) {
		t.Fatal("el ciclo no retomó el registro en una vuelta posterior a la fallida")
	}
	if got := calls.Load(); got < 2 {
		t.Errorf("hubo %d vueltas, esperaba al menos 2 (la fallida y la que destruyó)", got)
	}
}
