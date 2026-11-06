package hold

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-audit/internal/domain"
	"github.com/matiasfelau/vinculo-vial-audit/internal/manifest"
	"github.com/matiasfelau/vinculo-vial-audit/internal/testsupport"
)

// fakeHolds registra el orden de las operaciones sobre la fila y sobre S3.
type fakeHolds struct {
	events   *[]string
	found    bool
	rowErr   error
	legalErr error
	rowState bool
	objects  *testsupport.MemoryObjects
}

func (f *fakeHolds) SetJudicialHold(_ context.Context, _ uuid.UUID, hold bool) (bool, error) {
	if f.rowErr != nil {
		return false, f.rowErr
	}
	if hold {
		*f.events = append(*f.events, "fila:on")
	} else {
		*f.events = append(*f.events, "fila:off")
	}
	f.rowState = hold
	return f.found, nil
}

func (f *fakeHolds) SetLegalHold(ctx context.Context, prefix string, on bool) (int, error) {
	if f.legalErr != nil {
		return 0, f.legalErr
	}
	if on {
		*f.events = append(*f.events, "s3:on")
	} else {
		*f.events = append(*f.events, "s3:off")
	}
	return f.objects.SetLegalHold(ctx, prefix, on)
}

func newHolder(id uuid.UUID) (*Holder, *fakeHolds, *[]string) {
	events := []string{}
	objects := testsupport.NewMemoryObjects()
	for _, key := range []string{manifest.ManifestKey(id.String()), manifest.PhotoKey(id.String(), "GENERAL", 0)} {
		objects.Seed(key, []byte("x"))
	}
	objects.Seed(manifest.ManifestKey(uuid.NewString()), []byte("otro registro"))
	fake := &fakeHolds{events: &events, found: true, objects: objects}
	return New(fake, fake), fake, &events
}

func TestHoldOnMarcaLaFilaAntesQueS3(t *testing.T) {
	id := uuid.New()
	holder, fake, events := newHolder(id)

	changed, err := holder.Hold(context.Background(), id, true)

	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if changed != 2 {
		t.Errorf("modificó %d versiones, esperaba 2 (solo las del registro)", changed)
	}
	if got := *events; len(got) != 2 || got[0] != "fila:on" || got[1] != "s3:on" {
		t.Errorf("orden = %v, esperaba fila:on y después s3:on", got)
	}
	if !fake.rowState {
		t.Error("la fila debía quedar marcada")
	}
}

func TestHoldOffQuitaS3AntesQueLaFila(t *testing.T) {
	id := uuid.New()
	holder, _, events := newHolder(id)
	if _, err := holder.Hold(context.Background(), id, true); err != nil {
		t.Fatal(err)
	}
	*events = nil

	if _, err := holder.Hold(context.Background(), id, false); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	if got := *events; len(got) != 2 || got[0] != "s3:off" || got[1] != "fila:off" {
		t.Errorf("orden = %v, esperaba s3:off y después fila:off", got)
	}
}

func TestHoldOnSobreRegistroInexistenteFalla(t *testing.T) {
	id := uuid.New()
	holder, fake, events := newHolder(id)
	fake.found = false

	_, err := holder.Hold(context.Background(), id, true)

	if !errors.Is(err, domain.ErrRecordNotFound) {
		t.Fatalf("esperaba ErrRecordNotFound, obtuvo %v", err)
	}
	for _, event := range *events {
		if event == "s3:on" {
			t.Error("no debe tocar S3 si el registro no existe")
		}
	}
}

func TestHoldOnConS3CaidoDejaLaFilaMarcadaYLoInforma(t *testing.T) {
	id := uuid.New()
	holder, fake, _ := newHolder(id)
	fake.legalErr = domain.ErrStorageUnavailable

	_, err := holder.Hold(context.Background(), id, true)

	if !errors.Is(err, domain.ErrStorageUnavailable) {
		t.Fatalf("esperaba ErrStorageUnavailable, obtuvo %v", err)
	}
	if !fake.rowState {
		t.Error("del lado seguro: la fila queda marcada para que el sweeper no toque el registro")
	}
}

func TestHoldOffConS3CaidoNoQuitaLaMarcaDeLaFila(t *testing.T) {
	id := uuid.New()
	holder, fake, events := newHolder(id)
	if _, err := holder.Hold(context.Background(), id, true); err != nil {
		t.Fatal(err)
	}
	*events = nil
	fake.legalErr = domain.ErrStorageUnavailable

	if _, err := holder.Hold(context.Background(), id, false); err == nil {
		t.Fatal("esperaba error")
	}

	if !fake.rowState {
		t.Error("del lado seguro: si no se pudo quitar el hold de S3, la fila sigue marcada")
	}
}

func TestHoldConBaseCaidaFalla(t *testing.T) {
	id := uuid.New()
	holder, fake, _ := newHolder(id)
	fake.rowErr = domain.ErrRepositoryUnavailable

	_, err := holder.Hold(context.Background(), id, true)

	if !errors.Is(err, domain.ErrRepositoryUnavailable) {
		t.Fatalf("esperaba ErrRepositoryUnavailable, obtuvo %v", err)
	}
}
