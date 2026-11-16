package record

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

// tombstoneDown simula una base que no responde solo al consultar tombstones.
type tombstoneDown struct{ *testsupport.MemoryStore }

func (tombstoneDown) HasTombstone(context.Context, uuid.UUID) (bool, error) {
	return false, domain.ErrRepositoryUnavailable
}

func TestDeliverConBaseCaidaAlLeerElRegistroEsTransitorioYNoTocaS3(t *testing.T) {
	f := newDeliveryFixture(t)
	f.store.ErrGet = domain.ErrRepositoryUnavailable

	err := f.deliver.Deliver(context.Background(), f.input())

	if !errors.Is(err, domain.ErrRepositoryUnavailable) {
		t.Fatalf("esperaba ErrRepositoryUnavailable (transitorio), obtuvo %v", err)
	}
	if f.audit.PutCalls != 0 {
		t.Error("sin poder leer el registro no se debe escribir en S3")
	}
}

func TestDeliverSinRegistroYConBaseCaidaAlConsultarElTombstoneEsTransitorio(t *testing.T) {
	f := newDeliveryFixture(t)
	f.deliver.store = tombstoneDown{f.store}
	in := f.input()
	in.AlertID = uuid.New()

	err := f.deliver.Deliver(context.Background(), in)

	if !errors.Is(err, domain.ErrRepositoryUnavailable) {
		t.Fatalf("esperaba ErrRepositoryUnavailable, obtuvo %v", err)
	}
	if errors.Is(err, domain.ErrAlertDiscarded) || errors.Is(err, domain.ErrRecordNotFound) {
		t.Error("sin poder consultar el tombstone no se puede concluir ni descarte ni orden invertido")
	}
}

// failOnKey falla la escritura de una clave concreta y delega el resto.
type failOnKey struct {
	*testsupport.MemoryObjects
	key string
	err error
}

func (w failOnKey) PutLocked(ctx context.Context, key string, body []byte, contentType string, retainUntil time.Time) error {
	if key == w.key {
		return w.err
	}
	return w.MemoryObjects.PutLocked(ctx, key, body, contentType, retainUntil)
}

func TestDeliverSiFallaElManifiestoNoMarcaEntregadoYElReintentoLoCompleta(t *testing.T) {
	f := newDeliveryFixture(t)
	in := f.input()
	f.deliver.audit = failOnKey{MemoryObjects: f.audit, key: manifest.ManifestKey(f.id.String()), err: errors.New("s3 caído")}

	err := f.deliver.Deliver(context.Background(), in)

	if err == nil {
		t.Fatal("Deliver devolvió nil con el manifiesto sin escribir")
	}
	if record, _ := f.store.Lookup(f.id); record.Status != domain.StatusRecorded {
		t.Fatalf("estado = %s: sin manifiesto el registro no puede quedar DELIVERED", record.Status)
	}

	// El mensaje vuelve por .retry y esta vez S3 responde.
	f.deliver.audit = f.audit
	if err := f.deliver.Deliver(context.Background(), in); err != nil {
		t.Fatalf("el reintento falló: %v", err)
	}
	record, _ := f.store.Lookup(f.id)
	if record.Status != domain.StatusDelivered || record.ManifestKey == nil {
		t.Errorf("tras el reintento el registro debe estar entregado: %+v", record)
	}
}

// racingStore simula otra entrega que gana la carrera: justo antes de marcar
// DELIVERED, el registro ya fue marcado por otro camino.
type racingStore struct {
	*testsupport.MemoryStore
	winner domain.Delivery
}

func (r racingStore) MarkDelivered(ctx context.Context, id uuid.UUID, delivery domain.Delivery) (bool, error) {
	if _, err := r.MemoryStore.MarkDelivered(ctx, id, r.winner); err != nil {
		return false, err
	}
	return r.MemoryStore.MarkDelivered(ctx, id, delivery)
}

func TestDeliverSiOtraEntregaGanaLaCarreraHaceAckSinPisarlaYSinError(t *testing.T) {
	f := newDeliveryFixture(t)
	ganadora := domain.Delivery{DeliveredAt: fixedNow, ManifestKey: "ganadora", ManifestSHA256: "ganadora"}
	f.deliver.store = racingStore{MemoryStore: f.store, winner: ganadora}

	if err := f.deliver.Deliver(context.Background(), f.input()); err != nil {
		t.Fatalf("perder la carrera no es un error (el registro ya está entregado): %v", err)
	}

	record, _ := f.store.Lookup(f.id)
	if record.ManifestKey == nil || *record.ManifestKey != "ganadora" {
		t.Errorf("la entrega perdedora pisó la ganadora: %+v", record.ManifestKey)
	}
}

func TestDeliverArchivaLasFotosOrdenadasPorRolEIndice(t *testing.T) {
	f := newDeliveryFixture(t)
	var items []manifest.EvidenceItem
	for _, foto := range []struct {
		role  string
		index int
	}{{"PLATE", 0}, {"GENERAL", 1}, {"GENERAL", 0}} {
		key := "alerts/" + f.id.String() + "/redacted/" + manifest.PhotoFileName(foto.role, foto.index)
		body := []byte("foto-" + foto.role + string(rune('0'+foto.index)))
		f.evidence.Seed(key, body)
		items = append(items, manifest.EvidenceItem{Role: foto.role, Index: foto.index, Key: key, SHA256: sha(body)})
	}

	if err := f.deliver.Deliver(context.Background(), DeliveredInput{AlertID: f.id, DeliveredAt: fixedNow, Evidence: items}); err != nil {
		t.Fatal(err)
	}

	record, _ := f.store.Lookup(f.id)
	want := []struct {
		role  string
		index int
	}{{"GENERAL", 0}, {"GENERAL", 1}, {"PLATE", 0}}
	if len(record.Evidence) != len(want) {
		t.Fatalf("evidencia = %+v", record.Evidence)
	}
	for i, w := range want {
		got := record.Evidence[i]
		if got.Role != w.role || got.Index != w.index || got.Key != manifest.PhotoKey(f.id.String(), w.role, w.index) {
			t.Errorf("evidencia[%d] = %+v, esperaba %s-%d", i, got, w.role, w.index)
		}
	}
}

// --- Discarder ---

func TestDiscardSinRegistroYConBaseCaidaAlConsultarElTombstoneEsTransitorio(t *testing.T) {
	discarder := NewDiscarder(tombstoneDown{testsupport.NewMemoryStore()})

	err := discarder.Discard(context.Background(), uuid.New(), domain.DiscardReasonExpired)

	if !errors.Is(err, domain.ErrRepositoryUnavailable) {
		t.Fatalf("esperaba ErrRepositoryUnavailable, obtuvo %v", err)
	}
}

// entregaEnMedio hace que el registro pase a DELIVERED entre la lectura del
// Discarder y su borrado condicional.
type entregaEnMedio struct{ *testsupport.MemoryStore }

func (e entregaEnMedio) Get(ctx context.Context, id uuid.UUID) (domain.Record, error) {
	record, err := e.MemoryStore.Get(ctx, id)
	if err == nil {
		// Se devuelve la foto previa (RECORDED) y recién después se entrega.
		_, _ = e.MemoryStore.MarkDelivered(ctx, id, domain.Delivery{DeliveredAt: fixedNow, ManifestKey: "m", ManifestSHA256: "s"})
	}
	return record, err
}

func TestDiscardSiElRegistroSeEntregaDuranteElDescarteNoLoBorraNiCreaTombstone(t *testing.T) {
	store := testsupport.NewMemoryStore()
	id := uuid.New()
	if err := newRecorder(store).Record(context.Background(), recordedInput(id)); err != nil {
		t.Fatal(err)
	}

	err := NewDiscarder(entregaEnMedio{store}).Discard(context.Background(), id, domain.DiscardReasonUnclaimed)

	if err != nil {
		t.Fatalf("el descarte perdido es un ack, no un error: %v", err)
	}
	if got, ok := store.Lookup(id); !ok || got.Status != domain.StatusDelivered {
		t.Error("el registro entregado debe seguir ahí")
	}
	if store.TombstoneCount() != 0 {
		t.Error("no se descartó: no debe haber tombstone")
	}
}
