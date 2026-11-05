package record

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-audit/internal/domain"
	"github.com/matiasfelau/vinculo-vial-audit/internal/manifest"
	"github.com/matiasfelau/vinculo-vial-audit/internal/testsupport"
)

const retentionDays = 3

var (
	fixedNow  = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	createdAt = time.Date(2026, 11, 4, 10, 0, 0, 123456789, time.UTC)
)

func sha(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func recordedInput(id uuid.UUID) RecordedInput {
	return RecordedInput{
		AlertID:     id,
		AlertType:   domain.AlertTypeCrashed,
		CreatedAt:   createdAt,
		DNIEncAudit: "ZG5p",
		PatEncAudit: "cGF0",
		AuditKeyID:  "2026-11",
	}
}

func newRecorder(store *testsupport.MemoryStore) *Recorder {
	recorder := NewRecorder(store, retentionDays)
	recorder.now = func() time.Time { return fixedNow }
	return recorder
}

func TestRecordCreaElRegistroConDestroyAt(t *testing.T) {
	store := testsupport.NewMemoryStore()
	id := uuid.New()

	if err := newRecorder(store).Record(context.Background(), recordedInput(id)); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	got, ok := store.Lookup(id)
	if !ok {
		t.Fatal("el registro no se creó")
	}
	if got.Status != domain.StatusRecorded {
		t.Errorf("status = %s, esperaba RECORDED", got.Status)
	}
	wantCreated := createdAt.Truncate(time.Microsecond)
	if !got.AlertCreatedAt.Equal(wantCreated) {
		t.Errorf("alert_created_at = %v, esperaba %v", got.AlertCreatedAt, wantCreated)
	}
	if want := wantCreated.Add(retentionDays * 24 * time.Hour); !got.DestroyAt.Equal(want) {
		t.Errorf("destroy_at = %v, esperaba creación + %d días = %v", got.DestroyAt, retentionDays, want)
	}
	if got.DNIEncAudit != "ZG5p" || got.PatEncAudit != "cGF0" || got.AuditKeyID != "2026-11" {
		t.Error("los criptogramas deben guardarse tal como llegan")
	}
	if !got.RecordedAt.Equal(fixedNow) {
		t.Errorf("recorded_at = %v, esperaba %v", got.RecordedAt, fixedNow)
	}
}

func TestRecordRepetidoNoCambiaNada(t *testing.T) {
	store := testsupport.NewMemoryStore()
	id := uuid.New()
	recorder := newRecorder(store)

	if err := recorder.Record(context.Background(), recordedInput(id)); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	original, _ := store.Lookup(id)

	repetido := recordedInput(id)
	repetido.DNIEncAudit = "b3Rybw=="
	repetido.AuditKeyID = "otra"
	if err := recorder.Record(context.Background(), repetido); err != nil {
		t.Fatalf("un recorded repetido no debe fallar: %v", err)
	}

	got, _ := store.Lookup(id)
	if got.DNIEncAudit != original.DNIEncAudit || got.AuditKeyID != original.AuditKeyID {
		t.Error("un recorded repetido cambió el registro")
	}
	if store.Len() != 1 {
		t.Errorf("hay %d registros, esperaba 1", store.Len())
	}
}

func TestRecordConBaseCaidaEsTransitorio(t *testing.T) {
	store := testsupport.NewMemoryStore()
	store.ErrInsert = domain.ErrRepositoryUnavailable

	err := newRecorder(store).Record(context.Background(), recordedInput(uuid.New()))

	if !errors.Is(err, domain.ErrRepositoryUnavailable) {
		t.Fatalf("esperaba ErrRepositoryUnavailable, obtuvo %v", err)
	}
}

// --- Deliverer ---

type deliveryFixture struct {
	store    *testsupport.MemoryStore
	evidence *testsupport.MemoryObjects
	audit    *testsupport.MemoryObjects
	deliver  *Deliverer
	id       uuid.UUID
	photos   map[string][]byte
}

func newDeliveryFixture(t *testing.T) *deliveryFixture {
	t.Helper()

	f := &deliveryFixture{
		store:    testsupport.NewMemoryStore(),
		evidence: testsupport.NewMemoryObjects(),
		audit:    testsupport.NewMemoryObjects(),
		id:       uuid.New(),
		photos:   map[string][]byte{"GENERAL": []byte("foto-general"), "PLATE": []byte("foto-patente")},
	}
	f.deliver = NewDeliverer(f.store, f.evidence, f.audit)
	f.deliver.now = func() time.Time { return fixedNow }

	if err := newRecorder(f.store).Record(context.Background(), recordedInput(f.id)); err != nil {
		t.Fatalf("no se pudo crear el registro: %v", err)
	}
	return f
}

func (f *deliveryFixture) input() DeliveredInput {
	var items []manifest.EvidenceItem
	for _, role := range []string{"PLATE", "GENERAL"} {
		key := "alerts/" + f.id.String() + "/redacted/" + role + "-0.jpg"
		f.evidence.Seed(key, f.photos[role])
		items = append(items, manifest.EvidenceItem{Role: role, Index: 0, Key: key, SHA256: sha(f.photos[role])})
	}
	return DeliveredInput{AlertID: f.id, DeliveredAt: fixedNow, Evidence: items}
}

func TestDeliverArchivaFotosYManifiestoBloqueados(t *testing.T) {
	f := newDeliveryFixture(t)
	in := f.input()
	record, _ := f.store.Lookup(f.id)

	if err := f.deliver.Deliver(context.Background(), in); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	for role, body := range f.photos {
		key := manifest.PhotoKey(f.id.String(), role, 0)
		versions := f.audit.Versions(key)
		if len(versions) != 1 {
			t.Fatalf("%s: %d versiones, esperaba 1", key, len(versions))
		}
		if string(versions[0].Body) != string(body) {
			t.Errorf("%s: el contenido de la copia no coincide", key)
		}
		if !versions[0].RetainUntil.Equal(record.DestroyAt) {
			t.Errorf("%s: retención hasta %v, esperaba destroy_at %v", key, versions[0].RetainUntil, record.DestroyAt)
		}
		if versions[0].ContentType != manifest.ContentTypePhoto {
			t.Errorf("%s: content-type %q", key, versions[0].ContentType)
		}
	}

	manifestVersions := f.audit.Versions(manifest.ManifestKey(f.id.String()))
	if len(manifestVersions) != 1 {
		t.Fatalf("manifiesto con %d versiones, esperaba 1", len(manifestVersions))
	}
	if !manifestVersions[0].RetainUntil.Equal(record.DestroyAt) {
		t.Errorf("el manifiesto no está bloqueado hasta destroy_at: %v", manifestVersions[0].RetainUntil)
	}

	parsed, err := manifest.Parse(manifestVersions[0].Body)
	if err != nil {
		t.Fatalf("el manifiesto no se puede leer: %v", err)
	}
	if parsed.AlertID != f.id.String() || parsed.DNIEncAudit != record.DNIEncAudit || parsed.PatEncAudit != record.PatEncAudit || parsed.AuditKeyID != record.AuditKeyID {
		t.Error("el manifiesto no refleja el registro")
	}
	if len(parsed.Evidence) != 2 || parsed.Evidence[0].Role != "GENERAL" || parsed.Evidence[1].Role != "PLATE" {
		t.Errorf("evidencia del manifiesto = %+v, esperaba GENERAL y PLATE en orden", parsed.Evidence)
	}
	for _, item := range parsed.Evidence {
		if item.Key != manifest.PhotoKey(f.id.String(), item.Role, item.Index) {
			t.Errorf("la clave %q no apunta al bucket de Audit", item.Key)
		}
	}
}

func TestDeliverActualizaLaFila(t *testing.T) {
	f := newDeliveryFixture(t)

	if err := f.deliver.Deliver(context.Background(), f.input()); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	got, _ := f.store.Lookup(f.id)
	if got.Status != domain.StatusDelivered {
		t.Fatalf("status = %s, esperaba DELIVERED", got.Status)
	}
	if got.DeliveredAt == nil || !got.DeliveredAt.Equal(fixedNow) {
		t.Errorf("delivered_at = %v", got.DeliveredAt)
	}
	if len(got.Evidence) != 2 {
		t.Errorf("evidencia de la fila = %d fotos, esperaba 2", len(got.Evidence))
	}
	manifestBody := f.audit.Versions(manifest.ManifestKey(f.id.String()))[0].Body
	if got.ManifestKey == nil || *got.ManifestKey != manifest.ManifestKey(f.id.String()) {
		t.Errorf("manifest_key = %v", got.ManifestKey)
	}
	if got.ManifestSHA256 == nil || *got.ManifestSHA256 != sha(manifestBody) {
		t.Error("manifest_sha256 no coincide con el manifiesto escrito")
	}
}

func TestDeliverSinRegistroEsTransitorio(t *testing.T) {
	f := newDeliveryFixture(t)
	in := f.input()
	in.AlertID = uuid.New()

	err := f.deliver.Deliver(context.Background(), in)

	if !errors.Is(err, domain.ErrRecordNotFound) {
		t.Fatalf("esperaba ErrRecordNotFound (orden invertido), obtuvo %v", err)
	}
	if f.audit.PutCalls != 0 || f.evidence.GetCalls != 0 {
		t.Error("sin registro no debe tocar S3")
	}
}

func TestDeliverSobreRegistroEntregadoHaceAckSinTocarS3(t *testing.T) {
	f := newDeliveryFixture(t)
	in := f.input()
	if err := f.deliver.Deliver(context.Background(), in); err != nil {
		t.Fatalf("primera entrega: %v", err)
	}
	puts, gets := f.audit.PutCalls, f.evidence.GetCalls

	if err := f.deliver.Deliver(context.Background(), in); err != nil {
		t.Fatalf("un delivered repetido debe hacer ack: %v", err)
	}

	if f.audit.PutCalls != puts || f.evidence.GetCalls != gets {
		t.Error("un delivered repetido no debe volver a leer ni escribir objetos")
	}
}

func TestDeliverConSHA256DistintoEsIntegridadYNoSubeNada(t *testing.T) {
	f := newDeliveryFixture(t)
	in := f.input()
	// GENERAL es la primera foto en el orden de procesamiento (rol e índice).
	for i := range in.Evidence {
		if in.Evidence[i].Role == "GENERAL" {
			in.Evidence[i].SHA256 = sha([]byte("otra cosa"))
		}
	}

	err := f.deliver.Deliver(context.Background(), in)

	if !errors.Is(err, domain.ErrIntegrity) {
		t.Fatalf("esperaba ErrIntegrity, obtuvo %v", err)
	}
	if f.audit.PutCalls != 0 {
		t.Errorf("se subieron %d objetos pese a la discrepancia", f.audit.PutCalls)
	}
	if got, _ := f.store.Lookup(f.id); got.Status != domain.StatusRecorded {
		t.Errorf("el registro pasó a %s pese a la discrepancia", got.Status)
	}
}

func TestDeliverConSHA256DistintoEnUnaFotoPosteriorNoEscribeManifiestoNiEntrega(t *testing.T) {
	f := newDeliveryFixture(t)
	in := f.input()
	for i := range in.Evidence {
		if in.Evidence[i].Role == "PLATE" {
			in.Evidence[i].SHA256 = sha([]byte("otra cosa"))
		}
	}

	err := f.deliver.Deliver(context.Background(), in)

	if !errors.Is(err, domain.ErrIntegrity) {
		t.Fatalf("esperaba ErrIntegrity, obtuvo %v", err)
	}
	if n := len(f.audit.Versions(manifest.ManifestKey(f.id.String()))); n != 0 {
		t.Errorf("se escribió el manifiesto (%d versiones) pese a la discrepancia", n)
	}
	if got, _ := f.store.Lookup(f.id); got.Status != domain.StatusRecorded {
		t.Errorf("el registro pasó a %s pese a la discrepancia", got.Status)
	}
}

func TestDeliverAceptaSHA256EnMayusculas(t *testing.T) {
	f := newDeliveryFixture(t)
	in := f.input()
	for i := range in.Evidence {
		in.Evidence[i].SHA256 = strings.ToUpper(in.Evidence[i].SHA256)
	}

	if err := f.deliver.Deliver(context.Background(), in); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
}

func TestDeliverConFotoInexistenteEsTransitorio(t *testing.T) {
	f := newDeliveryFixture(t)
	in := f.input()
	in.Evidence[0].Key = "alerts/" + f.id.String() + "/redacted/NOEXISTE-0.jpg"

	err := f.deliver.Deliver(context.Background(), in)

	if !errors.Is(err, domain.ErrObjectNotFound) {
		t.Fatalf("esperaba ErrObjectNotFound, obtuvo %v", err)
	}
	if errors.Is(err, domain.ErrIntegrity) {
		t.Error("una foto inexistente no es un error de integridad (permanente)")
	}
}

func TestDeliverConS3CaidoEsTransitorio(t *testing.T) {
	f := newDeliveryFixture(t)
	in := f.input()
	f.audit.ErrPut = domain.ErrStorageUnavailable

	err := f.deliver.Deliver(context.Background(), in)

	if !errors.Is(err, domain.ErrStorageUnavailable) {
		t.Fatalf("esperaba ErrStorageUnavailable, obtuvo %v", err)
	}
	if got, _ := f.store.Lookup(f.id); got.Status != domain.StatusRecorded {
		t.Error("el registro no debe pasar a DELIVERED si S3 falló")
	}
}

func TestDeliverReintentoTrasSubidaParcialCreaVersionesNuevas(t *testing.T) {
	f := newDeliveryFixture(t)
	in := f.input()
	f.store.ErrMarkDelivered = domain.ErrRepositoryUnavailable

	if err := f.deliver.Deliver(context.Background(), in); !errors.Is(err, domain.ErrRepositoryUnavailable) {
		t.Fatalf("primer intento: esperaba ErrRepositoryUnavailable, obtuvo %v", err)
	}
	f.store.ErrMarkDelivered = nil

	if err := f.deliver.Deliver(context.Background(), in); err != nil {
		t.Fatalf("el reintento debe completar la entrega: %v", err)
	}

	key := manifest.PhotoKey(f.id.String(), "GENERAL", 0)
	if n := len(f.audit.Versions(key)); n != 2 {
		t.Errorf("%d versiones de la foto, esperaba 2 (una por intento)", n)
	}
	if got, _ := f.store.Lookup(f.id); got.Status != domain.StatusDelivered {
		t.Errorf("status = %s, esperaba DELIVERED", got.Status)
	}
}

func TestDeliverConDestroyAtVencidoEsPermanente(t *testing.T) {
	f := newDeliveryFixture(t)
	in := f.input()
	f.deliver.now = func() time.Time { return fixedNow.Add(10 * 24 * time.Hour) }

	err := f.deliver.Deliver(context.Background(), in)

	if !errors.Is(err, domain.ErrRetentionElapsed) {
		t.Fatalf("esperaba ErrRetentionElapsed, obtuvo %v", err)
	}
	if f.audit.PutCalls != 0 {
		t.Error("no debe escribir objetos con una retención en el pasado")
	}
}

// --- Discarder ---

func TestDiscardBorraUnRegistroRecorded(t *testing.T) {
	store := testsupport.NewMemoryStore()
	id := uuid.New()
	if err := newRecorder(store).Record(context.Background(), recordedInput(id)); err != nil {
		t.Fatal(err)
	}

	if err := NewDiscarder(store).Discard(context.Background(), id, domain.DiscardReasonRejected); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	if _, ok := store.Lookup(id); ok {
		t.Error("el registro RECORDED debía borrarse")
	}
}

func TestDiscardSinRegistroEsTransitorio(t *testing.T) {
	store := testsupport.NewMemoryStore()

	err := NewDiscarder(store).Discard(context.Background(), uuid.New(), domain.DiscardReasonExpired)

	if !errors.Is(err, domain.ErrRecordNotFound) {
		t.Fatalf("esperaba ErrRecordNotFound (orden invertido), obtuvo %v", err)
	}
}

func TestDiscardSobreRegistroEntregadoNoBorraYHaceAck(t *testing.T) {
	store := testsupport.NewMemoryStore()
	id := uuid.New()
	if err := newRecorder(store).Record(context.Background(), recordedInput(id)); err != nil {
		t.Fatal(err)
	}
	record, _ := store.Lookup(id)
	record.Status = domain.StatusDelivered
	store.Put(record)

	err := NewDiscarder(store).Discard(context.Background(), id, domain.DiscardReasonUnclaimed)

	if err != nil {
		t.Fatalf("un discarded sobre un registro entregado debe hacer ack: %v", err)
	}
	if got, ok := store.Lookup(id); !ok || got.Status != domain.StatusDelivered {
		t.Error("un registro entregado nunca se borra antes de su vencimiento")
	}
}

func TestDiscardConBaseCaidaEsTransitorio(t *testing.T) {
	store := testsupport.NewMemoryStore()
	store.ErrGet = domain.ErrRepositoryUnavailable

	err := NewDiscarder(store).Discard(context.Background(), uuid.New(), domain.DiscardReasonRejected)

	if !errors.Is(err, domain.ErrRepositoryUnavailable) {
		t.Fatalf("esperaba ErrRepositoryUnavailable, obtuvo %v", err)
	}
}
