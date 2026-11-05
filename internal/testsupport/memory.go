// Package testsupport reúne dobles en memoria que comparten las pruebas de los
// casos de uso, el sweeper, los consumidores y la exportación: una base de
// registros y dos buckets de objetos con versiones y retención. Solo lo importan
// archivos _test.go.
package testsupport

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-audit/internal/domain"
)

// MemoryStore es una base de registros en memoria. Cada operación puede fallar
// con el error configurado en Err* para simular una base caída.
type MemoryStore struct {
	mu      sync.Mutex
	records map[uuid.UUID]domain.Record
	// tombstones guarda el instante de descarte de cada alerta descartada.
	tombstones map[uuid.UUID]time.Time

	// ErrGet, ErrInsert, ErrMarkDelivered y ErrDelete fuerzan el error de la
	// operación correspondiente.
	ErrGet           error
	ErrInsert        error
	ErrMarkDelivered error
	ErrDelete        error

	// InsertCalls cuenta las inserciones intentadas.
	InsertCalls int
}

// NewMemoryStore construye una base vacía.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: make(map[uuid.UUID]domain.Record), tombstones: make(map[uuid.UUID]time.Time)}
}

// Put agrega o reemplaza un registro directamente.
func (s *MemoryStore) Put(record domain.Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[record.AlertID] = record
}

// Lookup devuelve el registro sin pasar por las fallas configuradas.
func (s *MemoryStore) Lookup(id uuid.UUID) (domain.Record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[id]
	return record, ok
}

// Len devuelve la cantidad de registros.
func (s *MemoryStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

// Insert implementa la inserción con ON CONFLICT DO NOTHING y respeta el tombstone.
func (s *MemoryStore) Insert(_ context.Context, record domain.Record) (domain.InsertResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.InsertCalls++
	if s.ErrInsert != nil {
		return domain.InsertCreated, s.ErrInsert
	}
	if _, discarded := s.tombstones[record.AlertID]; discarded {
		return domain.InsertTombstoned, nil
	}
	if _, exists := s.records[record.AlertID]; exists {
		return domain.InsertExisting, nil
	}
	s.records[record.AlertID] = record
	return domain.InsertCreated, nil
}

// AddTombstone agrega directamente el tombstone de una alerta.
func (s *MemoryStore) AddTombstone(id uuid.UUID, discardedAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tombstones[id] = discardedAt
}

// HasTombstone indica si la alerta fue descartada.
func (s *MemoryStore) HasTombstone(_ context.Context, id uuid.UUID) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ErrGet != nil {
		return false, s.ErrGet
	}
	_, ok := s.tombstones[id]
	return ok, nil
}

// TombstoneCount devuelve la cantidad de tombstones.
func (s *MemoryStore) TombstoneCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tombstones)
}

// DeleteTombstonesBefore borra los tombstones anteriores a cutoff.
func (s *MemoryStore) DeleteTombstonesBefore(_ context.Context, cutoff time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var deleted int64
	for id, at := range s.tombstones {
		if at.Before(cutoff) {
			delete(s.tombstones, id)
			deleted++
		}
	}
	return deleted, nil
}

// Get devuelve el registro o domain.ErrRecordNotFound.
func (s *MemoryStore) Get(_ context.Context, id uuid.UUID) (domain.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ErrGet != nil {
		return domain.Record{}, s.ErrGet
	}
	record, ok := s.records[id]
	if !ok {
		return domain.Record{}, domain.ErrRecordNotFound
	}
	return record, nil
}

// MarkDelivered pasa un registro RECORDED a DELIVERED.
func (s *MemoryStore) MarkDelivered(_ context.Context, id uuid.UUID, delivery domain.Delivery) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ErrMarkDelivered != nil {
		return false, s.ErrMarkDelivered
	}
	record, ok := s.records[id]
	if !ok || record.Status != domain.StatusRecorded {
		return false, nil
	}
	record.Status = domain.StatusDelivered
	deliveredAt := delivery.DeliveredAt
	record.DeliveredAt = &deliveredAt
	record.Evidence = delivery.Evidence
	record.ManifestKey = &delivery.ManifestKey
	record.ManifestSHA256 = &delivery.ManifestSHA256
	s.records[id] = record
	return true, nil
}

// DiscardRecorded borra el registro si está RECORDED e inserta el tombstone.
func (s *MemoryStore) DiscardRecorded(_ context.Context, id uuid.UUID, discardedAt time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ErrDelete != nil {
		return false, s.ErrDelete
	}
	record, ok := s.records[id]
	if !ok || record.Status != domain.StatusRecorded {
		return false, nil
	}
	delete(s.records, id)
	s.tombstones[id] = discardedAt
	return true, nil
}

// ListExpired devuelve los alert_id vencidos y sin retención judicial, mayores que
// after, en orden de alert_id.
func (s *MemoryStore) ListExpired(_ context.Context, now time.Time, after uuid.UUID, limit int) ([]uuid.UUID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var ids []uuid.UUID
	for id, record := range s.records {
		if !record.DestroyAt.After(now) && !record.JudicialHold && strings.Compare(id.String(), after.String()) > 0 {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	if len(ids) > limit {
		ids = ids[:limit]
	}
	return ids, nil
}

// DeleteExpired borra la fila si sigue vencida y sin retención judicial.
func (s *MemoryStore) DeleteExpired(_ context.Context, id uuid.UUID, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ErrDelete != nil {
		return false, s.ErrDelete
	}
	record, ok := s.records[id]
	if !ok || record.DestroyAt.After(now) || record.JudicialHold {
		return false, nil
	}
	delete(s.records, id)
	return true, nil
}

// MemoryObjects es un bucket en memoria con versiones y retención.
type MemoryObjects struct {
	mu      sync.Mutex
	objects map[string][]StoredVersion

	// ErrGet, ErrPut y ErrDelete fuerzan el error de la operación correspondiente.
	ErrGet    error
	ErrPut    error
	ErrDelete error

	// PutCalls y GetCalls cuentan las operaciones intentadas.
	PutCalls int
	GetCalls int

	// Now es el reloj con el que se evalúa la retención al borrar. Si es nil, no hay
	// retención que respetar.
	Now func() time.Time
}

// StoredVersion es una versión de un objeto.
type StoredVersion struct {
	Body        []byte
	ContentType string
	RetainUntil time.Time
	LockMode    string
	LegalHold   bool
}

// NewMemoryObjects construye un bucket vacío.
func NewMemoryObjects() *MemoryObjects {
	return &MemoryObjects{objects: make(map[string][]StoredVersion)}
}

// Seed agrega un objeto sin retención (por ejemplo, una foto del bucket de evidencia).
func (m *MemoryObjects) Seed(key string, body []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objects[key] = append(m.objects[key], StoredVersion{Body: body})
}

// Get devuelve la versión vigente de la clave.
func (m *MemoryObjects) Get(ctx context.Context, key string) ([]byte, error) {
	object, err := m.GetObject(ctx, key)
	if err != nil {
		return nil, err
	}
	return object.Body, nil
}

// GetObject devuelve la versión vigente con su estado de retención.
func (m *MemoryObjects) GetObject(_ context.Context, key string) (domain.StoredObject, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.GetCalls++
	if m.ErrGet != nil {
		return domain.StoredObject{}, m.ErrGet
	}
	versions := m.objects[key]
	if len(versions) == 0 {
		return domain.StoredObject{}, domain.ErrObjectNotFound
	}
	latest := versions[len(versions)-1]

	object := domain.StoredObject{Body: latest.Body, LockMode: latest.LockMode, LegalHold: latest.LegalHold}
	if !latest.RetainUntil.IsZero() {
		retainUntil := latest.RetainUntil
		object.RetainUntil = &retainUntil
	}
	return object, nil
}

// PutLocked agrega una versión nueva con retención.
func (m *MemoryObjects) PutLocked(_ context.Context, key string, body []byte, contentType string, retainUntil time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.PutCalls++
	if m.ErrPut != nil {
		return m.ErrPut
	}
	m.objects[key] = append(m.objects[key], StoredVersion{
		Body:        append([]byte(nil), body...),
		ContentType: contentType,
		RetainUntil: retainUntil,
		LockMode:    "GOVERNANCE",
	})
	return nil
}

// DeleteAllVersions borra todas las versiones bajo prefix. Si alguna sigue con
// retención o legal hold, devuelve domain.ErrRetentionActive sin borrar ninguna.
func (m *MemoryObjects) DeleteAllVersions(_ context.Context, prefix string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.ErrDelete != nil {
		return m.ErrDelete
	}

	var keys []string
	for key, versions := range m.objects {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		for _, version := range versions {
			if version.LegalHold || (m.Now != nil && version.RetainUntil.After(m.Now())) {
				return domain.ErrRetentionActive
			}
		}
		keys = append(keys, key)
	}
	for _, key := range keys {
		delete(m.objects, key)
	}
	return nil
}

// SetLegalHold aplica o quita el legal hold en todas las versiones bajo prefix.
func (m *MemoryObjects) SetLegalHold(_ context.Context, prefix string, on bool) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	changed := 0
	for key, versions := range m.objects {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		for i := range versions {
			versions[i].LegalHold = on
			changed++
		}
	}
	return changed, nil
}

// Versions devuelve las versiones de la clave.
func (m *MemoryObjects) Versions(key string) []StoredVersion {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]StoredVersion(nil), m.objects[key]...)
}

// Keys devuelve las claves con al menos una versión, ordenadas.
func (m *MemoryObjects) Keys() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	keys := make([]string, 0, len(m.objects))
	for key := range m.objects {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// Replace reemplaza el cuerpo de la versión vigente (para simular alteraciones).
func (m *MemoryObjects) Replace(key string, body []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if versions := m.objects[key]; len(versions) > 0 {
		versions[len(versions)-1].Body = body
	}
}
