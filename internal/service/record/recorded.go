// Package record contiene los casos de uso de los eventos de auditoría que
// consume el servicio: crear el registro (recorded), archivar la evidencia
// (delivered) y descartar el registro (discarded).
package record

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-audit/internal/domain"
)

// hoursPerDay convierte AUDIT_RETENTION_DAYS a una duración.
const hoursPerDay = 24

// recordWriter es lo que Recorder necesita de la persistencia.
type recordWriter interface {
	Insert(ctx context.Context, record domain.Record) (bool, error)
}

// RecordedInput son los datos validados de audit.alert.recorded.
type RecordedInput struct {
	AlertID     uuid.UUID
	AlertType   string
	CreatedAt   time.Time
	DNIEncAudit string
	PatEncAudit string
	AuditKeyID  string
}

// Recorder crea el registro de auditoría de una alerta.
type Recorder struct {
	store         recordWriter
	retentionDays int
	now           func() time.Time
}

// NewRecorder construye el caso de uso. retentionDays es AUDIT_RETENTION_DAYS.
func NewRecorder(store recordWriter, retentionDays int) *Recorder {
	return &Recorder{store: store, retentionDays: retentionDays, now: func() time.Time { return time.Now().UTC() }}
}

// Record inserta el registro en estado RECORDED con destroy_at igual a la
// creación de la alerta más la retención. Es idempotente: un recorded repetido
// no cambia nada. Los criptogramas se guardan tal como llegan.
func (r *Recorder) Record(ctx context.Context, in RecordedInput) error {
	createdAt := truncateToStorage(in.CreatedAt)

	inserted, err := r.store.Insert(ctx, domain.Record{
		AlertID:        in.AlertID,
		AlertType:      in.AlertType,
		AlertCreatedAt: createdAt,
		DNIEncAudit:    in.DNIEncAudit,
		PatEncAudit:    in.PatEncAudit,
		AuditKeyID:     in.AuditKeyID,
		Status:         domain.StatusRecorded,
		RecordedAt:     truncateToStorage(r.now()),
		DestroyAt:      createdAt.Add(time.Duration(r.retentionDays) * hoursPerDay * time.Hour),
	})
	if err != nil {
		return fmt.Errorf("no se pudo crear el registro: %w", err)
	}

	if !inserted {
		slog.Info("registro ya existente, recorded repetido sin cambios", "alert_id", in.AlertID)
	}
	return nil
}

// truncateToStorage lleva un instante a UTC y a la precisión de timestamptz
// (microsegundos), de modo que lo guardado y lo que luego se escribe en el
// manifiesto coincidan exactamente.
func truncateToStorage(t time.Time) time.Time {
	return t.UTC().Truncate(time.Microsecond)
}
