package record

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-audit/internal/domain"
)

// recordDiscarder es lo que Discarder necesita de la persistencia.
type recordDiscarder interface {
	Get(ctx context.Context, alertID uuid.UUID) (domain.Record, error)
	DiscardRecorded(ctx context.Context, alertID uuid.UUID, discardedAt time.Time) (bool, error)
	HasTombstone(ctx context.Context, alertID uuid.UUID) (bool, error)
}

// Discarder borra el registro de una alerta que ya no puede llegar a nadie.
type Discarder struct {
	store recordDiscarder
	now   func() time.Time
}

// NewDiscarder construye el caso de uso.
func NewDiscarder(store recordDiscarder) *Discarder {
	return &Discarder{store: store, now: func() time.Time { return time.Now().UTC() }}
}

// Discard resuelve un discarded:
//   - registro RECORDED: lo borra e inserta el tombstone, en la misma transacción;
//   - registro DELIVERED: hace ack sin borrar y registra un WARN solo con el
//     alert_id (un registro entregado nunca se borra antes de su vencimiento);
//   - sin registro pero con tombstone: ack (duplicado de un descarte ya resuelto);
//   - sin registro ni tombstone: domain.ErrRecordNotFound, transitorio (discarded
//     puede llegar antes que recorded).
func (d *Discarder) Discard(ctx context.Context, alertID uuid.UUID, reason string) error {
	record, err := d.store.Get(ctx, alertID)
	if errors.Is(err, domain.ErrRecordNotFound) {
		return d.resolveMissing(ctx, alertID)
	}
	if err != nil {
		return fmt.Errorf("no se pudo leer el registro: %w", err)
	}

	if record.Status == domain.StatusDelivered {
		slog.Warn("discarded sobre un registro entregado: no se borra", "alert_id", alertID)
		return nil
	}

	discarded, err := d.store.DiscardRecorded(ctx, alertID, truncateToStorage(d.now()))
	if err != nil {
		return fmt.Errorf("no se pudo descartar el registro: %w", err)
	}
	if !discarded {
		// Otro camino lo entregó o lo borró entre la lectura y el borrado
		// condicional. Si fue entregado, queda a salvo; si ya no existe, el
		// resultado buscado se cumplió.
		slog.Warn("el registro cambió durante el descarte, no se borró", "alert_id", alertID)
		return nil
	}

	slog.Info("registro descartado", "alert_id", alertID, "reason", reason)
	return nil
}

// resolveMissing decide qué hacer con un discarded sin registro: con tombstone es
// un duplicado (ack); sin él, el recorded todavía no llegó (transitorio).
func (d *Discarder) resolveMissing(ctx context.Context, alertID uuid.UUID) error {
	tombstoned, err := d.store.HasTombstone(ctx, alertID)
	if err != nil {
		return fmt.Errorf("no se pudo consultar el tombstone: %w", err)
	}
	if tombstoned {
		slog.Info("discarded duplicado, la alerta ya estaba descartada", "alert_id", alertID)
		return nil
	}
	return fmt.Errorf("no se pudo leer el registro: %w", domain.ErrRecordNotFound)
}
