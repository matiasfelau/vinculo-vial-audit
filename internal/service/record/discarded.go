package record

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-audit/internal/domain"
)

// recordDiscarder es lo que Discarder necesita de la persistencia.
type recordDiscarder interface {
	Get(ctx context.Context, alertID uuid.UUID) (domain.Record, error)
	DeleteRecorded(ctx context.Context, alertID uuid.UUID) (bool, error)
}

// Discarder borra el registro de una alerta que ya no puede llegar a nadie.
type Discarder struct {
	store recordDiscarder
}

// NewDiscarder construye el caso de uso.
func NewDiscarder(store recordDiscarder) *Discarder {
	return &Discarder{store: store}
}

// Discard borra el registro si está RECORDED. Si no existe devuelve
// domain.ErrRecordNotFound (transitorio: discarded puede llegar antes que
// recorded). Si está DELIVERED hace ack sin borrar y registra un WARN solo con el
// alert_id: un registro entregado nunca se borra antes de su vencimiento.
func (d *Discarder) Discard(ctx context.Context, alertID uuid.UUID, reason string) error {
	record, err := d.store.Get(ctx, alertID)
	if err != nil {
		return fmt.Errorf("no se pudo leer el registro: %w", err)
	}

	if record.Status == domain.StatusDelivered {
		slog.Warn("discarded sobre un registro entregado: no se borra", "alert_id", alertID)
		return nil
	}

	deleted, err := d.store.DeleteRecorded(ctx, alertID)
	if err != nil {
		return fmt.Errorf("no se pudo borrar el registro: %w", err)
	}
	if !deleted {
		// Otro camino lo entregó o lo borró entre la lectura y el borrado
		// condicional. Si fue entregado, queda a salvo; si ya no existe, el
		// resultado buscado se cumplió.
		slog.Warn("el registro cambió durante el descarte, no se borró", "alert_id", alertID)
		return nil
	}

	slog.Info("registro descartado", "alert_id", alertID, "reason", reason)
	return nil
}
