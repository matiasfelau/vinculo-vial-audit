// Package hold implementa auditctl hold: la retención judicial de un registro.
package hold

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-audit/internal/domain"
	"github.com/matiasfelau/vinculo-vial-audit/internal/manifest"
)

// holdStore marca la retención judicial en la fila.
type holdStore interface {
	SetJudicialHold(ctx context.Context, alertID uuid.UUID, hold bool) (bool, error)
}

// legalHolder aplica o quita el legal hold de S3 Object Lock bajo un prefijo.
type legalHolder interface {
	SetLegalHold(ctx context.Context, prefix string, on bool) (int, error)
}

// Holder aplica y quita la retención judicial.
type Holder struct {
	store  holdStore
	legals legalHolder
}

// New construye el Holder.
func New(store holdStore, legals legalHolder) *Holder {
	return &Holder{store: store, legals: legals}
}

// Hold marca (on) o desmarca (!on) judicial_hold y aplica o quita el legal hold de
// S3 Object Lock en todas las versiones de los objetos del registro. Devuelve
// cuántas versiones modificó en S3.
//
// El orden hace que un fallo a mitad de camino quede del lado seguro: al activar
// se marca primero la fila (el sweeper deja de tocar el registro) y después los
// objetos; al desactivar se quitan primero los objetos y después la fila. Repetir
// la operación completa lo que haya quedado pendiente.
func (h *Holder) Hold(ctx context.Context, alertID uuid.UUID, on bool) (int, error) {
	prefix := manifest.RecordPrefix(alertID.String())

	if on {
		if err := h.setRow(ctx, alertID, true); err != nil {
			return 0, err
		}
		changed, err := h.legals.SetLegalHold(ctx, prefix, true)
		if err != nil {
			return changed, fmt.Errorf("la fila quedó marcada pero no se pudo aplicar el legal hold de S3 (repetir el comando): %w", err)
		}
		return changed, nil
	}

	changed, err := h.legals.SetLegalHold(ctx, prefix, false)
	if err != nil {
		return changed, fmt.Errorf("no se pudo quitar el legal hold de S3, la fila sigue marcada (repetir el comando): %w", err)
	}
	if err := h.setRow(ctx, alertID, false); err != nil {
		return changed, err
	}
	return changed, nil
}

func (h *Holder) setRow(ctx context.Context, alertID uuid.UUID, on bool) error {
	found, err := h.store.SetJudicialHold(ctx, alertID, on)
	if err != nil {
		return fmt.Errorf("no se pudo actualizar judicial_hold: %w", err)
	}
	if !found {
		return domain.ErrRecordNotFound
	}
	return nil
}
