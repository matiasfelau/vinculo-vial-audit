// Package sweeper destruye los registros de auditoría vencidos: borra todas las
// versiones de sus objetos del bucket de Audit y después la fila.
package sweeper

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-audit/internal/domain"
	"github.com/matiasfelau/vinculo-vial-audit/internal/manifest"
)

// expiredStore es lo que el sweeper necesita de la persistencia.
type expiredStore interface {
	ListExpired(ctx context.Context, now time.Time, after uuid.UUID, limit int) ([]uuid.UUID, error)
	Get(ctx context.Context, alertID uuid.UUID) (domain.Record, error)
	DeleteExpired(ctx context.Context, alertID uuid.UUID, now time.Time) (bool, error)
}

// objectPurger borra todas las versiones de los objetos bajo un prefijo.
type objectPurger interface {
	DeleteAllVersions(ctx context.Context, prefix string) error
}

// Result resume una vuelta del sweeper.
type Result struct {
	// Destroyed son los registros destruidos (objetos y fila).
	Destroyed int
	// Retained son los registros cuyo borrado S3 rechazó porque la retención sigue
	// vigente; se reintentan en la vuelta siguiente.
	Retained int
	// Failed son los registros que fallaron por otra causa; también se reintentan.
	Failed int
}

// Sweeper destruye los registros con destroy_at <= now y sin retención judicial.
type Sweeper struct {
	store     expiredStore
	purger    objectPurger
	batchSize int
	now       func() time.Time
}

// New construye el sweeper. batchSize acota cuántos registros se leen por página.
func New(store expiredStore, purger objectPurger, batchSize int) *Sweeper {
	return &Sweeper{store: store, purger: purger, batchSize: batchSize, now: func() time.Time { return time.Now().UTC() }}
}

// RunOnce ejecuta una vuelta completa. Recorre los registros vencidos por páginas
// con un cursor de alert_id, de modo que uno que falla no bloquea a los demás ni
// se reintenta dentro de la misma vuelta. Es idempotente: si la fila quedó a
// medio borrar (los objetos ya no están), la vuelta siguiente la retoma.
func (s *Sweeper) RunOnce(ctx context.Context) (Result, error) {
	var result Result
	now := s.now()
	cursor := uuid.Nil

	for {
		ids, err := s.store.ListExpired(ctx, now, cursor, s.batchSize)
		if err != nil {
			return result, err
		}

		for _, id := range ids {
			if err := ctx.Err(); err != nil {
				return result, err
			}
			s.destroy(ctx, id, now, &result)
			cursor = id
		}

		if len(ids) < s.batchSize {
			return result, nil
		}
	}
}

// destroy destruye un registro y acumula el resultado.
func (s *Sweeper) destroy(ctx context.Context, id uuid.UUID, now time.Time, result *Result) {
	record, err := s.store.Get(ctx, id)
	if errors.Is(err, domain.ErrRecordNotFound) {
		return
	}
	if err != nil {
		result.Failed++
		slog.Error("sweeper: no se pudo leer el registro", "alert_id", id, "error", err.Error())
		return
	}
	// La retención judicial puede haberse marcado después de listar el registro.
	if record.JudicialHold {
		return
	}

	if err := s.purger.DeleteAllVersions(ctx, manifest.RecordPrefix(id.String())); err != nil {
		if errors.Is(err, domain.ErrRetentionActive) {
			result.Retained++
			slog.Info("sweeper: la retención del registro sigue vigente, se reintenta en la vuelta siguiente", "alert_id", id)
			return
		}
		result.Failed++
		slog.Error("sweeper: no se pudieron borrar los objetos del registro", "alert_id", id, "error", err.Error())
		return
	}

	deleted, err := s.store.DeleteExpired(ctx, id, now)
	if err != nil {
		result.Failed++
		slog.Error("sweeper: no se pudo borrar la fila del registro, se retoma en la vuelta siguiente", "alert_id", id, "error", err.Error())
		return
	}
	if deleted {
		result.Destroyed++
	}
}

// Run ejecuta RunOnce al arrancar y después cada interval, hasta que ctx se
// cancele. El error de una vuelta se registra y no corta el ciclo.
func (s *Sweeper) Run(ctx context.Context, interval time.Duration) {
	s.runAndLog(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runAndLog(ctx)
		}
	}
}

func (s *Sweeper) runAndLog(ctx context.Context) {
	result, err := s.RunOnce(ctx)
	if err != nil && ctx.Err() == nil {
		slog.Error("sweeper: la vuelta falló", "error", err.Error())
	}
	if result != (Result{}) {
		slog.Info("sweeper: vuelta completada", "destruidos", result.Destroyed, "retenidos", result.Retained, "fallidos", result.Failed)
	}
}
