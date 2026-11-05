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
	DeleteTombstonesBefore(ctx context.Context, cutoff time.Time) (int64, error)
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
	// Failed son los registros (o la depuración de tombstones) que fallaron por otra
	// causa; también se reintentan.
	Failed int
	// TombstonesDeleted son los tombstones de descartes depurados por antigüedad.
	TombstonesDeleted int
}

// Sweeper destruye los registros con destroy_at <= now y sin retención judicial.
type Sweeper struct {
	store              expiredStore
	purger             objectPurger
	batchSize          int
	tombstoneRetention time.Duration
	now                func() time.Time
}

// Option configura aspectos opcionales del Sweeper.
type Option func(*Sweeper)

// WithClock reemplaza el reloj. Permite simular el paso del tiempo en las pruebas
// sin esperarlo.
func WithClock(now func() time.Time) Option {
	return func(s *Sweeper) { s.now = now }
}

// New construye el sweeper. batchSize acota cuántos registros se leen por página y
// tombstoneRetention (AUDIT_TOMBSTONE_DAYS) cuánto se conserva el tombstone de un
// descarte.
func New(store expiredStore, purger objectPurger, batchSize int, tombstoneRetention time.Duration, opts ...Option) *Sweeper {
	s := &Sweeper{store: store, purger: purger, batchSize: batchSize, tombstoneRetention: tombstoneRetention, now: func() time.Time { return time.Now().UTC() }}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// RunOnce ejecuta una vuelta completa. Recorre los registros vencidos por páginas
// con un cursor de alert_id, de modo que uno que falla no bloquea a los demás ni
// se reintenta dentro de la misma vuelta. Es idempotente: si la fila quedó a
// medio borrar (los objetos ya no están), la vuelta siguiente la retoma.
//
// Además depura los tombstones de descartes con más de tombstoneRetention, aun
// si la destrucción de registros falló.
func (s *Sweeper) RunOnce(ctx context.Context) (Result, error) {
	var result Result
	now := s.now()

	err := s.sweepRecords(ctx, now, &result)
	s.purgeTombstones(ctx, now, &result)
	return result, err
}

// sweepRecords destruye los registros vencidos, página por página.
func (s *Sweeper) sweepRecords(ctx context.Context, now time.Time, result *Result) error {
	cursor := uuid.Nil

	for {
		ids, err := s.store.ListExpired(ctx, now, cursor, s.batchSize)
		if err != nil {
			return err
		}

		for _, id := range ids {
			if err := ctx.Err(); err != nil {
				return err
			}
			s.destroy(ctx, id, now, result)
			cursor = id
		}

		if len(ids) < s.batchSize {
			return nil
		}
	}
}

// purgeTombstones borra los tombstones con más de tombstoneRetention.
func (s *Sweeper) purgeTombstones(ctx context.Context, now time.Time, result *Result) {
	if ctx.Err() != nil {
		return
	}
	deleted, err := s.store.DeleteTombstonesBefore(ctx, now.Add(-s.tombstoneRetention))
	if err != nil {
		result.Failed++
		slog.Error("sweeper: no se pudieron depurar los tombstones de descartes", "error", err.Error())
		return
	}
	result.TombstonesDeleted = int(deleted)
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
		slog.Info("sweeper: vuelta completada", "destruidos", result.Destroyed, "retenidos", result.Retained, "fallidos", result.Failed, "tombstones_depurados", result.TombstonesDeleted)
	}
}
