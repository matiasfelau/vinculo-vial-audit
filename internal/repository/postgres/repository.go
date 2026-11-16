package postgres

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/matiasfelau/vinculo-vial-audit/internal/domain"
)

// defaultQueryTimeout acota cada consulta cuando el llamador no especifica un
// valor propio vía WithQueryTimeout. Se mantiene alineado con el default de
// DB_QUERY_TIMEOUT_MS (ver pkg/config).
const defaultQueryTimeout = 1500 * time.Millisecond

// sqlstate de PostgreSQL que classifyError reconoce como indisponibilidad.
const (
	sqlstateConnectionClass = "08"
	sqlstateResourcesClass  = "53"
	sqlstateQueryCanceled   = "57014"
	sqlstateShutdownPrefix  = "57P0"
)

// classifyError distingue una indisponibilidad de infraestructura (la base es
// inalcanzable o la consulta excedió su plazo) de cualquier otro error. Solo la
// primera categoría se envuelve en domain.ErrRepositoryUnavailable.
func classifyError(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return errors.Join(domain.ErrRepositoryUnavailable, err)
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		return errors.Join(domain.ErrRepositoryUnavailable, err)
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		code := pgErr.Code
		if len(code) >= 2 && (code[:2] == sqlstateConnectionClass || code[:2] == sqlstateResourcesClass ||
			code == sqlstateQueryCanceled || (len(code) >= 4 && code[:4] == sqlstateShutdownPrefix)) {
			return errors.Join(domain.ErrRepositoryUnavailable, err)
		}
	}

	return err
}

// AuditRepository implementa la persistencia de audit_records sobre PostgreSQL vía GORM.
type AuditRepository struct {
	db           *gorm.DB
	queryTimeout time.Duration
}

// Option configura aspectos opcionales de AuditRepository.
type Option func(*AuditRepository)

// WithQueryTimeout fija el plazo máximo de cada consulta.
func WithQueryTimeout(timeout time.Duration) Option {
	return func(r *AuditRepository) { r.queryTimeout = timeout }
}

// NewAuditRepository construye el repositorio. Sin WithQueryTimeout aplica
// defaultQueryTimeout.
func NewAuditRepository(db *gorm.DB, opts ...Option) *AuditRepository {
	r := &AuditRepository{db: db, queryTimeout: defaultQueryTimeout}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Ping verifica que la base responda, con el plazo de consulta.
func (r *AuditRepository) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()

	sqlDB, err := r.db.DB()
	if err != nil {
		return classifyError(err)
	}
	return classifyError(sqlDB.PingContext(ctx))
}

// Insert crea el registro en una transacción. Si la alerta ya fue descartada
// (existe su tombstone) no inserta nada y devuelve InsertTombstoned. Si ya existe
// un registro con el mismo alert_id no cambia nada (ON CONFLICT DO NOTHING) y
// devuelve InsertExisting.
func (r *AuditRepository) Insert(ctx context.Context, record domain.Record) (domain.InsertResult, error) {
	ctx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()

	model, err := toModel(record)
	if err != nil {
		return domain.InsertCreated, err
	}

	result := domain.InsertCreated
	err = r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var tombstones int64
		if err := tx.Model(&discardedAlertModel{}).Where("alert_id = ?", record.AlertID).Count(&tombstones).Error; err != nil {
			return err
		}
		if tombstones > 0 {
			result = domain.InsertTombstoned
			return nil
		}

		insert := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "alert_id"}}, DoNothing: true}).Create(&model)
		if insert.Error != nil {
			return insert.Error
		}
		if insert.RowsAffected != 1 {
			result = domain.InsertExisting
		}
		return nil
	})
	if err != nil {
		return domain.InsertCreated, classifyError(err)
	}
	return result, nil
}

// Get devuelve el registro, o domain.ErrRecordNotFound si no existe.
func (r *AuditRepository) Get(ctx context.Context, alertID uuid.UUID) (domain.Record, error) {
	ctx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()

	var model auditRecordModel
	err := r.db.WithContext(ctx).Where("alert_id = ?", alertID).Take(&model).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return domain.Record{}, domain.ErrRecordNotFound
	}
	if err != nil {
		return domain.Record{}, classifyError(err)
	}
	return model.toDomain()
}

// MarkDelivered pasa el registro de RECORDED a DELIVERED con una única
// sentencia, en una transacción explícita. Devuelve false si el registro ya no
// está RECORDED (entregado por otra entrega, o borrado).
func (r *AuditRepository) MarkDelivered(ctx context.Context, alertID uuid.UUID, delivery domain.Delivery) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()

	evidence, err := encodeEvidence(delivery.Evidence)
	if err != nil {
		return false, err
	}

	var updated bool
	err = r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&auditRecordModel{}).
			Where("alert_id = ? AND status = ?", alertID, string(domain.StatusRecorded)).
			Updates(map[string]any{
				"status":          string(domain.StatusDelivered),
				"delivered_at":    delivery.DeliveredAt,
				"evidence":        evidence,
				"manifest_key":    delivery.ManifestKey,
				"manifest_sha256": delivery.ManifestSHA256,
			})
		updated = result.RowsAffected == 1
		return result.Error
	})
	if err != nil {
		return false, classifyError(err)
	}
	return updated, nil
}

// DiscardRecorded borra el registro solo si sigue RECORDED e inserta el tombstone
// de la alerta, en la misma transacción: o ocurren las dos cosas o ninguna. Un
// registro entregado nunca se borra antes de su vencimiento. Devuelve si borró.
func (r *AuditRepository) DiscardRecorded(ctx context.Context, alertID uuid.UUID, discardedAt time.Time) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()

	var discarded bool
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Where("alert_id = ? AND status = ?", alertID, string(domain.StatusRecorded)).Delete(&auditRecordModel{})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return nil
		}

		tombstone := discardedAlertModel{AlertID: alertID, DiscardedAt: discardedAt}
		insert := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "alert_id"}}, DoNothing: true}).Create(&tombstone)
		if insert.Error != nil {
			return insert.Error
		}
		discarded = true
		return nil
	})
	if err != nil {
		return false, classifyError(err)
	}
	return discarded, nil
}

// HasTombstone indica si la alerta fue descartada.
func (r *AuditRepository) HasTombstone(ctx context.Context, alertID uuid.UUID) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()

	var count int64
	if err := r.db.WithContext(ctx).Model(&discardedAlertModel{}).Where("alert_id = ?", alertID).Count(&count).Error; err != nil {
		return false, classifyError(err)
	}
	return count > 0, nil
}

// DeleteTombstonesBefore borra los tombstones descartados antes de cutoff y
// devuelve cuántos borró.
func (r *AuditRepository) DeleteTombstonesBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()

	var deleted int64
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Where("discarded_at < ?", cutoff).Delete(&discardedAlertModel{})
		deleted = result.RowsAffected
		return result.Error
	})
	if err != nil {
		return 0, classifyError(err)
	}
	return deleted, nil
}

// ListExpired devuelve hasta limit alert_id vencidos (destroy_at <= now) y sin
// retención judicial, con alert_id mayor que after y en orden de alert_id. El
// cursor after permite al sweeper recorrer todo el universo sin volver a
// encontrar los registros que ya intentó en la misma vuelta.
func (r *AuditRepository) ListExpired(ctx context.Context, now time.Time, after uuid.UUID, limit int) ([]uuid.UUID, error) {
	ctx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()

	var ids []uuid.UUID
	err := r.db.WithContext(ctx).Model(&auditRecordModel{}).
		Where("destroy_at <= ? AND judicial_hold = false AND alert_id > ?", now, after).
		Order("alert_id").
		Limit(limit).
		Pluck("alert_id", &ids).Error
	if err != nil {
		return nil, classifyError(err)
	}
	return ids, nil
}

// DeleteExpired borra la fila si sigue vencida y sin retención judicial. La
// condición se evalúa en la sentencia de borrado: un hold aplicado mientras el
// sweeper trabajaba impide el borrado de la fila.
func (r *AuditRepository) DeleteExpired(ctx context.Context, alertID uuid.UUID, now time.Time) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()

	var deleted bool
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Where("alert_id = ? AND destroy_at <= ? AND judicial_hold = false", alertID, now).Delete(&auditRecordModel{})
		deleted = result.RowsAffected == 1
		return result.Error
	})
	if err != nil {
		return false, classifyError(err)
	}
	return deleted, nil
}

// ListForExport devuelve los registros que cumplen el filtro, por fecha de
// creación de la alerta. Es de uso exclusivo de las CLIs.
func (r *AuditRepository) ListForExport(ctx context.Context, filter domain.ExportFilter) ([]domain.Record, error) {
	ctx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()

	query := r.db.WithContext(ctx).Model(&auditRecordModel{})
	switch {
	case filter.AlertID != nil:
		query = query.Where("alert_id = ?", *filter.AlertID)
	case !filter.From.IsZero() && !filter.To.IsZero():
		query = query.Where("alert_created_at >= ? AND alert_created_at <= ?", filter.From, filter.To)
	default:
		return nil, errors.New("postgres: el filtro de exportación necesita alert_id o un rango")
	}

	var models []auditRecordModel
	if err := query.Order("alert_created_at, alert_id").Find(&models).Error; err != nil {
		return nil, classifyError(err)
	}

	records := make([]domain.Record, 0, len(models))
	for _, model := range models {
		record, err := model.toDomain()
		if err != nil {
			return nil, fmt.Errorf("postgres: registro ilegible: %w", err)
		}
		records = append(records, record)
	}
	return records, nil
}

// SetJudicialHold marca o desmarca la retención judicial del registro. Devuelve
// false si el registro no existe.
func (r *AuditRepository) SetJudicialHold(ctx context.Context, alertID uuid.UUID, hold bool) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()

	var found bool
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&auditRecordModel{}).Where("alert_id = ?", alertID).Update("judicial_hold", hold)
		found = result.RowsAffected == 1
		return result.Error
	})
	if err != nil {
		return false, classifyError(err)
	}
	return found, nil
}
