package postgres

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-audit/internal/domain"
	"github.com/matiasfelau/vinculo-vial-audit/internal/manifest"
)

// auditRecordModel es la fila de audit_records. El esquema lo crea la migración
// versionada; este modelo solo mapea columnas.
type auditRecordModel struct {
	AlertID        uuid.UUID  `gorm:"column:alert_id;type:uuid;primaryKey"`
	AlertType      string     `gorm:"column:alert_type"`
	AlertCreatedAt time.Time  `gorm:"column:alert_created_at"`
	DNIEncAudit    string     `gorm:"column:dni_enc_audit"`
	PatEncAudit    string     `gorm:"column:pat_enc_audit"`
	AuditKeyID     string     `gorm:"column:audit_key_id"`
	Status         string     `gorm:"column:status"`
	RecordedAt     time.Time  `gorm:"column:recorded_at"`
	DeliveredAt    *time.Time `gorm:"column:delivered_at"`
	Evidence       *string    `gorm:"column:evidence;type:jsonb"`
	ManifestKey    *string    `gorm:"column:manifest_key"`
	ManifestSHA256 *string    `gorm:"column:manifest_sha256"`
	DestroyAt      time.Time  `gorm:"column:destroy_at"`
	JudicialHold   bool       `gorm:"column:judicial_hold"`
}

// TableName fija el nombre de la tabla.
func (auditRecordModel) TableName() string { return "audit_records" }

// discardedAlertModel es el tombstone de una alerta descartada: sin datos personales.
type discardedAlertModel struct {
	AlertID     uuid.UUID `gorm:"column:alert_id;type:uuid;primaryKey"`
	DiscardedAt time.Time `gorm:"column:discarded_at"`
}

// TableName fija el nombre de la tabla.
func (discardedAlertModel) TableName() string { return "discarded_alerts" }

func toModel(r domain.Record) (auditRecordModel, error) {
	evidence, err := encodeEvidence(r.Evidence)
	if err != nil {
		return auditRecordModel{}, err
	}
	return auditRecordModel{
		AlertID:        r.AlertID,
		AlertType:      r.AlertType,
		AlertCreatedAt: r.AlertCreatedAt,
		DNIEncAudit:    r.DNIEncAudit,
		PatEncAudit:    r.PatEncAudit,
		AuditKeyID:     r.AuditKeyID,
		Status:         string(r.Status),
		RecordedAt:     r.RecordedAt,
		DeliveredAt:    r.DeliveredAt,
		Evidence:       evidence,
		ManifestKey:    r.ManifestKey,
		ManifestSHA256: r.ManifestSHA256,
		DestroyAt:      r.DestroyAt,
		JudicialHold:   r.JudicialHold,
	}, nil
}

func (m auditRecordModel) toDomain() (domain.Record, error) {
	evidence, err := decodeEvidence(m.Evidence)
	if err != nil {
		return domain.Record{}, err
	}
	return domain.Record{
		AlertID:        m.AlertID,
		AlertType:      m.AlertType,
		AlertCreatedAt: m.AlertCreatedAt.UTC(),
		DNIEncAudit:    m.DNIEncAudit,
		PatEncAudit:    m.PatEncAudit,
		AuditKeyID:     m.AuditKeyID,
		Status:         domain.Status(m.Status),
		RecordedAt:     m.RecordedAt.UTC(),
		DeliveredAt:    utcPtr(m.DeliveredAt),
		Evidence:       evidence,
		ManifestKey:    m.ManifestKey,
		ManifestSHA256: m.ManifestSHA256,
		DestroyAt:      m.DestroyAt.UTC(),
		JudicialHold:   m.JudicialHold,
	}, nil
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	utc := t.UTC()
	return &utc
}

// encodeEvidence serializa la evidencia a JSON; una lista nula queda como NULL.
func encodeEvidence(items []manifest.EvidenceItem) (*string, error) {
	if items == nil {
		return nil, nil
	}
	body, err := json.Marshal(items)
	if err != nil {
		return nil, fmt.Errorf("postgres: no se pudo serializar la evidencia: %w", err)
	}
	text := string(body)
	return &text, nil
}

func decodeEvidence(raw *string) ([]manifest.EvidenceItem, error) {
	if raw == nil {
		return nil, nil
	}
	var items []manifest.EvidenceItem
	if err := json.Unmarshal([]byte(*raw), &items); err != nil {
		return nil, fmt.Errorf("postgres: evidencia ilegible: %w", err)
	}
	return items, nil
}
