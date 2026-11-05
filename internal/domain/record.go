// Package domain contiene las entidades y los errores del Audit Service. No
// depende de infraestructura (base de datos, broker ni S3).
package domain

import (
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-audit/internal/manifest"
)

// Status es el estado de un registro de auditoría.
type Status string

const (
	// StatusRecorded es un registro creado cuyas fotos aún no se archivaron: la
	// alerta puede todavía no haber llegado a ningún destinatario.
	StatusRecorded Status = "RECORDED"
	// StatusDelivered es un registro con las fotos y el manifiesto bloqueados
	// en el bucket de Audit. Solo se borra por vencimiento.
	StatusDelivered Status = "DELIVERED"
)

// Tipos de alerta admitidos.
const (
	AlertTypeCrashed        = "CRASHED"
	AlertTypeParkedOnGarage = "PARKED_ON_GARAGE"
)

// Motivos de descarte admitidos en audit.alert.discarded.
const (
	DiscardReasonRejected  = "REJECTED"
	DiscardReasonExpired   = "EXPIRED"
	DiscardReasonUnclaimed = "UNCLAIMED"
)

// Record es el registro de auditoría de una alerta. Los criptogramas se guardan
// tal como llegan: Audit nunca los descifra.
type Record struct {
	AlertID        uuid.UUID
	AlertType      string
	AlertCreatedAt time.Time
	DNIEncAudit    string
	PatEncAudit    string
	AuditKeyID     string
	Status         Status
	RecordedAt     time.Time
	DeliveredAt    *time.Time
	Evidence       []manifest.EvidenceItem
	ManifestKey    *string
	ManifestSHA256 *string
	DestroyAt      time.Time
	JudicialHold   bool
}

// Delivery son los datos que pasan un registro de RECORDED a DELIVERED.
type Delivery struct {
	DeliveredAt    time.Time
	Evidence       []manifest.EvidenceItem
	ManifestKey    string
	ManifestSHA256 string
}

// IsValidAlertType indica si t es un tipo de alerta del contrato.
func IsValidAlertType(t string) bool {
	return t == AlertTypeCrashed || t == AlertTypeParkedOnGarage
}

// IsValidDiscardReason indica si r es un motivo de descarte del contrato.
func IsValidDiscardReason(r string) bool {
	return r == DiscardReasonRejected || r == DiscardReasonExpired || r == DiscardReasonUnclaimed
}

// StoredObject es un objeto leído de S3 con su estado de retención.
type StoredObject struct {
	Body []byte
	// LockMode es el modo de Object Lock del objeto, vacío si no tiene retención.
	LockMode string
	// RetainUntil es el fin de la retención, nil si no tiene.
	RetainUntil *time.Time
	// LegalHold indica si el objeto tiene legal hold.
	LegalHold bool
}

// ExportFilter filtra los registros de auditctl export: por alert_id, o por el
// rango cerrado [From, To] de alert_created_at.
type ExportFilter struct {
	AlertID *uuid.UUID
	From    time.Time
	To      time.Time
}

// InsertResult es el desenlace de insertar un registro.
type InsertResult int

const (
	// InsertCreated indica que se creó el registro.
	InsertCreated InsertResult = iota
	// InsertExisting indica que ya existía un registro con ese alert_id: no se cambió nada.
	InsertExisting
	// InsertTombstoned indica que la alerta ya fue descartada: no se insertó nada.
	InsertTombstoned
)
