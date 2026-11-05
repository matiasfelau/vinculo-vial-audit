package record

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-audit/internal/domain"
	"github.com/matiasfelau/vinculo-vial-audit/internal/manifest"
)

// minRetentionRemaining es el margen mínimo entre ahora y destroy_at para
// escribir un objeto con Object Lock: S3 rechaza una retención en el pasado, y
// una retención de segundos no protege nada.
const minRetentionRemaining = time.Minute

// deliveryStore es lo que Deliverer necesita de la persistencia.
type deliveryStore interface {
	Get(ctx context.Context, alertID uuid.UUID) (domain.Record, error)
	MarkDelivered(ctx context.Context, alertID uuid.UUID, delivery domain.Delivery) (bool, error)
}

// evidenceReader lee una foto redactada del bucket de evidencia.
type evidenceReader interface {
	Get(ctx context.Context, key string) ([]byte, error)
}

// auditWriter escribe un objeto bloqueado en el bucket de Audit.
type auditWriter interface {
	PutLocked(ctx context.Context, key string, body []byte, contentType string, retainUntil time.Time) error
}

// DeliveredInput son los datos validados de audit.alert.delivered. Evidence
// lleva las claves del bucket de evidencia.
type DeliveredInput struct {
	AlertID     uuid.UUID
	DeliveredAt time.Time
	Evidence    []manifest.EvidenceItem
}

// Deliverer archiva la evidencia de una alerta entregada.
type Deliverer struct {
	store    deliveryStore
	evidence evidenceReader
	audit    auditWriter
	now      func() time.Time
}

// NewDeliverer construye el caso de uso.
func NewDeliverer(store deliveryStore, evidence evidenceReader, audit auditWriter) *Deliverer {
	return &Deliverer{store: store, evidence: evidence, audit: audit, now: func() time.Time { return time.Now().UTC() }}
}

// Deliver archiva las fotos redactadas y el manifiesto en el bucket de Audit, con
// Object Lock hasta destroy_at, y pasa el registro a DELIVERED.
//
// Errores:
//   - domain.ErrRecordNotFound: el registro no existe todavía (transitorio);
//   - domain.ErrIntegrity y domain.ErrRetentionElapsed: permanentes;
//   - cualquier otro (S3 o base caídos): transitorio.
//
// Un reintento tras una subida parcial crea versiones nuevas de los objetos: es
// aceptable, el sweeper borra todas las versiones.
func (d *Deliverer) Deliver(ctx context.Context, in DeliveredInput) error {
	record, err := d.store.Get(ctx, in.AlertID)
	if err != nil {
		return fmt.Errorf("no se pudo leer el registro: %w", err)
	}
	if record.Status == domain.StatusDelivered {
		slog.Info("registro ya entregado, delivered repetido sin cambios", "alert_id", in.AlertID)
		return nil
	}
	if !record.DestroyAt.After(d.now().Add(minRetentionRemaining)) {
		return fmt.Errorf("registro de la alerta %s: %w", in.AlertID, domain.ErrRetentionElapsed)
	}

	archived, err := d.archivePhotos(ctx, record, in)
	if err != nil {
		return err
	}

	deliveredAt := truncateToStorage(in.DeliveredAt)
	manifestBody, err := manifest.Marshal(manifest.Manifest{
		AlertID:        record.AlertID.String(),
		AlertType:      record.AlertType,
		AlertCreatedAt: record.AlertCreatedAt,
		DeliveredAt:    deliveredAt,
		DNIEncAudit:    record.DNIEncAudit,
		PatEncAudit:    record.PatEncAudit,
		AuditKeyID:     record.AuditKeyID,
		Evidence:       archived,
	})
	if err != nil {
		return err
	}

	manifestKey := manifest.ManifestKey(record.AlertID.String())
	if err := d.audit.PutLocked(ctx, manifestKey, manifestBody, manifest.ContentTypeManifest, record.DestroyAt); err != nil {
		return fmt.Errorf("no se pudo guardar el manifiesto: %w", err)
	}

	updated, err := d.store.MarkDelivered(ctx, in.AlertID, domain.Delivery{
		DeliveredAt:    deliveredAt,
		Evidence:       archived,
		ManifestKey:    manifestKey,
		ManifestSHA256: sha256Hex(manifestBody),
	})
	if err != nil {
		return fmt.Errorf("no se pudo marcar el registro como entregado: %w", err)
	}
	if !updated {
		slog.Warn("el registro dejó de estar RECORDED durante la entrega", "alert_id", in.AlertID)
		return nil
	}

	slog.Info("registro entregado", "alert_id", in.AlertID, "fotos", len(archived))
	return nil
}

// archivePhotos lee cada foto del bucket de evidencia, verifica su SHA-256 y la
// sube bloqueada al bucket de Audit. Devuelve la evidencia con las claves del
// bucket de Audit, ordenada por rol e índice.
func (d *Deliverer) archivePhotos(ctx context.Context, record domain.Record, in DeliveredInput) ([]manifest.EvidenceItem, error) {
	items := append([]manifest.EvidenceItem(nil), in.Evidence...)
	sort.Slice(items, func(i, j int) bool {
		if items[i].Role != items[j].Role {
			return items[i].Role < items[j].Role
		}
		return items[i].Index < items[j].Index
	})

	archived := make([]manifest.EvidenceItem, 0, len(items))
	for _, item := range items {
		photo, err := d.evidence.Get(ctx, item.Key)
		if err != nil {
			return nil, fmt.Errorf("no se pudo leer la foto %s-%d: %w", item.Role, item.Index, err)
		}

		sum := sha256Hex(photo)
		if !strings.EqualFold(sum, item.SHA256) {
			return nil, fmt.Errorf("foto %s-%d: %w", item.Role, item.Index, domain.ErrIntegrity)
		}

		destKey := manifest.PhotoKey(record.AlertID.String(), item.Role, item.Index)
		if err := d.audit.PutLocked(ctx, destKey, photo, manifest.ContentTypePhoto, record.DestroyAt); err != nil {
			return nil, fmt.Errorf("no se pudo guardar la foto %s-%d: %w", item.Role, item.Index, err)
		}

		archived = append(archived, manifest.EvidenceItem{Role: item.Role, Index: item.Index, Key: destKey, SHA256: sum})
	}
	return archived, nil
}

func sha256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
