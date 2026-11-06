// Package export implementa auditctl export: por cada registro entregado,
// descarga el manifiesto y las fotos del bucket de Audit y escribe un informe de
// verificación que contrasta la fila contra el manifiesto, el manifiesto contra
// las fotos (SHA-256) y la retención de cada objeto.
package export

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/matiasfelau/vinculo-vial-audit/internal/domain"
	"github.com/matiasfelau/vinculo-vial-audit/internal/manifest"
	"github.com/matiasfelau/vinculo-vial-audit/internal/pathguard"
)

const (
	// ReportFileName es el nombre del informe de verificación de cada registro.
	ReportFileName = "report.json"

	filePerm = 0o600

	// retentionTolerance absorbe la precisión de segundos con la que S3 guarda la
	// fecha de retención.
	retentionTolerance = time.Second

	reportIndent = "  "
)

// Diferencias entre la fila y el manifiesto: nombres de campo fijos, que nunca
// reflejan los datos.
const (
	fieldAlertID        = "alert_id"
	fieldAlertType      = "alert_type"
	fieldAlertCreatedAt = "alert_created_at"
	fieldDeliveredAt    = "delivered_at"
	fieldDNIEncAudit    = "dni_enc_audit"
	fieldPatEncAudit    = "pat_enc_audit"
	fieldAuditKeyID     = "audit_key_id"
	fieldEvidence       = "evidence"
	fieldManifestKey    = "manifest_key"
	fieldManifestSHA256 = "manifest_sha256"
)

// recordSource lista los registros a exportar.
type recordSource interface {
	ListForExport(ctx context.Context, filter domain.ExportFilter) ([]domain.Record, error)
}

// objectSource lee un objeto del bucket de Audit con su estado de retención.
type objectSource interface {
	GetObject(ctx context.Context, key string) (domain.StoredObject, error)
}

// Exporter exporta registros de auditoría.
type Exporter struct {
	records recordSource
	objects objectSource
}

// New construye el Exporter.
func New(records recordSource, objects objectSource) *Exporter {
	return &Exporter{records: records, objects: objects}
}

// Retention es el estado de retención de un objeto.
type Retention struct {
	LockMode    string     `json:"lock_mode"`
	RetainUntil *time.Time `json:"retain_until"`
	LegalHold   bool       `json:"legal_hold"`
	// OK indica que el objeto tiene retención en modo GOVERNANCE o COMPLIANCE hasta
	// destroy_at o más tarde.
	OK bool `json:"retention_ok"`
}

// PhotoReport es el resultado de verificar una foto del manifiesto.
type PhotoReport struct {
	Role  string `json:"role"`
	Index int    `json:"index"`
	// Found indica que la foto se descargó y se escribió.
	Found bool `json:"found"`
	// SHA256Matches indica que el SHA-256 de la foto coincide con el del manifiesto.
	SHA256Matches bool       `json:"sha256_matches"`
	Retention     *Retention `json:"retention,omitempty"`
	Error         string     `json:"error,omitempty"`
}

// Report es el informe de verificación de un registro.
type Report struct {
	AlertID string `json:"alert_id"`
	Status  string `json:"status"`
	// ManifestFound indica que el manifiesto existe en el bucket.
	ManifestFound bool `json:"manifest_found"`
	// RowMatchesManifest indica que la fila coincide con el manifiesto.
	RowMatchesManifest bool `json:"row_matches_manifest"`
	// RowDifferences lista los campos en que la fila difiere del manifiesto.
	RowDifferences    []string      `json:"row_differences,omitempty"`
	ManifestRetention *Retention    `json:"manifest_retention,omitempty"`
	Photos            []PhotoReport `json:"photos"`
	Error             string        `json:"error,omitempty"`
}

// OK indica que el registro pasó todas las verificaciones.
func (r Report) OK() bool {
	if r.Error != "" || !r.ManifestFound || !r.RowMatchesManifest {
		return false
	}
	if r.ManifestRetention == nil || !r.ManifestRetention.OK {
		return false
	}
	for _, photo := range r.Photos {
		if !photo.Found || !photo.SHA256Matches || photo.Retention == nil || !photo.Retention.OK {
			return false
		}
	}
	return true
}

// Summary resume una exportación.
type Summary struct {
	// Exported son los registros entregados cuyo directorio se escribió.
	Exported int
	// Skipped son los registros que no están entregados (no tienen manifiesto).
	Skipped int
	// Discrepancies son los alert_id cuyo informe no pasó todas las verificaciones.
	Discrepancies []string
}

// Export escribe en outDir un subdirectorio por registro entregado que cumple el
// filtro, con manifest.json, las fotos ({role}-{index}.jpg) y report.json. Las
// diferencias no interrumpen la exportación: se informan en el informe y en
// Summary.Discrepancies.
func (e *Exporter) Export(ctx context.Context, filter domain.ExportFilter, outDir string) (Summary, error) {
	if err := pathguard.MkdirAll(outDir); err != nil {
		return Summary{}, err
	}

	records, err := e.records.ListForExport(ctx, filter)
	if err != nil {
		return Summary{}, fmt.Errorf("no se pudieron listar los registros: %w", err)
	}

	var summary Summary
	for _, record := range records {
		if record.Status != domain.StatusDelivered {
			summary.Skipped++
			continue
		}

		report, err := e.exportOne(ctx, record, outDir)
		if err != nil {
			return summary, err
		}
		summary.Exported++
		if !report.OK() {
			summary.Discrepancies = append(summary.Discrepancies, report.AlertID)
		}
	}
	return summary, nil
}

// exportOne exporta un registro. Devuelve error solo ante fallas locales (el
// disco, el contexto); las del bucket quedan en el informe.
func (e *Exporter) exportOne(ctx context.Context, record domain.Record, outDir string) (Report, error) {
	alertID := record.AlertID.String()
	report := Report{AlertID: alertID, Status: string(record.Status), Photos: []PhotoReport{}}

	dir := filepath.Join(outDir, alertID)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return report, fmt.Errorf("no se pudo crear el directorio del registro %s: %w", alertID, err)
	}

	manifestObject, err := e.objects.GetObject(ctx, manifest.ManifestKey(alertID))
	if err != nil {
		if ctx.Err() != nil {
			return report, ctx.Err()
		}
		report.Error = "no se pudo leer el manifiesto del bucket"
		return report, writeReport(dir, report)
	}
	report.ManifestFound = true
	report.ManifestRetention = retentionOf(manifestObject, record.DestroyAt)

	if err := writeFile(filepath.Join(dir, manifest.ManifestFileName), manifestObject.Body); err != nil {
		return report, err
	}

	parsed, err := manifest.Parse(manifestObject.Body)
	if err != nil {
		report.Error = "el manifiesto es ilegible"
		return report, writeReport(dir, report)
	}

	report.RowDifferences = compareRow(record, parsed, manifestObject.Body)
	report.RowMatchesManifest = len(report.RowDifferences) == 0

	for _, item := range parsed.Evidence {
		photo, err := e.exportPhoto(ctx, record, parsed.AlertID, item, dir)
		if err != nil {
			return report, err
		}
		report.Photos = append(report.Photos, photo)
	}

	return report, writeReport(dir, report)
}

// exportPhoto descarga una foto del manifiesto y la verifica. Solo lee la clave
// canónica {records/alert_id/role-index.jpg}: una clave distinta en el manifiesto
// no se sigue.
func (e *Exporter) exportPhoto(ctx context.Context, record domain.Record, manifestAlertID string, item manifest.EvidenceItem, dir string) (PhotoReport, error) {
	photo := PhotoReport{Role: item.Role, Index: item.Index}

	if !manifest.ValidRole(item.Role) || item.Index < 0 {
		photo.Error = "rol o índice inválido en el manifiesto"
		return photo, nil
	}
	if manifestAlertID != record.AlertID.String() || item.Key != manifest.PhotoKey(manifestAlertID, item.Role, item.Index) {
		photo.Error = "la clave de la foto no es la esperada"
		return photo, nil
	}

	object, err := e.objects.GetObject(ctx, item.Key)
	if err != nil {
		if ctx.Err() != nil {
			return photo, ctx.Err()
		}
		photo.Error = "no se pudo leer la foto del bucket"
		return photo, nil
	}

	if err := writeFile(filepath.Join(dir, manifest.PhotoFileName(item.Role, item.Index)), object.Body); err != nil {
		return photo, err
	}
	photo.Found = true
	photo.SHA256Matches = strings.EqualFold(sha256Hex(object.Body), item.SHA256)
	photo.Retention = retentionOf(object, record.DestroyAt)
	return photo, nil
}

// compareRow devuelve los campos en que la fila difiere del manifiesto. rawManifest
// permite contrastar también el SHA-256 del manifiesto registrado en la fila.
func compareRow(row domain.Record, m manifest.Manifest, rawManifest []byte) []string {
	var diffs []string
	add := func(different bool, field string) {
		if different {
			diffs = append(diffs, field)
		}
	}

	add(row.AlertID.String() != m.AlertID, fieldAlertID)
	add(row.AlertType != m.AlertType, fieldAlertType)
	add(!row.AlertCreatedAt.Equal(m.AlertCreatedAt), fieldAlertCreatedAt)
	add(row.DeliveredAt == nil || !row.DeliveredAt.Equal(m.DeliveredAt), fieldDeliveredAt)
	add(row.DNIEncAudit != m.DNIEncAudit, fieldDNIEncAudit)
	add(row.PatEncAudit != m.PatEncAudit, fieldPatEncAudit)
	add(row.AuditKeyID != m.AuditKeyID, fieldAuditKeyID)
	add(!sameEvidence(row.Evidence, m.Evidence), fieldEvidence)
	add(row.ManifestKey == nil || *row.ManifestKey != manifest.ManifestKey(m.AlertID), fieldManifestKey)
	add(row.ManifestSHA256 == nil || !strings.EqualFold(*row.ManifestSHA256, sha256Hex(rawManifest)), fieldManifestSHA256)
	return diffs
}

func sameEvidence(a, b []manifest.EvidenceItem) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Role != b[i].Role || a[i].Index != b[i].Index || a[i].Key != b[i].Key || !strings.EqualFold(a[i].SHA256, b[i].SHA256) {
			return false
		}
	}
	return true
}

// retentionOf resume la retención de un objeto y evalúa si es la esperada: un
// modo de Object Lock vigente hasta destroy_at o más tarde.
func retentionOf(object domain.StoredObject, destroyAt time.Time) *Retention {
	retention := &Retention{LockMode: object.LockMode, RetainUntil: object.RetainUntil, LegalHold: object.LegalHold}
	retention.OK = object.LockMode != "" &&
		object.RetainUntil != nil &&
		!object.RetainUntil.Before(destroyAt.Add(-retentionTolerance))
	return retention
}

func sha256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func writeReport(dir string, report Report) error {
	body, err := json.MarshalIndent(report, "", reportIndent)
	if err != nil {
		return fmt.Errorf("no se pudo serializar el informe: %w", err)
	}
	return writeFile(filepath.Join(dir, ReportFileName), append(body, '\n'))
}

// writeFile escribe un archivo nuevo con permisos 0600.
func writeFile(path string, body []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, filePerm)
	if err != nil {
		return fmt.Errorf("no se pudo crear %s: %w", path, err)
	}
	_, writeErr := file.Write(body)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return fmt.Errorf("no se pudo escribir %s", path)
	}
	return nil
}
