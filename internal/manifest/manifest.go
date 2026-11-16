// Package manifest define el contenido del manifest.json que Audit guarda,
// bloqueado, junto a las fotos de cada registro, y las claves de objeto del
// bucket de Audit. Es un paquete de valores puros (solo biblioteca estándar):
// lo comparten el servicio y las CLIs, incluida audit-open, que no puede
// importar paquetes de red.
package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

const (
	// recordsPrefix es el prefijo común de los objetos de todos los registros.
	recordsPrefix = "records/"

	// ManifestFileName es el nombre del manifiesto dentro del prefijo del registro.
	ManifestFileName = "manifest.json"

	// ContentTypeManifest y ContentTypePhoto son los Content-Type con los que se
	// suben los objetos del registro.
	ContentTypeManifest = "application/json"
	ContentTypePhoto    = "image/jpeg"
)

// rolePattern restringe el rol de una foto: forma parte de la clave de la copia
// ({role}-{index}.jpg) y del nombre del archivo exportado, así que no admite "-",
// "/" ni "..".
var rolePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,31}$`)

// ValidRole indica si role es un rol de foto admisible.
func ValidRole(role string) bool {
	return rolePattern.MatchString(role)
}

// EvidenceItem describe una foto redactada. En el evento delivered Key es la
// clave en el bucket de evidencia; en el manifiesto y en la fila, la clave de la
// copia en el bucket de Audit.
type EvidenceItem struct {
	Role   string `json:"role"`
	Index  int    `json:"index"`
	Key    string `json:"key"`
	SHA256 string `json:"sha256"`
}

// Manifest es la fuente de verdad de un registro entregado: la fila de la base
// es solo un índice.
type Manifest struct {
	AlertID        string         `json:"alert_id"`
	AlertType      string         `json:"alert_type"`
	AlertCreatedAt time.Time      `json:"alert_created_at"`
	DeliveredAt    time.Time      `json:"delivered_at"`
	DNIEncAudit    string         `json:"dni_enc_audit"`
	PatEncAudit    string         `json:"pat_enc_audit"`
	AuditKeyID     string         `json:"audit_key_id"`
	Evidence       []EvidenceItem `json:"evidence"`
}

// RecordPrefix devuelve el prefijo (con barra final) de los objetos del registro.
func RecordPrefix(alertID string) string {
	return recordsPrefix + alertID + "/"
}

// ManifestKey devuelve la clave del manifiesto del registro.
func ManifestKey(alertID string) string {
	return RecordPrefix(alertID) + ManifestFileName
}

// PhotoKey devuelve la clave de la copia de una foto redactada en el bucket de
// Audit: records/{alert_id}/{role}-{index}.jpg.
func PhotoKey(alertID, role string, index int) string {
	return RecordPrefix(alertID) + PhotoFileName(role, index)
}

// PhotoFileName devuelve el nombre de una foto dentro del registro y de la
// exportación: {role}-{index}.jpg.
func PhotoFileName(role string, index int) string {
	return role + "-" + strconv.Itoa(index) + ".jpg"
}

// Marshal serializa el manifiesto de forma determinista: los mismos datos
// producen siempre los mismos bytes, de modo que un reintento escribe un
// manifiesto idéntico. Los instantes se normalizan a UTC.
func Marshal(m Manifest) ([]byte, error) {
	m.AlertCreatedAt = m.AlertCreatedAt.UTC()
	m.DeliveredAt = m.DeliveredAt.UTC()
	if m.Evidence == nil {
		m.Evidence = []EvidenceItem{}
	}

	body, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("manifest: no se pudo serializar: %w", err)
	}
	return body, nil
}

// Parse decodifica un manifiesto. Rechaza campos desconocidos y contenido
// posterior al objeto JSON: el manifiesto es una prueba, y un documento con
// campos o bytes extra no es el que escribió Audit.
func Parse(body []byte) (Manifest, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()

	var m Manifest
	if err := decoder.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("manifest: ilegible: %w", err)
	}
	if decoder.More() {
		return Manifest{}, errors.New("manifest: contenido inesperado tras el objeto JSON")
	}
	if m.AlertID == "" {
		return Manifest{}, errors.New("manifest: sin alert_id")
	}
	return m, nil
}
