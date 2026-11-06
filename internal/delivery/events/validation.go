package events

import (
	"encoding/base64"
	"regexp"
	"time"

	"github.com/google/uuid"
)

const (
	// maxCryptogramLength acota el largo (en caracteres base64) de un criptograma.
	// Un DNI o una patente sellados con HPKE ocupan unas decenas de bytes; el tope
	// solo evita guardar contenido abusivo.
	maxCryptogramLength = 2048

	// maxAuditKeyIDLength es el largo de la columna audit_key_id.
	maxAuditKeyIDLength = 32
)

// auditKeyIDPattern restringe audit_key_id a un identificador corto (por ejemplo,
// 2026-11). El mismo valor se usa como clave del formato audit_key_id=base64 de
// audit-open, así que no admite "=" ni espacios.
var auditKeyIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// parseUUID valida un UUID no nulo. El error no refleja el valor recibido.
func parseUUID(raw *string, field string) (uuid.UUID, error) {
	if raw == nil {
		return uuid.Nil, invalid(field + " ausente")
	}
	id, err := uuid.Parse(*raw)
	if err != nil || id == uuid.Nil {
		return uuid.Nil, invalid(field + " inválido")
	}
	return id, nil
}

// parseRFC3339 valida un instante en RFC3339.
func parseRFC3339(raw *string, field string) (time.Time, error) {
	if raw == nil {
		return time.Time{}, invalid(field + " ausente")
	}
	instant, err := time.Parse(time.RFC3339, *raw)
	if err != nil {
		return time.Time{}, invalid(field + " no es RFC3339")
	}
	return instant, nil
}

// parseCryptogram valida que el criptograma sea base64 estándar no vacío y
// devuelve el texto tal como llegó: Audit nunca lo decodifica ni lo descifra.
func parseCryptogram(raw *string, field string) (string, error) {
	if raw == nil || *raw == "" {
		return "", invalid(field + " ausente")
	}
	if len(*raw) > maxCryptogramLength {
		return "", invalid(field + " excede el largo máximo")
	}
	decoded, err := base64.StdEncoding.DecodeString(*raw)
	if err != nil || len(decoded) == 0 {
		return "", invalid(field + " no es base64")
	}
	return *raw, nil
}

// parseAuditKeyID valida el identificador de la clave de Audit.
func parseAuditKeyID(raw *string) (string, error) {
	if raw == nil || *raw == "" {
		return "", invalid("audit_key_id ausente")
	}
	if len(*raw) > maxAuditKeyIDLength || !auditKeyIDPattern.MatchString(*raw) {
		return "", invalid("audit_key_id inválido")
	}
	return *raw, nil
}
