package events

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-audit/internal/domain"
	"github.com/matiasfelau/vinculo-vial-audit/internal/manifest"
	"github.com/matiasfelau/vinculo-vial-audit/internal/service/record"
)

// eventTypeDelivered es el eventType (y routing key) con el que Alert informa que
// la alerta llegó por primera vez a un destinatario.
const eventTypeDelivered = "audit.alert.delivered"

const (
	// maxEvidenceItems acota cuántas fotos admite un evento delivered.
	maxEvidenceItems = 32
	// maxEvidenceIndex acota el índice de una foto dentro de su rol.
	maxEvidenceIndex = 999
	// sha256HexLength es el largo de un SHA-256 en hexadecimal.
	sha256HexLength = 64

	// redactedKeyPrefix y redactedKeyMiddle componen el prefijo obligatorio de toda
	// clave de evidencia redactada: alerts/{alert_id}/redacted/.
	redactedKeyPrefix = "alerts/"
	redactedKeyMiddle = "/redacted/"
)

var (
	// keyNamePattern restringe el nombre de la foto tras el prefijo redactado: sin
	// subdirectorios.
	keyNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

// alertDeliverer archiva la evidencia de una alerta entregada.
type alertDeliverer interface {
	Deliver(ctx context.Context, in record.DeliveredInput) error
}

// DeliveredProcessor es el Processor de audit.alert.delivered. Valida el payload,
// incluidos el bucket y las claves de evidencia, antes de tocar S3 o la base.
type DeliveredProcessor struct {
	deliverer      alertDeliverer
	evidenceBucket string
}

var _ Processor = (*DeliveredProcessor)(nil)

// NewDeliveredProcessor construye el procesador. evidenceBucket es
// EVIDENCE_BUCKET: el único bucket del que Audit acepta leer.
func NewDeliveredProcessor(deliverer alertDeliverer, evidenceBucket string) *DeliveredProcessor {
	return &DeliveredProcessor{deliverer: deliverer, evidenceBucket: evidenceBucket}
}

// Process implementa Processor. Los errores permanentes del caso de uso
// (integridad, retención vencida) se traducen a ErrInvalidMessage para que el
// mensaje vaya directo a la DLQ; el resto es transitorio.
func (p *DeliveredProcessor) Process(ctx context.Context, envelope InboundEnvelope) error {
	input, err := p.parseDelivered(envelope)
	if err != nil {
		return err
	}

	err = p.deliverer.Deliver(ctx, input)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, domain.ErrIntegrity):
		return invalid("el contenido de una foto no coincide con su SHA-256")
	case errors.Is(err, domain.ErrRetentionElapsed):
		return invalid("la fecha de destrucción del registro ya venció")
	default:
		return fmt.Errorf("audit.alert.delivered: %w", err)
	}
}

// deliveredPayload es el payload de audit.alert.delivered.
type deliveredPayload struct {
	AlertID     *string           `json:"alert_id"`
	DeliveredAt *string           `json:"delivered_at"`
	Bucket      *string           `json:"bucket"`
	Evidence    []evidencePayload `json:"evidence"`
}

type evidencePayload struct {
	Role   *string `json:"role"`
	Index  *int    `json:"index"`
	Key    *string `json:"key"`
	SHA256 *string `json:"sha256"`
}

func (p *DeliveredProcessor) parseDelivered(envelope InboundEnvelope) (record.DeliveredInput, error) {
	if envelope.EventType != eventTypeDelivered {
		return record.DeliveredInput{}, invalid("eventType inesperado")
	}

	var payload deliveredPayload
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		return record.DeliveredInput{}, invalid("payload ilegible")
	}

	alertID, err := parseUUID(payload.AlertID, "alert_id")
	if err != nil {
		return record.DeliveredInput{}, err
	}
	deliveredAt, err := parseRFC3339(payload.DeliveredAt, "delivered_at")
	if err != nil {
		return record.DeliveredInput{}, err
	}
	if payload.Bucket == nil || *payload.Bucket != p.evidenceBucket {
		return record.DeliveredInput{}, invalid("bucket distinto del bucket de evidencia")
	}

	evidence, err := parseEvidence(alertID, payload.Evidence)
	if err != nil {
		return record.DeliveredInput{}, err
	}

	return record.DeliveredInput{AlertID: alertID, DeliveredAt: deliveredAt, Evidence: evidence}, nil
}

// parseEvidence valida la lista de fotos redactadas: cantidad acotada, rol e
// índice válidos, clave dentro de alerts/{alert_id}/redacted/, SHA-256 bien
// formado y sin repetidos.
func parseEvidence(alertID uuid.UUID, items []evidencePayload) ([]manifest.EvidenceItem, error) {
	if len(items) == 0 {
		return nil, invalid("evidence ausente o vacía")
	}
	if len(items) > maxEvidenceItems {
		return nil, invalid("evidence excede la cantidad máxima de fotos")
	}

	keyPrefix := redactedKeyPrefix + alertID.String() + redactedKeyMiddle
	seenPhotos := make(map[string]struct{}, len(items))
	seenKeys := make(map[string]struct{}, len(items))
	result := make([]manifest.EvidenceItem, 0, len(items))

	for _, item := range items {
		if item.Role == nil || !manifest.ValidRole(*item.Role) {
			return nil, invalid("role de evidencia ausente o inválido")
		}
		if item.Index == nil || *item.Index < 0 || *item.Index > maxEvidenceIndex {
			return nil, invalid("index de evidencia ausente o inválido")
		}
		if item.Key == nil || !isRedactedKey(*item.Key, keyPrefix) {
			return nil, invalid("key de evidencia fuera de alerts/{alert_id}/redacted/")
		}
		sum, err := parseSHA256(item.SHA256)
		if err != nil {
			return nil, err
		}

		photo := manifest.PhotoFileName(*item.Role, *item.Index)
		if _, dup := seenPhotos[photo]; dup {
			return nil, invalid("foto de evidencia repetida")
		}
		if _, dup := seenKeys[*item.Key]; dup {
			return nil, invalid("key de evidencia repetida")
		}
		seenPhotos[photo] = struct{}{}
		seenKeys[*item.Key] = struct{}{}

		result = append(result, manifest.EvidenceItem{Role: *item.Role, Index: *item.Index, Key: *item.Key, SHA256: sum})
	}
	return result, nil
}

// isRedactedKey indica si key es exactamente keyPrefix seguido de un nombre de
// archivo simple (sin subdirectorios ni "..").
func isRedactedKey(key, keyPrefix string) bool {
	name, ok := strings.CutPrefix(key, keyPrefix)
	return ok && keyNamePattern.MatchString(name) && !strings.Contains(name, "..")
}

// parseSHA256 valida un SHA-256 en hexadecimal y lo devuelve en minúsculas.
func parseSHA256(raw *string) (string, error) {
	if raw == nil || len(*raw) != sha256HexLength {
		return "", invalid("sha256 de evidencia ausente o inválido")
	}
	if _, err := hex.DecodeString(*raw); err != nil {
		return "", invalid("sha256 de evidencia ausente o inválido")
	}
	return strings.ToLower(*raw), nil
}
