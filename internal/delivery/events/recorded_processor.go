package events

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/matiasfelau/vinculo-vial-audit/internal/domain"
	"github.com/matiasfelau/vinculo-vial-audit/internal/service/record"
)

// eventTypeRecorded es el eventType (y routing key) con el que Alert informa el
// alta del registro de una alerta.
const eventTypeRecorded = "audit.alert.recorded"

// alertRecorder crea el registro de auditoría de una alerta.
type alertRecorder interface {
	Record(ctx context.Context, in record.RecordedInput) error
}

// RecordedProcessor es el Processor de audit.alert.recorded: valida el envelope y
// el payload contra el contrato y delega la creación del registro. Todo mensaje
// que no cumple el contrato es inválido (DLQ sin reintento); cualquier otro error
// es transitorio. Nunca loguea ni refleja el payload: lleva criptogramas.
type RecordedProcessor struct {
	recorder alertRecorder
}

var _ Processor = (*RecordedProcessor)(nil)

// NewRecordedProcessor construye el procesador sobre el caso de uso.
func NewRecordedProcessor(recorder alertRecorder) *RecordedProcessor {
	return &RecordedProcessor{recorder: recorder}
}

// Process implementa Processor. Es idempotente porque lo es el caso de uso.
func (p *RecordedProcessor) Process(ctx context.Context, envelope InboundEnvelope) error {
	input, err := parseRecorded(envelope)
	if err != nil {
		return err
	}
	if err := p.recorder.Record(ctx, input); err != nil {
		return fmt.Errorf("audit.alert.recorded: %w", err)
	}
	return nil
}

// recordedPayload es el payload de audit.alert.recorded.
type recordedPayload struct {
	AlertID     *string `json:"alert_id"`
	AlertType   *string `json:"alert_type"`
	CreatedAt   *string `json:"created_at"`
	DNIEncAudit *string `json:"dni_enc_audit"`
	PatEncAudit *string `json:"pat_enc_audit"`
	AuditKeyID  *string `json:"audit_key_id"`
}

// parseRecorded valida el envelope y el payload de audit.alert.recorded. Todo
// error que devuelve envuelve ErrInvalidMessage y ninguno refleja el contenido.
func parseRecorded(envelope InboundEnvelope) (record.RecordedInput, error) {
	if envelope.EventType != eventTypeRecorded {
		return record.RecordedInput{}, invalid("eventType inesperado")
	}

	var payload recordedPayload
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		return record.RecordedInput{}, invalid("payload ilegible")
	}

	alertID, err := parseUUID(payload.AlertID, "alert_id")
	if err != nil {
		return record.RecordedInput{}, err
	}
	if payload.AlertType == nil || !domain.IsValidAlertType(*payload.AlertType) {
		return record.RecordedInput{}, invalid("alert_type ausente o inválido")
	}
	createdAt, err := parseRFC3339(payload.CreatedAt, "created_at")
	if err != nil {
		return record.RecordedInput{}, err
	}
	dni, err := parseCryptogram(payload.DNIEncAudit, "dni_enc_audit")
	if err != nil {
		return record.RecordedInput{}, err
	}
	pat, err := parseCryptogram(payload.PatEncAudit, "pat_enc_audit")
	if err != nil {
		return record.RecordedInput{}, err
	}
	keyID, err := parseAuditKeyID(payload.AuditKeyID)
	if err != nil {
		return record.RecordedInput{}, err
	}

	return record.RecordedInput{
		AlertID:     alertID,
		AlertType:   *payload.AlertType,
		CreatedAt:   createdAt,
		DNIEncAudit: dni,
		PatEncAudit: pat,
		AuditKeyID:  keyID,
	}, nil
}
