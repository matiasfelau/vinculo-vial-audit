package events

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-audit/internal/domain"
)

// eventTypeDiscarded es el eventType (y routing key) con el que Alert informa que
// una alerta ya no puede llegar a nadie.
const eventTypeDiscarded = "audit.alert.discarded"

// alertDiscarder borra el registro de una alerta descartada.
type alertDiscarder interface {
	Discard(ctx context.Context, alertID uuid.UUID, reason string) error
}

// DiscardedProcessor es el Processor de audit.alert.discarded.
type DiscardedProcessor struct {
	discarder alertDiscarder
}

var _ Processor = (*DiscardedProcessor)(nil)

// NewDiscardedProcessor construye el procesador sobre el caso de uso.
func NewDiscardedProcessor(discarder alertDiscarder) *DiscardedProcessor {
	return &DiscardedProcessor{discarder: discarder}
}

// Process implementa Processor. Es idempotente: sobre un registro entregado hace
// ack sin borrar.
func (p *DiscardedProcessor) Process(ctx context.Context, envelope InboundEnvelope) error {
	alertID, reason, err := parseDiscarded(envelope)
	if err != nil {
		return err
	}
	if err := p.discarder.Discard(ctx, alertID, reason); err != nil {
		return fmt.Errorf("audit.alert.discarded: %w", err)
	}
	return nil
}

// discardedPayload es el payload de audit.alert.discarded.
type discardedPayload struct {
	AlertID *string `json:"alert_id"`
	Reason  *string `json:"reason"`
}

func parseDiscarded(envelope InboundEnvelope) (uuid.UUID, string, error) {
	if envelope.EventType != eventTypeDiscarded {
		return uuid.Nil, "", invalid("eventType inesperado")
	}

	var payload discardedPayload
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		return uuid.Nil, "", invalid("payload ilegible")
	}

	alertID, err := parseUUID(payload.AlertID, "alert_id")
	if err != nil {
		return uuid.Nil, "", err
	}
	if payload.Reason == nil || !domain.IsValidDiscardReason(*payload.Reason) {
		return uuid.Nil, "", invalid("reason ausente o inválido")
	}
	return alertID, *payload.Reason, nil
}
