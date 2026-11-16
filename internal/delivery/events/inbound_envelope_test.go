package events

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// envelopeValido arma el cuerpo de un audit.alert.recorded bien formado.
func envelopeValido(eventID string) []byte {
	return []byte(`{"eventId":"` + eventID + `","eventType":"audit.alert.recorded","timestamp":"2026-11-01T12:00:00Z","producer":"vinculo-vial-alert","actor":null,"payload":{"alert_id":"x"}}`)
}

func TestParseEnvelopeValido(t *testing.T) {
	eventID := uuid.New()

	envelope, err := ParseEnvelope(envelopeValido(eventID.String()))
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	if envelope.EventID != eventID {
		t.Errorf("eventId = %v, esperaba %v", envelope.EventID, eventID)
	}
	if envelope.EventType != "audit.alert.recorded" {
		t.Errorf("eventType = %q", envelope.EventType)
	}
	if envelope.Actor != nil {
		t.Error("el actor debía ser nil: Audit no recibe identificadores del emisor")
	}
	if envelope.Timestamp.IsZero() {
		t.Error("timestamp no se decodificó")
	}
	if string(envelope.Payload) != `{"alert_id":"x"}` {
		t.Errorf("payload = %s", envelope.Payload)
	}
}

func TestParseEnvelopeConActorNullDevuelveActorNil(t *testing.T) {
	body := []byte(`{"eventId":"` + uuid.NewString() + `","eventType":"user.status.changed","timestamp":"2026-11-01T12:00:00Z","producer":"p","actor":null,"payload":{}}`)

	envelope, err := ParseEnvelope(body)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if envelope.Actor != nil {
		t.Errorf("actor = %v, esperaba nil para un actor null", *envelope.Actor)
	}
}

func TestParseEnvelopeInvalidoEnvuelveErrInvalidMessage(t *testing.T) {
	id := uuid.New().String()
	casos := map[string]string{
		"json ilegible":      `{no es json`,
		"eventId no es uuid": `{"eventId":"abc","eventType":"t","timestamp":"2026-11-01T12:00:00Z","payload":{}}`,
		"sin eventId":        `{"eventType":"t","timestamp":"2026-11-01T12:00:00Z","payload":{}}`,
		"eventId nulo":       `{"eventId":"00000000-0000-0000-0000-000000000000","eventType":"t","timestamp":"2026-11-01T12:00:00Z","payload":{}}`,
		"sin eventType":      `{"eventId":"` + id + `","timestamp":"2026-11-01T12:00:00Z","payload":{}}`,
		"sin timestamp":      `{"eventId":"` + id + `","eventType":"t","payload":{}}`,
		"timestamp inválido": `{"eventId":"` + id + `","eventType":"t","timestamp":"ayer","payload":{}}`,
		"sin payload":        `{"eventId":"` + id + `","eventType":"t","timestamp":"2026-11-01T12:00:00Z"}`,
	}

	for nombre, body := range casos {
		t.Run(nombre, func(t *testing.T) {
			_, err := ParseEnvelope([]byte(body))
			if !errors.Is(err, ErrInvalidMessage) {
				t.Fatalf("error = %v, esperaba que envolviera ErrInvalidMessage", err)
			}
		})
	}
}

func TestParseEnvelopeElErrorNoReflejaElContenidoDelMensaje(t *testing.T) {
	// El cuerpo puede llevar criptogramas o claves: nunca debe terminar en un
	// mensaje de error ni, por lo tanto, en un log o en x-discard-reason.
	_, err := ParseEnvelope([]byte(`{"payload":"SECRETO-CRIPTOGRAMA"`))
	if err == nil {
		t.Fatal("esperaba error")
	}
	if strings.Contains(err.Error(), "SECRETO-CRIPTOGRAMA") {
		t.Errorf("el error refleja el contenido del mensaje: %v", err)
	}
}
