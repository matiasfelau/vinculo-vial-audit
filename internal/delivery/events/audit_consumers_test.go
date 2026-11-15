package events

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-audit/internal/domain"
	"github.com/matiasfelau/vinculo-vial-audit/internal/manifest"
	"github.com/matiasfelau/vinculo-vial-audit/internal/service/record"
	"github.com/matiasfelau/vinculo-vial-audit/internal/testsupport"
)

const (
	evidenceBucket = "vinculo-vial-evidence-test"
	maxRetriesTest = 3
	cryptogram     = "ZW5jLWNpcGhlcnRleHQ="
	retentionDays  = 3
)

// harness arma los tres consumidores reales (procesador + caso de uso +
// MessageHandler) sobre dobles en memoria, para verificar el desenlace de cada
// mensaje: ack, reintento (nack a .retry) o DLQ.
type harness struct {
	store    *testsupport.MemoryStore
	evidence *testsupport.MemoryObjects
	audit    *testsupport.MemoryObjects

	recorded  *MessageHandler
	delivered *MessageHandler
	discarded *MessageHandler

	recordedDLQ  *fakeDeadLetterPublisher
	deliveredDLQ *fakeDeadLetterPublisher
	discardedDLQ *fakeDeadLetterPublisher
}

func newHarness() *harness {
	h := &harness{
		store:        testsupport.NewMemoryStore(),
		evidence:     testsupport.NewMemoryObjects(),
		audit:        testsupport.NewMemoryObjects(),
		recordedDLQ:  &fakeDeadLetterPublisher{},
		deliveredDLQ: &fakeDeadLetterPublisher{},
		discardedDLQ: &fakeDeadLetterPublisher{},
	}

	recorder := record.NewRecorder(h.store, retentionDays)
	deliverer := record.NewDeliverer(h.store, h.evidence, h.audit)
	discarder := record.NewDiscarder(h.store)

	h.recorded = NewMessageHandler(NewRecordedProcessor(recorder), h.recordedDLQ, "audit.alert-recorded.q", maxRetriesTest)
	h.delivered = NewMessageHandler(NewDeliveredProcessor(deliverer, evidenceBucket), h.deliveredDLQ, "audit.alert-delivered.q", maxRetriesTest)
	h.discarded = NewMessageHandler(NewDiscardedProcessor(discarder), h.discardedDLQ, "audit.alert-discarded.q", maxRetriesTest)
	return h
}

// envelopeBody arma un evento con el envelope estándar y actor null.
func envelopeBody(t *testing.T, eventType string, payload any) []byte {
	t.Helper()

	rawPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("no se pudo serializar el payload: %v", err)
	}
	body, err := json.Marshal(map[string]any{
		"eventId":   uuid.NewString(),
		"eventType": eventType,
		"timestamp": "2026-11-04T12:00:00Z",
		"producer":  "vinculo-vial-alert",
		"actor":     nil,
		"payload":   json.RawMessage(rawPayload),
	})
	if err != nil {
		t.Fatalf("no se pudo serializar el envelope: %v", err)
	}
	return body
}

func recordedPayloadFor(id uuid.UUID) map[string]any {
	return map[string]any{
		"alert_id":      id.String(),
		"alert_type":    "CRASHED",
		"created_at":    time.Now().UTC().Format(time.RFC3339),
		"dni_enc_audit": cryptogram,
		"pat_enc_audit": cryptogram,
		"audit_key_id":  "2026-11",
	}
}

func (h *harness) record(t *testing.T, id uuid.UUID) {
	t.Helper()
	if outcome := h.recorded.Handle(context.Background(), envelopeBody(t, "audit.alert.recorded", recordedPayloadFor(id)), 0); outcome != OutcomeAck {
		t.Fatalf("recorded: outcome = %v, esperaba ack", outcome)
	}
}

func sha(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// deliveredPayloadFor siembra dos fotos en el bucket de evidencia y arma el payload.
func (h *harness) deliveredPayloadFor(id uuid.UUID) map[string]any {
	photos := []struct {
		role string
		body []byte
	}{{"GENERAL", []byte("foto-general")}, {"PLATE", []byte("foto-patente")}}

	var evidence []map[string]any
	for _, photo := range photos {
		key := "alerts/" + id.String() + "/redacted/" + photo.role + "-0.jpg"
		h.evidence.Seed(key, photo.body)
		evidence = append(evidence, map[string]any{"role": photo.role, "index": 0, "key": key, "sha256": sha(photo.body)})
	}
	return map[string]any{
		"alert_id":     id.String(),
		"delivered_at": time.Now().UTC().Format(time.RFC3339),
		"bucket":       evidenceBucket,
		"evidence":     evidence,
	}
}

func assertDLQ(t *testing.T, outcome Outcome, dlq *fakeDeadLetterPublisher) {
	t.Helper()
	if outcome != OutcomeAck {
		t.Errorf("outcome = %v, esperaba ack tras confirmar la DLQ", outcome)
	}
	if len(dlq.published) != 1 {
		t.Fatalf("mensajes en la DLQ = %d, esperaba 1", len(dlq.published))
	}
	reason := dlq.published[0].reason
	for _, secret := range []string{cryptogram, "foto-general"} {
		if strings.Contains(reason, secret) {
			t.Errorf("el motivo de la DLQ refleja contenido del mensaje: %q", reason)
		}
	}
}

func assertRetry(t *testing.T, outcome Outcome, dlq *fakeDeadLetterPublisher) {
	t.Helper()
	if outcome != OutcomeNackNoRequeue {
		t.Errorf("outcome = %v, esperaba nack sin requeue (cola .retry)", outcome)
	}
	if len(dlq.published) != 0 {
		t.Errorf("el fallo transitorio no debe ir a la DLQ todavía (%d mensajes)", len(dlq.published))
	}
}

// --- recorded ---

func TestRecordedValidoCreaElRegistroYHaceAck(t *testing.T) {
	h := newHarness()
	id := uuid.New()

	h.record(t, id)

	got, ok := h.store.Lookup(id)
	if !ok || got.Status != domain.StatusRecorded {
		t.Fatalf("el registro no se creó RECORDED: %+v (existe=%v)", got, ok)
	}
	if len(h.recordedDLQ.published) != 0 {
		t.Error("un mensaje válido no va a la DLQ")
	}
}

func TestRecordedRepetidoHaceAckSinCambios(t *testing.T) {
	h := newHarness()
	id := uuid.New()
	h.record(t, id)

	h.record(t, id)

	if h.store.Len() != 1 {
		t.Errorf("hay %d registros, esperaba 1", h.store.Len())
	}
}

func TestRecordedInvalidoVaDirectoALaDLQSinReintento(t *testing.T) {
	casos := map[string]func(p map[string]any){
		"alert_id ausente":           func(p map[string]any) { delete(p, "alert_id") },
		"alert_id no es UUID":        func(p map[string]any) { p["alert_id"] = "no-es-uuid" },
		"alert_id UUID nulo":         func(p map[string]any) { p["alert_id"] = uuid.Nil.String() },
		"alert_type ausente":         func(p map[string]any) { delete(p, "alert_type") },
		"alert_type desconocido":     func(p map[string]any) { p["alert_type"] = "ROBBED" },
		"created_at ausente":         func(p map[string]any) { delete(p, "created_at") },
		"created_at no es RFC3339":   func(p map[string]any) { p["created_at"] = "04/11/2026" },
		"dni_enc_audit ausente":      func(p map[string]any) { delete(p, "dni_enc_audit") },
		"dni_enc_audit vacío":        func(p map[string]any) { p["dni_enc_audit"] = "" },
		"dni_enc_audit no es base64": func(p map[string]any) { p["dni_enc_audit"] = "***no-base64***" },
		"dni_enc_audit demasiado largo": func(p map[string]any) {
			p["dni_enc_audit"] = strings.Repeat("QUFB", maxCryptogramLength)
		},
		"pat_enc_audit ausente":      func(p map[string]any) { delete(p, "pat_enc_audit") },
		"pat_enc_audit no es base64": func(p map[string]any) { p["pat_enc_audit"] = "%%%" },
		"audit_key_id ausente":       func(p map[string]any) { delete(p, "audit_key_id") },
		"audit_key_id con igual":     func(p map[string]any) { p["audit_key_id"] = "a=b" },
		"audit_key_id demasiado largo": func(p map[string]any) {
			p["audit_key_id"] = strings.Repeat("a", maxAuditKeyIDLength+1)
		},
		"campo con tipo equivocado": func(p map[string]any) { p["alert_type"] = 7 },
	}

	for nombre, mutar := range casos {
		t.Run(nombre, func(t *testing.T) {
			h := newHarness()
			payload := recordedPayloadFor(uuid.New())
			mutar(payload)

			outcome := h.recorded.Handle(context.Background(), envelopeBody(t, "audit.alert.recorded", payload), 0)

			assertDLQ(t, outcome, h.recordedDLQ)
			if h.store.Len() != 0 {
				t.Error("un mensaje inválido no debe crear registros")
			}
		})
	}
}

func TestRecordedConEventTypeIncorrectoVaALaDLQ(t *testing.T) {
	h := newHarness()

	outcome := h.recorded.Handle(context.Background(), envelopeBody(t, "audit.alert.delivered", recordedPayloadFor(uuid.New())), 0)

	assertDLQ(t, outcome, h.recordedDLQ)
}

func TestRecordedConPayloadQueNoEsObjetoVaALaDLQ(t *testing.T) {
	h := newHarness()

	outcome := h.recorded.Handle(context.Background(), envelopeBody(t, "audit.alert.recorded", []string{"no", "es", "objeto"}), 0)

	assertDLQ(t, outcome, h.recordedDLQ)
}

func TestRecordedIgnoraElActorSinGuardarlo(t *testing.T) {
	h := newHarness()
	id := uuid.New()
	body := envelopeBody(t, "audit.alert.recorded", recordedPayloadFor(id))
	var envelope map[string]any
	_ = json.Unmarshal(body, &envelope)
	envelope["actor"] = uuid.NewString()
	body, _ = json.Marshal(envelope)

	if outcome := h.recorded.Handle(context.Background(), body, 0); outcome != OutcomeAck {
		t.Fatalf("outcome = %v, esperaba ack", outcome)
	}
	if _, ok := h.store.Lookup(id); !ok {
		t.Error("el registro debía crearse ignorando el actor")
	}
}

func TestRecordedConBaseCaidaReintentaYAgotadoVaALaDLQ(t *testing.T) {
	h := newHarness()
	h.store.ErrInsert = domain.ErrRepositoryUnavailable
	body := envelopeBody(t, "audit.alert.recorded", recordedPayloadFor(uuid.New()))

	assertRetry(t, h.recorded.Handle(context.Background(), body, 0), h.recordedDLQ)
	assertRetry(t, h.recorded.Handle(context.Background(), body, maxRetriesTest-1), h.recordedDLQ)

	assertDLQ(t, h.recorded.Handle(context.Background(), body, maxRetriesTest), h.recordedDLQ)
}

// --- delivered ---

func TestDeliveredValidoArchivaYMarcaDelivered(t *testing.T) {
	h := newHarness()
	id := uuid.New()
	h.record(t, id)

	outcome := h.delivered.Handle(context.Background(), envelopeBody(t, "audit.alert.delivered", h.deliveredPayloadFor(id)), 0)

	if outcome != OutcomeAck {
		t.Fatalf("outcome = %v, esperaba ack", outcome)
	}
	got, _ := h.store.Lookup(id)
	if got.Status != domain.StatusDelivered || got.ManifestKey == nil {
		t.Errorf("el registro no quedó DELIVERED con manifiesto: %+v", got)
	}
	if len(h.audit.Versions(manifest.ManifestKey(id.String()))) != 1 {
		t.Error("no se escribió el manifiesto")
	}
}

func TestDeliveredAntesQueRecordedEsTransitorioYAgotadoVaALaDLQ(t *testing.T) {
	h := newHarness()
	id := uuid.New()
	body := envelopeBody(t, "audit.alert.delivered", h.deliveredPayloadFor(id))

	assertRetry(t, h.delivered.Handle(context.Background(), body, 0), h.deliveredDLQ)

	assertDLQ(t, h.delivered.Handle(context.Background(), body, maxRetriesTest), h.deliveredDLQ)
}

func TestDeliveredEntregaCuandoRecordedLlegaDuranteLosReintentos(t *testing.T) {
	h := newHarness()
	id := uuid.New()
	body := envelopeBody(t, "audit.alert.delivered", h.deliveredPayloadFor(id))

	assertRetry(t, h.delivered.Handle(context.Background(), body, 0), h.deliveredDLQ)
	h.record(t, id)

	if outcome := h.delivered.Handle(context.Background(), body, 1); outcome != OutcomeAck {
		t.Fatalf("outcome = %v, esperaba ack una vez creado el registro", outcome)
	}
	if got, _ := h.store.Lookup(id); got.Status != domain.StatusDelivered {
		t.Errorf("status = %s, esperaba DELIVERED", got.Status)
	}
}

func TestDeliveredSobreRegistroDeliveredHaceAck(t *testing.T) {
	h := newHarness()
	id := uuid.New()
	h.record(t, id)
	body := envelopeBody(t, "audit.alert.delivered", h.deliveredPayloadFor(id))
	if outcome := h.delivered.Handle(context.Background(), body, 0); outcome != OutcomeAck {
		t.Fatalf("primera entrega: %v", outcome)
	}
	puts := h.audit.PutCalls

	outcome := h.delivered.Handle(context.Background(), body, 0)

	if outcome != OutcomeAck || h.audit.PutCalls != puts {
		t.Errorf("un delivered repetido debe hacer ack sin subir nada (outcome=%v, puts %d->%d)", outcome, puts, h.audit.PutCalls)
	}
	if len(h.deliveredDLQ.published) != 0 {
		t.Error("un delivered repetido no va a la DLQ")
	}
}

func TestDeliveredConSHA256DistintoVaALaDLQSinReintento(t *testing.T) {
	h := newHarness()
	id := uuid.New()
	h.record(t, id)
	payload := h.deliveredPayloadFor(id)
	payload["evidence"].([]map[string]any)[0]["sha256"] = sha([]byte("otro contenido"))

	outcome := h.delivered.Handle(context.Background(), envelopeBody(t, "audit.alert.delivered", payload), 0)

	assertDLQ(t, outcome, h.deliveredDLQ)
	if got, _ := h.store.Lookup(id); got.Status != domain.StatusRecorded {
		t.Errorf("status = %s, el registro no debe entregarse con una foto alterada", got.Status)
	}
}

func TestDeliveredInvalidoVaDirectoALaDLQSinTocarS3(t *testing.T) {
	otraAlerta := uuid.NewString()
	casos := map[string]func(p map[string]any, id uuid.UUID){
		"alert_id ausente":     func(p map[string]any, _ uuid.UUID) { delete(p, "alert_id") },
		"alert_id inválido":    func(p map[string]any, _ uuid.UUID) { p["alert_id"] = "x" },
		"delivered_at ausente": func(p map[string]any, _ uuid.UUID) { delete(p, "delivered_at") },
		"delivered_at no es RFC3339": func(p map[string]any, _ uuid.UUID) {
			p["delivered_at"] = "ayer"
		},
		"bucket ausente":                     func(p map[string]any, _ uuid.UUID) { delete(p, "bucket") },
		"bucket distinto de EVIDENCE_BUCKET": func(p map[string]any, _ uuid.UUID) { p["bucket"] = "otro-bucket" },
		"bucket es el de Audit":              func(p map[string]any, _ uuid.UUID) { p["bucket"] = "vinculo-vial-audit-dev-x" },
		"evidence ausente":                   func(p map[string]any, _ uuid.UUID) { delete(p, "evidence") },
		"evidence vacía":                     func(p map[string]any, _ uuid.UUID) { p["evidence"] = []any{} },
		"evidence con tres fotos": func(p map[string]any, id uuid.UUID) {
			p["evidence"] = append(p["evidence"].([]map[string]any), map[string]any{"role": "GENERAL", "index": 1, "key": "alerts/" + id.String() + "/redacted/GENERAL-1.jpg", "sha256": strings.Repeat("a", 64)})
		},
		"evidence con una sola foto": func(p map[string]any, _ uuid.UUID) {
			p["evidence"] = p["evidence"].([]map[string]any)[:1]
		},
		"role detail (retirado)":  func(p map[string]any, _ uuid.UUID) { evidenceItem(p, 1)["role"] = "detail" },
		"role DETAIL (retirado)":  func(p map[string]any, _ uuid.UUID) { evidenceItem(p, 1)["role"] = "DETAIL" },
		"role context (retirado)": func(p map[string]any, _ uuid.UUID) { evidenceItem(p, 1)["role"] = "context" },
		"role CONTEXT (retirado)": func(p map[string]any, _ uuid.UUID) { evidenceItem(p, 1)["role"] = "CONTEXT" },
		"dos GENERAL y ninguna PLATE": func(p map[string]any, _ uuid.UUID) {
			evidenceItem(p, 1)["role"] = "GENERAL"
			evidenceItem(p, 1)["index"] = 1
		},
		"role ausente":   func(p map[string]any, _ uuid.UUID) { evidenceItem(p, 0)["role"] = nil },
		"role con guion": func(p map[string]any, _ uuid.UUID) { evidenceItem(p, 0)["role"] = "GENE-RAL" },
		"role con barra": func(p map[string]any, _ uuid.UUID) { evidenceItem(p, 0)["role"] = "../x" },
		"index ausente":  func(p map[string]any, _ uuid.UUID) { evidenceItem(p, 0)["index"] = nil },
		"index negativo": func(p map[string]any, _ uuid.UUID) { evidenceItem(p, 0)["index"] = -1 },
		"index enorme":   func(p map[string]any, _ uuid.UUID) { evidenceItem(p, 0)["index"] = maxEvidenceIndex + 1 },
		"key ausente":    func(p map[string]any, _ uuid.UUID) { evidenceItem(p, 0)["key"] = nil },
		"key de otra alerta": func(p map[string]any, _ uuid.UUID) {
			evidenceItem(p, 0)["key"] = "alerts/" + otraAlerta + "/redacted/GENERAL-0.jpg"
		},
		"key en original y no redacted": func(p map[string]any, id uuid.UUID) {
			evidenceItem(p, 0)["key"] = "alerts/" + id.String() + "/original/GENERAL-0.bin"
		},
		"key con traversal": func(p map[string]any, id uuid.UUID) {
			evidenceItem(p, 0)["key"] = "alerts/" + id.String() + "/redacted/../original/GENERAL-0.bin"
		},
		"key con subdirectorio": func(p map[string]any, id uuid.UUID) {
			evidenceItem(p, 0)["key"] = "alerts/" + id.String() + "/redacted/sub/GENERAL-0.jpg"
		},
		"key sin nombre": func(p map[string]any, id uuid.UUID) {
			evidenceItem(p, 0)["key"] = "alerts/" + id.String() + "/redacted/"
		},
		"sha256 ausente": func(p map[string]any, _ uuid.UUID) { evidenceItem(p, 0)["sha256"] = nil },
		"sha256 corto":   func(p map[string]any, _ uuid.UUID) { evidenceItem(p, 0)["sha256"] = "abc" },
		"sha256 no hexa": func(p map[string]any, _ uuid.UUID) { evidenceItem(p, 0)["sha256"] = strings.Repeat("z", 64) },
		"foto repetida": func(p map[string]any, _ uuid.UUID) {
			evidenceItem(p, 1)["role"] = evidenceItem(p, 0)["role"]
			evidenceItem(p, 1)["index"] = evidenceItem(p, 0)["index"]
		},
		"key repetida": func(p map[string]any, _ uuid.UUID) { evidenceItem(p, 1)["key"] = evidenceItem(p, 0)["key"] },
	}

	for nombre, mutar := range casos {
		t.Run(nombre, func(t *testing.T) {
			h := newHarness()
			id := uuid.New()
			h.record(t, id)
			payload := h.deliveredPayloadFor(id)
			mutar(payload, id)
			gets := h.evidence.GetCalls

			outcome := h.delivered.Handle(context.Background(), envelopeBody(t, "audit.alert.delivered", payload), 0)

			assertDLQ(t, outcome, h.deliveredDLQ)
			if h.evidence.GetCalls != gets || h.audit.PutCalls != 0 {
				t.Error("un payload inválido no debe tocar S3")
			}
		})
	}
}

func evidenceItem(payload map[string]any, i int) map[string]any {
	return payload["evidence"].([]map[string]any)[i]
}

func TestDeliveredConS3CaidoEsTransitorio(t *testing.T) {
	h := newHarness()
	id := uuid.New()
	h.record(t, id)
	body := envelopeBody(t, "audit.alert.delivered", h.deliveredPayloadFor(id))
	h.audit.ErrPut = domain.ErrStorageUnavailable

	assertRetry(t, h.delivered.Handle(context.Background(), body, 0), h.deliveredDLQ)

	if got, _ := h.store.Lookup(id); got.Status != domain.StatusRecorded {
		t.Error("el registro no debe entregarse si S3 falló")
	}
}

// --- discarded ---

func TestDiscardedBorraElRegistroRecorded(t *testing.T) {
	for _, reason := range []string{"REJECTED", "EXPIRED", "UNCLAIMED"} {
		t.Run(reason, func(t *testing.T) {
			h := newHarness()
			id := uuid.New()
			h.record(t, id)

			outcome := h.discarded.Handle(context.Background(), envelopeBody(t, "audit.alert.discarded", map[string]any{"alert_id": id.String(), "reason": reason}), 0)

			if outcome != OutcomeAck {
				t.Fatalf("outcome = %v, esperaba ack", outcome)
			}
			if _, ok := h.store.Lookup(id); ok {
				t.Error("el registro RECORDED debía borrarse")
			}
		})
	}
}

func TestDiscardedAntesQueRecordedEsTransitorioYAgotadoVaALaDLQ(t *testing.T) {
	h := newHarness()
	body := envelopeBody(t, "audit.alert.discarded", map[string]any{"alert_id": uuid.NewString(), "reason": "REJECTED"})

	assertRetry(t, h.discarded.Handle(context.Background(), body, 0), h.discardedDLQ)

	assertDLQ(t, h.discarded.Handle(context.Background(), body, maxRetriesTest), h.discardedDLQ)
}

func TestDiscardedSobreRegistroDeliveredHaceAckSinBorrar(t *testing.T) {
	h := newHarness()
	id := uuid.New()
	h.record(t, id)
	if outcome := h.delivered.Handle(context.Background(), envelopeBody(t, "audit.alert.delivered", h.deliveredPayloadFor(id)), 0); outcome != OutcomeAck {
		t.Fatalf("entrega: %v", outcome)
	}

	outcome := h.discarded.Handle(context.Background(), envelopeBody(t, "audit.alert.discarded", map[string]any{"alert_id": id.String(), "reason": "UNCLAIMED"}), 0)

	if outcome != OutcomeAck {
		t.Fatalf("outcome = %v, esperaba ack", outcome)
	}
	if got, ok := h.store.Lookup(id); !ok || got.Status != domain.StatusDelivered {
		t.Error("un registro entregado nunca se borra antes de su vencimiento")
	}
	if len(h.discardedDLQ.published) != 0 {
		t.Error("discarded sobre un registro entregado no va a la DLQ")
	}
}

func TestDiscardedInvalidoVaALaDLQ(t *testing.T) {
	casos := map[string]map[string]any{
		"alert_id ausente":   {"reason": "REJECTED"},
		"alert_id inválido":  {"alert_id": "x", "reason": "REJECTED"},
		"reason ausente":     {"alert_id": uuid.NewString()},
		"reason desconocido": {"alert_id": uuid.NewString(), "reason": "DELETED"},
	}

	for nombre, payload := range casos {
		t.Run(nombre, func(t *testing.T) {
			h := newHarness()

			outcome := h.discarded.Handle(context.Background(), envelopeBody(t, "audit.alert.discarded", payload), 0)

			assertDLQ(t, outcome, h.discardedDLQ)
		})
	}
}

func TestEnvelopeIlegibleVaALaDLQ(t *testing.T) {
	h := newHarness()

	assertDLQ(t, h.recorded.Handle(context.Background(), []byte("no es json"), 0), h.recordedDLQ)
}

func TestRecordedSobreAlertaDescartadaHaceAckSinCrearElRegistro(t *testing.T) {
	h := newHarness()
	id := uuid.New()
	h.record(t, id)
	if outcome := h.discarded.Handle(context.Background(), envelopeBody(t, "audit.alert.discarded", map[string]any{"alert_id": id.String(), "reason": "REJECTED"}), 0); outcome != OutcomeAck {
		t.Fatalf("descarte: %v", outcome)
	}

	outcome := h.recorded.Handle(context.Background(), envelopeBody(t, "audit.alert.recorded", recordedPayloadFor(id)), 0)

	if outcome != OutcomeAck {
		t.Fatalf("outcome = %v, esperaba ack", outcome)
	}
	if _, ok := h.store.Lookup(id); ok {
		t.Error("un recorded duplicado tras el descarte no debe recrear el registro")
	}
	if len(h.recordedDLQ.published) != 0 {
		t.Error("no va a la DLQ")
	}
}

func TestDiscardedDuplicadoTrasElBorradoHaceAckSinDLQ(t *testing.T) {
	h := newHarness()
	id := uuid.New()
	h.record(t, id)
	body := envelopeBody(t, "audit.alert.discarded", map[string]any{"alert_id": id.String(), "reason": "EXPIRED"})
	if outcome := h.discarded.Handle(context.Background(), body, 0); outcome != OutcomeAck {
		t.Fatalf("primer descarte: %v", outcome)
	}

	outcome := h.discarded.Handle(context.Background(), body, 0)

	if outcome != OutcomeAck || len(h.discardedDLQ.published) != 0 {
		t.Errorf("la reentrega debe hacer ack sin DLQ (outcome=%v, DLQ=%d)", outcome, len(h.discardedDLQ.published))
	}
}

func TestDeliveredSobreAlertaDescartadaVaALaDLQSinReintento(t *testing.T) {
	h := newHarness()
	id := uuid.New()
	h.record(t, id)
	if outcome := h.discarded.Handle(context.Background(), envelopeBody(t, "audit.alert.discarded", map[string]any{"alert_id": id.String(), "reason": "UNCLAIMED"}), 0); outcome != OutcomeAck {
		t.Fatalf("descarte: %v", outcome)
	}
	puts := h.audit.PutCalls

	outcome := h.delivered.Handle(context.Background(), envelopeBody(t, "audit.alert.delivered", h.deliveredPayloadFor(id)), 0)

	assertDLQ(t, outcome, h.deliveredDLQ)
	if h.audit.PutCalls != puts {
		t.Error("no debe subir nada")
	}
}
