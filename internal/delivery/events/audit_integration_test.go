//go:build integration

package events

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
	"gorm.io/gorm"

	"github.com/matiasfelau/vinculo-vial-audit/internal/domain"
	"github.com/matiasfelau/vinculo-vial-audit/internal/repository/postgres"
	"github.com/matiasfelau/vinculo-vial-audit/internal/repository/postgres/postgrestest"
	"github.com/matiasfelau/vinculo-vial-audit/internal/service/record"
	"github.com/matiasfelau/vinculo-vial-audit/internal/testsupport"
)

// Estas pruebas corren contra un RabbitMQ real (TEST_RABBITMQ_URL) y un PostgreSQL
// real (DATABASE_URL) porque lo que verifican es comportamiento del broker (x-death,
// TTL de la cola .retry, dead letter, publisher confirms) y la cadena completa
// consumidor → caso de uso → base. Se ejecutan con:
//
//	go test -tags integration ./internal/delivery/events/...
//
// Replican la topología que declara vinculo-vial-core: cola de trabajo → exchange
// de retry → .retry con TTL → de vuelta a la cola de trabajo, y .dlq bindeada al
// exchange de dead letter por el nombre de la cola de trabajo.
const (
	integrationRetryTTLMillis = 150
	integrationMaxRetries     = 2
	integrationPrefetch       = 5
	integrationWait           = 20 * time.Second
	integrationPublishTimeout = 5 * time.Second
	integrationRetentionDays  = 3
)

const envRabbitMQURL = "TEST_RABBITMQ_URL"

func brokerURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv(envRabbitMQURL)
	if url == "" {
		t.Skip("TEST_RABBITMQ_URL no configurada: se omite la prueba contra RabbitMQ")
	}
	return url
}

// flujo es la topología de un consumidor, con nombres únicos por prueba.
type flujo struct {
	eventType     string
	exchange      string
	retryExchange string
	work          string
	retry         string
	dlq           string
}

// declararFlujo declara el exchange de eventos, el de retry, y las colas de
// trabajo, .retry y .dlq con sus bindings, y los borra al terminar. El exchange de
// dead letter es fijo en la plataforma (dlqExchange): se declara igual que Core
// (topic, durable) y no se borra, por si lo comparte con un broker de desarrollo.
func declararFlujo(t *testing.T, conn *amqp.Connection, eventType string) flujo {
	t.Helper()

	ch, err := conn.Channel()
	if err != nil {
		t.Fatalf("no se pudo abrir el canal: %v", err)
	}
	t.Cleanup(func() { _ = ch.Close() })

	id := uuid.NewString()[:8]
	f := flujo{
		eventType:     eventType,
		exchange:      "vvi.test." + id,
		retryExchange: "vvi.test.retry." + id,
		work:          "audit.test-" + id + ".q",
		retry:         "audit.test-" + id + ".retry",
		dlq:           "audit.test-" + id + ".dlq",
	}

	for _, exchange := range []string{f.exchange, f.retryExchange, dlqExchange} {
		if err := ch.ExchangeDeclare(exchange, "topic", true, false, false, false, nil); err != nil {
			t.Fatalf("no se pudo declarar el exchange %s: %v", exchange, err)
		}
	}

	declaraciones := []struct {
		name string
		args amqp.Table
	}{
		{f.work, amqp.Table{"x-dead-letter-exchange": f.retryExchange, "x-dead-letter-routing-key": f.work}},
		{f.retry, amqp.Table{"x-message-ttl": int32(integrationRetryTTLMillis), "x-dead-letter-exchange": "", "x-dead-letter-routing-key": f.work}},
		{f.dlq, nil},
	}
	for _, q := range declaraciones {
		if _, err := ch.QueueDeclare(q.name, true, false, false, false, q.args); err != nil {
			t.Fatalf("no se pudo declarar la cola %s: %v", q.name, err)
		}
	}
	bindings := []struct{ queue, key, exchange string }{
		{f.work, eventType, f.exchange},
		{f.retry, f.work, f.retryExchange},
		{f.dlq, f.work, dlqExchange},
	}
	for _, b := range bindings {
		if err := ch.QueueBind(b.queue, b.key, b.exchange, false, nil); err != nil {
			t.Fatalf("no se pudo bindear %s: %v", b.queue, err)
		}
	}

	t.Cleanup(func() {
		cleanup, err := conn.Channel()
		if err != nil {
			return
		}
		defer func() { _ = cleanup.Close() }()
		for _, q := range []string{f.work, f.retry, f.dlq} {
			_, _ = cleanup.QueueDelete(q, false, false, false)
		}
		_ = cleanup.ExchangeDelete(f.exchange, false, false)
		_ = cleanup.ExchangeDelete(f.retryExchange, false, false)
	})

	return f
}

// processorContado envuelve un Processor y cuenta cuántas veces se invocó.
type processorContado struct {
	inner Processor
	calls atomic.Int32
}

func (p *processorContado) Process(ctx context.Context, envelope InboundEnvelope) error {
	p.calls.Add(1)
	return p.inner.Process(ctx, envelope)
}

// iniciarConsumidor arranca el consumidor real (RunWithReconnect) sobre la cola
// de trabajo y devuelve una función que lo detiene y espera a que termine.
func iniciarConsumidor(t *testing.T, url string, f flujo, processor Processor) (detener func()) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	status := &ConnectionStatus{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		RunWithReconnect(ctx, url, f.work, integrationPrefetch, status, func(channel ConsumerChannel) *Consumer {
			deadLetters := NewAMQPDeadLetterPublisher(channel, integrationPublishTimeout)
			return NewConsumer(channel, f.work, NewMessageHandler(processor, deadLetters, f.work, integrationMaxRetries))
		})
	}()

	var once sync.Once
	detener = func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(integrationWait):
				t.Error("el consumidor no terminó a tiempo")
			}
		})
	}
	t.Cleanup(detener)

	if !esperar(status.Connected) {
		t.Fatal("el consumidor no se conectó al broker")
	}
	return detener
}

func esperar(cond func() bool) bool {
	deadline := time.Now().Add(integrationWait)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func publicar(t *testing.T, ch *amqp.Channel, f flujo, body []byte) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), integrationPublishTimeout)
	defer cancel()
	err := ch.PublishWithContext(ctx, f.exchange, f.eventType, true, false, amqp.Publishing{
		ContentType: "application/json", DeliveryMode: amqp.Persistent, Body: body,
	})
	if err != nil {
		t.Fatalf("no se pudo publicar el evento: %v", err)
	}
}

// esperarEnDLQ devuelve el primer mensaje que llega a la DLQ.
func esperarEnDLQ(t *testing.T, ch *amqp.Channel, f flujo) amqp.Delivery {
	t.Helper()

	deadline := time.Now().Add(integrationWait)
	for time.Now().Before(deadline) {
		msg, ok, err := ch.Get(f.dlq, true)
		if err != nil {
			t.Fatalf("no se pudo leer la DLQ: %v", err)
		}
		if ok {
			return msg
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("el mensaje no llegó a la DLQ a tiempo")
	return amqp.Delivery{}
}

// exigirColasVacias verifica que ninguna cola tenga mensajes listos. Con el
// consumidor detenido, un mensaje sin ack vuelve a estar listo, así que 0 prueba
// el ack.
func exigirColasVacias(t *testing.T, ch *amqp.Channel, colas ...string) {
	t.Helper()

	for _, queue := range colas {
		q, err := ch.QueueInspect(queue)
		if err != nil {
			t.Fatalf("no se pudo inspeccionar %s: %v", queue, err)
		}
		if q.Messages != 0 {
			t.Errorf("la cola %s tiene %d mensajes, esperaba 0", queue, q.Messages)
		}
	}
}

// entorno es la cadena completa: tres consumidores reales sobre un broker real, con
// los casos de uso reales, PostgreSQL real y un bucket en memoria.
type entorno struct {
	t         *testing.T
	ch        *amqp.Channel
	db        *gorm.DB
	repo      *postgres.AuditRepository
	evidence  *testsupport.MemoryObjects
	audit     *testsupport.MemoryObjects
	recorded  flujo
	delivered flujo
	discarded flujo

	recordedCalls  *processorContado
	deliveredCalls *processorContado
	discardedCalls *processorContado
	stop           func()
}

func nuevoEntorno(t *testing.T) *entorno {
	t.Helper()

	url := brokerURL(t)
	db := postgrestest.New(t)
	repo := postgres.NewAuditRepository(db, postgres.WithQueryTimeout(5*time.Second))

	conn, err := amqp.Dial(url)
	if err != nil {
		t.Fatalf("no se pudo conectar al broker de prueba: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	ch, err := conn.Channel()
	if err != nil {
		t.Fatalf("no se pudo abrir el canal: %v", err)
	}

	e := &entorno{
		t: t, ch: ch, db: db, repo: repo,
		evidence:  testsupport.NewMemoryObjects(),
		audit:     testsupport.NewMemoryObjects(),
		recorded:  declararFlujo(t, conn, eventTypeRecorded),
		delivered: declararFlujo(t, conn, eventTypeDelivered),
		discarded: declararFlujo(t, conn, eventTypeDiscarded),
	}

	e.recordedCalls = &processorContado{inner: NewRecordedProcessor(record.NewRecorder(repo, integrationRetentionDays))}
	e.deliveredCalls = &processorContado{inner: NewDeliveredProcessor(record.NewDeliverer(repo, e.evidence, e.audit), evidenceBucket)}
	e.discardedCalls = &processorContado{inner: NewDiscardedProcessor(record.NewDiscarder(repo))}

	stopRecorded := iniciarConsumidor(t, url, e.recorded, e.recordedCalls)
	stopDelivered := iniciarConsumidor(t, url, e.delivered, e.deliveredCalls)
	stopDiscarded := iniciarConsumidor(t, url, e.discarded, e.discardedCalls)
	e.stop = func() { stopRecorded(); stopDelivered(); stopDiscarded() }
	return e
}

func (e *entorno) estado(id uuid.UUID) (domain.Status, bool) {
	record, err := e.repo.Get(context.Background(), id)
	if err != nil {
		return "", false
	}
	return record.Status, true
}

func (e *entorno) existe(id uuid.UUID) bool {
	_, ok := e.estado(id)
	return ok
}

func (e *entorno) publicarRecorded(id uuid.UUID) {
	e.t.Helper()
	publicar(e.t, e.ch, e.recorded, envelopeBody(e.t, eventTypeRecorded, recordedPayloadFor(id)))
}

func (e *entorno) publicarDelivered(id uuid.UUID, mutar func(payload map[string]any)) {
	e.t.Helper()
	h := &harness{evidence: e.evidence}
	payload := h.deliveredPayloadFor(id)
	if mutar != nil {
		mutar(payload)
	}
	publicar(e.t, e.ch, e.delivered, envelopeBody(e.t, eventTypeDelivered, payload))
}

func (e *entorno) publicarDiscarded(id uuid.UUID, reason string) {
	e.t.Helper()
	publicar(e.t, e.ch, e.discarded, envelopeBody(e.t, eventTypeDiscarded, map[string]any{"alert_id": id.String(), "reason": reason}))
}

func (e *entorno) exigirTodoConfirmado() {
	e.t.Helper()
	e.stop()
	exigirColasVacias(e.t, e.ch,
		e.recorded.work, e.recorded.retry, e.recorded.dlq,
		e.delivered.work, e.delivered.retry, e.delivered.dlq,
		e.discarded.work, e.discarded.retry, e.discarded.dlq)
}

func TestIntegracionRecordedCreaElRegistroEnPostgresYHaceAck(t *testing.T) {
	e := nuevoEntorno(t)
	id := uuid.New()

	e.publicarRecorded(id)

	if !esperar(func() bool { return e.existe(id) }) {
		t.Fatal("el registro no se creó")
	}
	e.exigirTodoConfirmado()
	if status, _ := e.estado(id); status != domain.StatusRecorded {
		t.Errorf("status = %s, esperaba RECORDED", status)
	}
}

func TestIntegracionRecordedRepetidoEsIdempotente(t *testing.T) {
	e := nuevoEntorno(t)
	id := uuid.New()

	for i := 0; i < 3; i++ {
		e.publicarRecorded(id)
	}

	if !esperar(func() bool { return e.recordedCalls.calls.Load() == 3 }) {
		t.Fatalf("se procesaron %d de las 3 entregas", e.recordedCalls.calls.Load())
	}
	e.exigirTodoConfirmado()
	var total int64
	e.db.Table("audit_records").Count(&total)
	if total != 1 {
		t.Errorf("hay %d registros, esperaba 1", total)
	}
}

func TestIntegracionDeliveredLlegaAntesQueRecordedYSeReintentaHastaQueExiste(t *testing.T) {
	e := nuevoEntorno(t)
	id := uuid.New()

	e.publicarDelivered(id, nil)
	if !esperar(func() bool { return e.deliveredCalls.calls.Load() >= 1 }) {
		t.Fatal("delivered no llegó al consumidor")
	}
	e.publicarRecorded(id)

	if !esperar(func() bool { status, _ := e.estado(id); return status == domain.StatusDelivered }) {
		t.Fatal("el registro no llegó a DELIVERED tras el reintento")
	}
	if n := e.deliveredCalls.calls.Load(); n < 2 {
		t.Errorf("delivered se procesó %d veces, esperaba al menos 2 (un reintento por orden invertido)", n)
	}
	e.exigirTodoConfirmado()
	if len(e.audit.Keys()) != 3 {
		t.Errorf("objetos en el bucket de Audit = %v, esperaba 2 fotos y el manifiesto", e.audit.Keys())
	}
}

func TestIntegracionDiscardedSinRegistroAgotaMaxRetriesYVaALaDLQ(t *testing.T) {
	e := nuevoEntorno(t)
	id := uuid.New()
	body := envelopeBody(t, eventTypeDiscarded, map[string]any{"alert_id": id.String(), "reason": "REJECTED"})

	publicar(t, e.ch, e.discarded, body)

	msg := esperarEnDLQ(t, e.ch, e.discarded)
	if string(msg.Body) != string(body) {
		t.Error("la DLQ debe recibir el cuerpo original")
	}
	e.stop()
	if n := e.discardedCalls.calls.Load(); n != integrationMaxRetries+1 {
		t.Errorf("discarded se procesó %d veces, esperaba %d (1 + MAX_RETRIES)", n, integrationMaxRetries+1)
	}
	exigirColasVacias(t, e.ch, e.discarded.work, e.discarded.retry)
}

func TestIntegracionRecordedYDiscardedBorranElRegistro(t *testing.T) {
	e := nuevoEntorno(t)
	id := uuid.New()
	e.publicarRecorded(id)
	if !esperar(func() bool { return e.existe(id) }) {
		t.Fatal("el registro no se creó")
	}

	e.publicarDiscarded(id, "REJECTED")

	if !esperar(func() bool { return !e.existe(id) }) {
		t.Fatal("el registro RECORDED no se borró")
	}
	e.exigirTodoConfirmado()
}

func TestIntegracionDiscardedSobreRegistroEntregadoHaceAckSinBorrar(t *testing.T) {
	e := nuevoEntorno(t)
	id := uuid.New()
	e.publicarRecorded(id)
	if !esperar(func() bool { return e.existe(id) }) {
		t.Fatal("el registro no se creó")
	}
	e.publicarDelivered(id, nil)
	if !esperar(func() bool { status, _ := e.estado(id); return status == domain.StatusDelivered }) {
		t.Fatal("el registro no se entregó")
	}

	e.publicarDiscarded(id, "UNCLAIMED")

	if !esperar(func() bool { return e.discardedCalls.calls.Load() == 1 }) {
		t.Fatal("discarded no se procesó")
	}
	e.exigirTodoConfirmado()
	if status, ok := e.estado(id); !ok || status != domain.StatusDelivered {
		t.Error("un registro entregado nunca se borra antes de su vencimiento")
	}
}

func TestIntegracionDeliveredConSHA256DistintoVaALaDLQSinReintento(t *testing.T) {
	e := nuevoEntorno(t)
	id := uuid.New()
	e.publicarRecorded(id)
	if !esperar(func() bool { return e.existe(id) }) {
		t.Fatal("el registro no se creó")
	}

	e.publicarDelivered(id, func(payload map[string]any) {
		payload["evidence"].([]map[string]any)[0]["sha256"] = sha([]byte("otro contenido"))
	})

	esperarEnDLQ(t, e.ch, e.delivered)
	e.stop()
	if n := e.deliveredCalls.calls.Load(); n != 1 {
		t.Errorf("delivered se procesó %d veces, esperaba 1 (error permanente, sin reintento)", n)
	}
	exigirColasVacias(t, e.ch, e.delivered.work, e.delivered.retry)
	if status, _ := e.estado(id); status != domain.StatusRecorded {
		t.Errorf("status = %s, el registro no debe entregarse con una foto alterada", status)
	}
}

func TestIntegracionPayloadInvalidoVaALaDLQSinReintento(t *testing.T) {
	e := nuevoEntorno(t)
	payload := recordedPayloadFor(uuid.New())
	delete(payload, "dni_enc_audit")
	body := envelopeBody(t, eventTypeRecorded, payload)

	publicar(t, e.ch, e.recorded, body)

	msg := esperarEnDLQ(t, e.ch, e.recorded)
	if motivo, _ := msg.Headers[headerDiscardReason].(string); motivo == "" {
		t.Error("la DLQ debía recibir x-discard-reason")
	}
	if msg.DeliveryMode != amqp.Persistent {
		t.Errorf("DeliveryMode = %d, esperaba persistente", msg.DeliveryMode)
	}
	e.stop()
	if n := e.recordedCalls.calls.Load(); n != 1 {
		t.Errorf("el procesador corrió %d veces, esperaba 1 (error permanente, sin reintento)", n)
	}
	exigirColasVacias(t, e.ch, e.recorded.work, e.recorded.retry)
	var total int64
	e.db.Table("audit_records").Count(&total)
	if total != 0 {
		t.Errorf("hay %d registros, esperaba 0", total)
	}
}
