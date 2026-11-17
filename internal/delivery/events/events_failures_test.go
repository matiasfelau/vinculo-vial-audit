package events

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/matiasfelau/vinculo-vial-audit/internal/domain"
)

// syncBuffer es un bytes.Buffer seguro para las goroutines que loguean.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// capturarLogs reemplaza el logger por defecto durante la prueba.
func capturarLogs(t *testing.T) *syncBuffer {
	t.Helper()
	logs := &syncBuffer{}
	previo := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previo) })
	return logs
}

// --- procesadores ---

func TestDeliveredYDiscardedConEnvelopeInvalidoVanALaDLQ(t *testing.T) {
	casos := []struct {
		nombre    string
		eventType string
		payload   any
		handler   func(*harness) *MessageHandler
		dlq       func(*harness) *fakeDeadLetterPublisher
	}{
		{"delivered con eventType de otro evento", "audit.alert.recorded", map[string]any{}, func(h *harness) *MessageHandler { return h.delivered }, func(h *harness) *fakeDeadLetterPublisher { return h.deliveredDLQ }},
		{"delivered con payload que no es un objeto", "audit.alert.delivered", "texto", func(h *harness) *MessageHandler { return h.delivered }, func(h *harness) *fakeDeadLetterPublisher { return h.deliveredDLQ }},
		{"discarded con eventType de otro evento", "audit.alert.delivered", map[string]any{}, func(h *harness) *MessageHandler { return h.discarded }, func(h *harness) *fakeDeadLetterPublisher { return h.discardedDLQ }},
		{"discarded con payload que no es un objeto", "audit.alert.discarded", []int{1, 2}, func(h *harness) *MessageHandler { return h.discarded }, func(h *harness) *fakeDeadLetterPublisher { return h.discardedDLQ }},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			h := newHarness()

			outcome := c.handler(h).Handle(context.Background(), envelopeBody(t, c.eventType, c.payload), 0)

			assertDLQ(t, outcome, c.dlq(h))
		})
	}
}

// Un delivered cuyo registro ya venció (o está por vencer) no se puede archivar
// con Object Lock: es permanente, va a la DLQ en vez de reintentarse.
func TestDeliveredSobreUnRegistroVencidoVaALaDLQSinTocarS3(t *testing.T) {
	h := newHarness()
	id := uuid.New()
	h.store.Put(domain.Record{AlertID: id, Status: domain.StatusRecorded, DestroyAt: time.Now().Add(-time.Hour)})
	gets := h.evidence.GetCalls

	outcome := h.delivered.Handle(context.Background(), envelopeBody(t, "audit.alert.delivered", h.deliveredPayloadFor(id)), 0)

	assertDLQ(t, outcome, h.deliveredDLQ)
	if h.audit.PutCalls != 0 || h.evidence.GetCalls != gets {
		t.Error("un registro vencido no debe tocar S3")
	}
	if got, _ := h.store.Lookup(id); got.Status != domain.StatusRecorded {
		t.Errorf("status = %s, el registro vencido no debe entregarse", got.Status)
	}
}

// --- consumidor ---

type failingAcknowledger struct{}

func (failingAcknowledger) Ack(uint64, bool) error        { return errors.New("canal cerrado") }
func (failingAcknowledger) Nack(uint64, bool, bool) error { return errors.New("canal cerrado") }
func (failingAcknowledger) Reject(uint64, bool) error     { return errors.New("canal cerrado") }

func TestConsumerSiNoPuedeConfirmarORechazarLoLoguaSinElCuerpoDelMensaje(t *testing.T) {
	casos := []struct {
		nombre  string
		outcome Outcome
		mensaje string
	}{
		{"ack", OutcomeAck, "no se pudo confirmar el mensaje"},
		{"nack", OutcomeNackNoRequeue, "no se pudo rechazar el mensaje"},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			logs := capturarLogs(t)
			consumer := NewConsumer(nil, testQueue, &handlerFijo{outcome: c.outcome})

			consumer.process(context.Background(), amqp.Delivery{
				Acknowledger: failingAcknowledger{},
				DeliveryTag:  1,
				Body:         []byte(`{"dni_enc_audit":"CRIPTOGRAMA-SECRETO"}`),
			})

			salida := logs.String()
			if !strings.Contains(salida, c.mensaje) || !strings.Contains(salida, testQueue) {
				t.Errorf("no se registró la falla con la cola: %q", salida)
			}
			if strings.Contains(salida, "CRIPTOGRAMA-SECRETO") {
				t.Errorf("el log refleja el contenido del mensaje: %q", salida)
			}
		})
	}
}

// --- reconexión ---

type errCloser struct{ closed atomic.Int32 }

func (c *errCloser) Close() error {
	c.closed.Add(1)
	return errors.New("conexión ya cerrada")
}

type closeErrChannel struct{ *fakeConsumerChannel }

func (closeErrChannel) Close() error { return errors.New("canal ya cerrado") }

func finalizaEn(t *testing.T, done <-chan struct{}, mensaje string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(testWait):
		t.Fatal(mensaje)
	}
}

func TestRunWithReconnectSeDetieneSiSeCancelaEsperandoParaReintentarUnaConexionFallida(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var dials atomic.Int32
	status := &ConnectionStatus{}
	open := func() (closer, ConsumerChannel, error) {
		dials.Add(1)
		return nil, nil, errors.New("broker caído")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Con un backoff de una hora, solo la cancelación puede terminar la espera.
		runWithReconnect(ctx, open, testQueue, status, nil, backoffLimits{min: time.Hour, max: time.Hour})
	}()
	if !waitFor(func() bool { return dials.Load() == 1 }) {
		t.Fatal("no se intentó conectar")
	}

	cancel()

	finalizaEn(t, done, "no terminó al cancelarse durante el backoff")
	if status.Connected() {
		t.Error("el estado debía quedar desconectado")
	}
	if dials.Load() != 1 {
		t.Errorf("intentos = %d, no debía reintentar tras cancelar", dials.Load())
	}
}

func TestRunWithReconnectSeDetieneSiSeCancelaEsperandoTrasPerderLaConexion(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var dials atomic.Int32
	conn := &fakeCloser{}
	open := func() (closer, ConsumerChannel, error) {
		dials.Add(1)
		channel := &fakeConsumerChannel{consumeDeliveries: make(chan amqp.Delivery)}
		close(channel.consumeDeliveries) // la conexión se cae enseguida
		return conn, channel, nil
	}
	factory := func(channel ConsumerChannel) *Consumer { return NewConsumer(channel, testQueue, &handlerFijo{}) }
	done := make(chan struct{})
	go func() {
		defer close(done)
		runWithReconnect(ctx, open, testQueue, &ConnectionStatus{}, factory, backoffLimits{min: time.Hour, max: time.Hour})
	}()
	if !waitFor(func() bool { return conn.closed.Load() == 1 }) {
		t.Fatal("la conexión caída no se cerró")
	}

	cancel()

	finalizaEn(t, done, "no terminó al cancelarse durante el backoff posterior a la caída")
	if dials.Load() != 1 {
		t.Errorf("conexiones abiertas = %d, esperaba 1", dials.Load())
	}
}

// Que el broker ya haya cerrado la conexión no impide reconectar.
func TestRunWithReconnectSigueReconectandoAunqueFalleElCierreDeCanalYConexion(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var dials atomic.Int32
	conn := &errCloser{}
	open := func() (closer, ConsumerChannel, error) {
		dials.Add(1)
		channel := &fakeConsumerChannel{consumeDeliveries: make(chan amqp.Delivery)}
		close(channel.consumeDeliveries)
		return conn, closeErrChannel{channel}, nil
	}
	factory := func(channel ConsumerChannel) *Consumer { return NewConsumer(channel, testQueue, &handlerFijo{}) }
	done := make(chan struct{})
	go func() {
		defer close(done)
		runWithReconnect(ctx, open, testQueue, &ConnectionStatus{}, factory, backoffLimits{min: testBackoffMin, max: testBackoffMax})
	}()

	if !waitFor(func() bool { return dials.Load() >= 3 }) {
		t.Fatalf("solo hubo %d conexiones: un error al cerrar frenó la reconexión", dials.Load())
	}
	cancel()
	finalizaEn(t, done, "no terminó al cancelar")
}

func TestDialConsumerConBrokerInalcanzableFallaSinFiltrarLasCredenciales(t *testing.T) {
	conn, channel, err := dialConsumer("amqp://usuario:clave-secreta@127.0.0.1:1/", 10)

	if err == nil {
		_ = channel.Close()
		_ = conn.Close()
		t.Fatal("dialConsumer no falló con el broker inalcanzable")
	}
	if conn != nil || channel != nil {
		t.Error("con error no debe devolver conexión ni canal")
	}
	if strings.Contains(err.Error(), "clave-secreta") {
		t.Errorf("el error filtra las credenciales del broker: %v", err)
	}
}

func TestWatchReturnsLoguaElDestinoSinElCuerpoDelMensaje(t *testing.T) {
	logs := capturarLogs(t)
	returns := make(chan amqp.Return, 1)
	returns <- amqp.Return{
		Exchange:   "vvi.events",
		RoutingKey: "audit.alert-recorded",
		ReplyCode:  312,
		ReplyText:  "NO_ROUTE",
		Body:       []byte("CRIPTOGRAMA-SECRETO"),
	}
	close(returns)

	watchReturns(returns)

	salida := logs.String()
	for _, esperado := range []string{"vvi.events", "audit.alert-recorded", "312", "NO_ROUTE"} {
		if !strings.Contains(salida, esperado) {
			t.Errorf("el log no incluye %q: %s", esperado, salida)
		}
	}
	if strings.Contains(salida, "CRIPTOGRAMA-SECRETO") {
		t.Errorf("el log refleja el cuerpo del mensaje: %s", salida)
	}
}
