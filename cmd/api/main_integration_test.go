//go:build integration

package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/matiasfelau/vinculo-vial-audit/internal/repository/postgres/postgrestest"
	"github.com/matiasfelau/vinculo-vial-audit/pkg/config"
)

// Estas pruebas levantan el servicio completo con run() contra un PostgreSQL y un
// RabbitMQ reales (DATABASE_URL y TEST_RABBITMQ_URL). S3 no se toca: el cliente se
// construye sin red y la base de prueba está vacía, así que el sweeper no tiene
// nada que borrar.

const (
	esperaArranque = 30 * time.Second
	esperaApagado  = 30 * time.Second
)

// configDePrueba arma una Config con un esquema aislado de PostgreSQL, colas de
// RabbitMQ únicas ya declaradas (Core es quien las declara en producción) y un
// puerto HTTP libre.
func configDePrueba(t *testing.T) *config.Config {
	t.Helper()

	brokerURL := os.Getenv("TEST_RABBITMQ_URL")
	if brokerURL == "" {
		t.Skip("TEST_RABBITMQ_URL no configurada: se omite la prueba contra RabbitMQ")
	}

	db := postgrestest.New(t)
	dsn := postgrestest.DSN(t, postgrestest.Schema(t, db))

	id := uuid.NewString()[:8]
	colas := []string{"audit.test-run-recorded-" + id + ".q", "audit.test-run-delivered-" + id + ".q", "audit.test-run-discarded-" + id + ".q"}
	declararColas(t, brokerURL, colas)

	return &config.Config{
		Port:                   puertoLibre(t),
		DatabaseURL:            dsn,
		DBQueryTimeout:         2 * time.Second,
		RabbitMQURL:            brokerURL,
		RabbitMQPublishTimeout: 2 * time.Second,
		RabbitMQPrefetch:       5,
		MaxRetries:             3,
		RecordedQueue:          colas[0],
		DeliveredQueue:         colas[1],
		DiscardedQueue:         colas[2],
		RetentionDays:          1095,
		ObjectLockMode:         config.LockModeGovernance,
		AuditBucket:            "audit-test",
		EvidenceBucket:         "evidence-test",
		S3: config.S3{
			Region:              "us-east-1",
			PutTimeout:          time.Second,
			GetTimeout:          time.Second,
			MaxObjectBytes:      1 << 20,
			BreakerThreshold:    3,
			BreakerWindow:       time.Minute,
			BreakerOpenDuration: time.Minute,
		},
		SweepInterval:  time.Hour,
		SweepBatchSize: 10,
		TombstoneDays:  1,
	}
}

func declararColas(t *testing.T, brokerURL string, colas []string) {
	t.Helper()

	conn, err := amqp.Dial(brokerURL)
	if err != nil {
		t.Fatalf("no se pudo conectar a RabbitMQ: %v", err)
	}
	ch, err := conn.Channel()
	if err != nil {
		t.Fatalf("no se pudo abrir el canal: %v", err)
	}
	for _, q := range colas {
		if _, err := ch.QueueDeclare(q, true, false, false, false, nil); err != nil {
			t.Fatalf("no se pudo declarar %s: %v", q, err)
		}
	}
	t.Cleanup(func() {
		for _, q := range colas {
			_, _ = ch.QueueDelete(q, false, false, false)
		}
		_ = ch.Close()
		_ = conn.Close()
	})
}

func puertoLibre(t *testing.T) string {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("no se pudo reservar un puerto: %v", err)
	}
	defer func() { _ = l.Close() }()
	return strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
}

func obtener(url string) (int, error) {
	cliente := http.Client{Timeout: 2 * time.Second}
	resp, err := cliente.Get(url)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, nil
}

func TestRunLevantaElServicioYSeApagaAlCancelarElContexto(t *testing.T) {
	cfg := configDePrueba(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	terminado := make(chan error, 1)
	go func() { terminado <- run(ctx, cfg) }()

	// /health/deps solo da 200 cuando la base, los dos buckets y los tres
	// consumidores (cada uno con su cola) están arriba.
	depsURL := "http://127.0.0.1:" + cfg.Port + "/health/deps"
	var ultimo int
	var ultimoErr error
	arriba := false
	for limite := time.Now().Add(esperaArranque); time.Now().Before(limite); time.Sleep(100 * time.Millisecond) {
		select {
		case err := <-terminado:
			t.Fatalf("run terminó antes de tiempo: %v", err)
		default:
		}
		if ultimo, ultimoErr = obtener(depsURL); ultimoErr == nil && ultimo == http.StatusOK {
			arriba = true
			break
		}
	}
	if !arriba {
		t.Fatalf("/health/deps no llegó a 200 (último estado %d, error %v)", ultimo, ultimoErr)
	}

	for _, ruta := range []string{"/health", "/ready"} {
		if status, err := obtener("http://127.0.0.1:" + cfg.Port + ruta); err != nil || status != http.StatusOK {
			t.Errorf("GET %s = %d (error %v), esperaba 200", ruta, status, err)
		}
	}

	cancel()
	select {
	case err := <-terminado:
		if err != nil {
			t.Errorf("run devolvió %v tras el apagado ordenado, esperaba nil", err)
		}
	case <-time.After(esperaApagado):
		t.Fatal("run no terminó tras cancelar el contexto")
	}

	if _, err := obtener(depsURL); err == nil {
		t.Error("el servidor sigue aceptando conexiones tras el apagado")
	}
}

func TestRunDevuelveElErrorSiElPuertoEstaOcupadoYDetieneElTrabajoDeFondo(t *testing.T) {
	cfg := configDePrueba(t)

	ocupante, err := net.Listen("tcp", ":"+cfg.Port)
	if err != nil {
		t.Skipf("no se pudo ocupar el puerto %s: %v", cfg.Port, err)
	}
	defer func() { _ = ocupante.Close() }()

	terminado := make(chan error, 1)
	go func() { terminado <- run(context.Background(), cfg) }()

	select {
	case err := <-terminado:
		if err == nil {
			t.Error("run devolvió nil con el puerto ocupado")
		}
	case <-time.After(esperaApagado):
		t.Fatal("run no terminó con el puerto ocupado: el trabajo de fondo quedó colgado")
	}
}
