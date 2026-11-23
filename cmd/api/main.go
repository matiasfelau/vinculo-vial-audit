// Command api es el Audit Service de Vínculo Vial: consume los eventos
// audit.alert.* y conserva, aislado e inmutable, el registro de cada alerta que
// llegó a un destinatario. No tiene usuarios, endpoints públicos ni eventos
// propios: su única superficie HTTP es /health, /ready y /health/deps.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/matiasfelau/vinculo-vial-audit/internal/client/storage"
	"github.com/matiasfelau/vinculo-vial-audit/internal/delivery/events"
	httpdelivery "github.com/matiasfelau/vinculo-vial-audit/internal/delivery/http"
	"github.com/matiasfelau/vinculo-vial-audit/internal/lifecycle"
	"github.com/matiasfelau/vinculo-vial-audit/internal/repository/postgres"
	"github.com/matiasfelau/vinculo-vial-audit/internal/service/record"
	"github.com/matiasfelau/vinculo-vial-audit/internal/service/sweeper"
	"github.com/matiasfelau/vinculo-vial-audit/pkg/config"
)

// Plazos del *http.Server. Sin ellos, el server de Go no aplica ningún límite de
// lectura ni de escritura. shutdownTimeout acota cuánto espera el apagado
// ordenado a que las peticiones en vuelo terminen antes de cortarlas.
// hoursPerDay convierte AUDIT_TOMBSTONE_DAYS a una duración.
const hoursPerDay = 24

const (
	httpReadHeaderTimeout = 5 * time.Second
	httpReadTimeout       = 10 * time.Second
	httpWriteTimeout      = 15 * time.Second
	httpIdleTimeout       = 60 * time.Second
	shutdownTimeout       = 10 * time.Second

	// backgroundShutdownTimeout acota, en conjunto, cuánto espera el apagado al
	// mensaje en curso de cada consumidor y a la vuelta en curso del sweeper.
	backgroundShutdownTimeout = 20 * time.Second

	// startupTimeout acota la construcción de los clientes de S3 al arrancar.
	startupTimeout = 15 * time.Second
)

func main() { os.Exit(exitCode(execute)) }

// exitCode corre start y devuelve el código de salida del proceso: 0 si el
// servicio se apagó en orden y 1 si el arranque o la ejecución fallaron, con el
// error en el log. Recibe la función para poder probar los dos caminos.
func exitCode(start func() error) int {
	if err := start(); err != nil {
		slog.Error("el servicio terminó con error", "error", err.Error())
		return 1
	}
	return 0
}

// execute prepara el logger y el modo de gin, carga la configuración y corre el
// servicio. main queda en llamarla y salir con el estado que corresponda; el
// arranque en sí vive en run, que recibe la configuración y el contexto.
func execute() error {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	// Sin modo de depuración: ni trazas de rutas ni detalles internos en la salida.
	gin.SetMode(gin.ReleaseMode)

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	return run(context.Background(), cfg)
}

// run levanta el servicio con cfg y bloquea hasta que ctx se cancele o llegue
// SIGINT o SIGTERM. Devuelve nil tras un apagado ordenado.
func run(ctx context.Context, cfg *config.Config) error {
	db, err := postgres.Connect(cfg.DatabaseURL)
	if err != nil {
		return err
	}
	if err := postgres.Migrate(db); err != nil {
		return err
	}
	repository := postgres.NewAuditRepository(db, postgres.WithQueryTimeout(cfg.DBQueryTimeout))

	startCtx, cancelStart := context.WithTimeout(context.Background(), startupTimeout)
	evidenceStore, err := storage.New(startCtx, storageConfig(cfg, cfg.EvidenceBucket))
	if err != nil {
		cancelStart()
		return err
	}
	auditStore, err := storage.New(startCtx, storageConfig(cfg, cfg.AuditBucket))
	cancelStart()
	if err != nil {
		return err
	}

	recorder := record.NewRecorder(repository, cfg.RetentionDays)
	deliverer := record.NewDeliverer(repository, evidenceStore, auditStore)
	discarder := record.NewDiscarder(repository)

	consumers := []consumerSpec{
		{queue: cfg.RecordedQueue, name: "recorded_consumer", processor: events.NewRecordedProcessor(recorder), status: &events.ConnectionStatus{}},
		{queue: cfg.DeliveredQueue, name: "delivered_consumer", processor: events.NewDeliveredProcessor(deliverer, cfg.EvidenceBucket), status: &events.ConnectionStatus{}},
		{queue: cfg.DiscardedQueue, name: "discarded_consumer", processor: events.NewDiscardedProcessor(discarder), status: &events.ConnectionStatus{}},
	}

	checks := []httpdelivery.DependencyCheck{
		{Name: "database", Healthy: func(ctx context.Context) bool { return repository.Ping(ctx) == nil }},
		{Name: "evidence_bucket", Healthy: withoutContext(evidenceStore.Healthy)},
		{Name: "audit_bucket", Healthy: withoutContext(auditStore.Healthy)},
	}
	for _, c := range consumers {
		checks = append(checks, httpdelivery.DependencyCheck{Name: c.name, Healthy: withoutContext(c.status.Connected)})
	}

	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           httpdelivery.NewRouter(repository, checks...),
		ReadHeaderTimeout: httpReadHeaderTimeout,
		ReadTimeout:       httpReadTimeout,
		WriteTimeout:      httpWriteTimeout,
		IdleTimeout:       httpIdleTimeout,
	}

	// El apagado ordenado se dispara ante SIGINT o SIGTERM: se dejan de aceptar
	// solicitudes, los consumidores terminan el mensaje en curso (el resto vuelve a
	// la cola) y el sweeper termina la vuelta en curso.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	var background sync.WaitGroup
	for _, c := range consumers {
		background.Add(1)
		go func() {
			defer background.Done()
			runConsumer(ctx, cfg, c)
		}()
	}

	background.Add(1)
	go func() {
		defer background.Done()
		sweeper.New(repository, auditStore, cfg.SweepBatchSize, time.Duration(cfg.TombstoneDays)*hoursPerDay*time.Hour).Run(ctx, cfg.SweepInterval)
	}()

	slog.Info("audit service escuchando", "port", cfg.Port)
	serveErr := lifecycle.RunUntilSignal(ctx, []lifecycle.Server{server}, shutdownTimeout)

	// Si el servidor falló antes de la señal hay que detener igual el trabajo de fondo.
	stop()
	waitBackground(&background, backgroundShutdownTimeout)

	return serveErr
}

// withoutContext adapta un chequeo local (sin llamadas de red) a la firma de
// DependencyCheck.
func withoutContext(check func() bool) func(context.Context) bool {
	return func(context.Context) bool { return check() }
}

// consumerSpec describe un consumidor de una cola de auditoría.
type consumerSpec struct {
	queue     string
	name      string
	processor events.Processor
	status    *events.ConnectionStatus
}

// runConsumer consume la cola hasta que ctx se cancele, con su propia conexión y
// reconexión: un broker caído no afecta a /health ni a /ready.
func runConsumer(ctx context.Context, cfg *config.Config, spec consumerSpec) {
	events.RunWithReconnect(ctx, cfg.RabbitMQURL, spec.queue, cfg.RabbitMQPrefetch, spec.status,
		func(channel events.ConsumerChannel) *events.Consumer {
			deadLetters := events.NewAMQPDeadLetterPublisher(channel, cfg.RabbitMQPublishTimeout)
			handler := events.NewMessageHandler(spec.processor, deadLetters, spec.queue, cfg.MaxRetries)
			return events.NewConsumer(channel, spec.queue, handler)
		})
}

// waitBackground espera a que terminen los consumidores y el sweeper, hasta timeout.
func waitBackground(background *sync.WaitGroup, timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		background.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		slog.Warn("el trabajo de fondo no terminó a tiempo; los mensajes en vuelo se reentregan al reiniciar")
	}
}

// storageConfig arma la configuración del Store de un bucket.
func storageConfig(cfg *config.Config, bucket string) storage.Config {
	return storage.Config{
		Region:              cfg.S3.Region,
		Bucket:              bucket,
		LockMode:            cfg.ObjectLockMode,
		PutTimeout:          cfg.S3.PutTimeout,
		GetTimeout:          cfg.S3.GetTimeout,
		MaxObjectBytes:      cfg.S3.MaxObjectBytes,
		BreakerThreshold:    cfg.S3.BreakerThreshold,
		BreakerWindow:       cfg.S3.BreakerWindow,
		BreakerOpenDuration: cfg.S3.BreakerOpenDuration,
	}
}
