// Package config centraliza la carga de configuración desde variables de
// entorno, con validación fail-fast: ante una variable obligatoria ausente o
// inválida el proceso no arranca.
package config

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultPort = "8080"

	// Convención de nombres de cola: <consumidor>.<evento-kebab>.q. Deben coincidir
	// con las que declara vinculo-vial-core, junto con su .retry y su .dlq.
	defaultRecordedQueue  = "audit.alert-recorded.q"
	defaultDeliveredQueue = "audit.alert-delivered.q"
	defaultDiscardedQueue = "audit.alert-discarded.q"

	// maxRabbitMQPrefetch es el mayor prefetch que admite basic.qos: el campo del
	// protocolo es de 16 bits y un valor mayor se truncaría en silencio.
	maxRabbitMQPrefetch = 65535

	// maxRetentionDays acota AUDIT_RETENTION_DAYS (100 años): un valor mayor es casi
	// seguro un error de tipeo y produciría fechas de retención absurdas.
	maxRetentionDays = 36500

	// Modos de S3 Object Lock admitidos. COMPLIANCE solo en producción.
	LockModeGovernance = "GOVERNANCE"
	LockModeCompliance = "COMPLIANCE"

	// maxTombstoneDays acota AUDIT_TOMBSTONE_DAYS (10 años): el tombstone solo tiene
	// que cubrir la ventana de duplicados del broker.
	maxTombstoneDays = 3650

	// Hasta 1 GiB por objeto: un tope mayor no tiene sentido para una foto y deja
	// sin protección a la memoria del proceso.
	maxObjectBytesCeiling = 1 << 30
)

// forbiddenSecretNames son variables que Audit jamás debe recibir: las claves
// AES operativas de otros servicios. Además se rechaza toda variable terminada
// en _PRIVATE_KEY. Si alguna está definida el proceso no arranca: es la señal de
// que el despliegue le entregó a Audit un secreto que no le corresponde.
var forbiddenSecretNames = []string{"AES_KEY", "PAT_AES_KEY"}

const forbiddenSecretSuffix = "_PRIVATE_KEY"

// S3 agrupa los parámetros de las llamadas a S3: timeouts, tope de tamaño y
// circuit breaker. Cada bucket instancia su propio breaker con estos valores.
type S3 struct {
	Region              string
	PutTimeout          time.Duration
	GetTimeout          time.Duration
	MaxObjectBytes      int64
	BreakerThreshold    int
	BreakerWindow       time.Duration
	BreakerOpenDuration time.Duration
}

// Config agrupa los parámetros del servicio.
type Config struct {
	// Port es el puerto de /health y /ready. No se publica fuera de la red de Docker.
	Port string

	DatabaseURL    string
	DBQueryTimeout time.Duration

	RabbitMQURL            string
	RabbitMQPublishTimeout time.Duration
	RabbitMQPrefetch       int
	MaxRetries             int64
	RecordedQueue          string
	DeliveredQueue         string
	DiscardedQueue         string

	// RetentionDays es AUDIT_RETENTION_DAYS: cuánto se conserva un registro, contado
	// desde la creación de la alerta.
	RetentionDays int
	// ObjectLockMode es GOVERNANCE o COMPLIANCE.
	ObjectLockMode string

	AuditBucket    string
	EvidenceBucket string
	S3             S3

	SweepInterval  time.Duration
	SweepBatchSize int

	// TombstoneDays es AUDIT_TOMBSTONE_DAYS: cuánto se conserva el tombstone de un
	// descarte (alert_id y fecha, sin datos personales). Debe cubrir la ventana en
	// la que puede llegar un recorded o un discarded duplicado.
	TombstoneDays int
}

// CLIConfig agrupa los parámetros de auditctl, que usa las credenciales de la
// base y del bucket de Audit. No necesita el broker ni el bucket de evidencia.
type CLIConfig struct {
	DatabaseURL    string
	DBQueryTimeout time.Duration
	AuditBucket    string
	S3             S3
}

// Load construye la configuración del servicio a partir del entorno del proceso.
func Load() (*Config, error) {
	r := &reader{}

	cfg := &Config{
		Port:           r.str("PORT", defaultPort),
		DatabaseURL:    r.required("DATABASE_URL"),
		RabbitMQURL:    r.required("RABBITMQ_URL"),
		RecordedQueue:  r.str("AUDIT_RECORDED_QUEUE", defaultRecordedQueue),
		DeliveredQueue: r.str("AUDIT_DELIVERED_QUEUE", defaultDeliveredQueue),
		DiscardedQueue: r.str("AUDIT_DISCARDED_QUEUE", defaultDiscardedQueue),
		AuditBucket:    r.required("AUDIT_BUCKET"),
		EvidenceBucket: r.required("EVIDENCE_BUCKET"),
	}

	cfg.DBQueryTimeout = r.millis("DB_QUERY_TIMEOUT_MS", "1500")
	cfg.RabbitMQPublishTimeout = r.millis("RABBITMQ_PUBLISH_TIMEOUT_MS", "2000")
	cfg.RabbitMQPrefetch = int(r.intRange("RABBITMQ_PREFETCH", "10", 1, maxRabbitMQPrefetch, true))
	cfg.MaxRetries = r.intRange("MAX_RETRIES", "10", 0, math.MaxInt32, true)

	// La retención y el modo de bloqueo son decisiones legales: no tienen valor por
	// defecto, el despliegue las declara.
	cfg.RetentionDays = int(r.intRange("AUDIT_RETENTION_DAYS", "", 1, maxRetentionDays, false))
	cfg.ObjectLockMode = r.required("AUDIT_OBJECT_LOCK_MODE")
	if cfg.ObjectLockMode != "" && cfg.ObjectLockMode != LockModeGovernance && cfg.ObjectLockMode != LockModeCompliance {
		r.fail("AUDIT_OBJECT_LOCK_MODE debe ser %s o %s", LockModeGovernance, LockModeCompliance)
	}

	cfg.S3 = r.s3()

	// Cuánto dura el tombstone también es una decisión del despliegue: sin default.
	cfg.TombstoneDays = int(r.intRange("AUDIT_TOMBSTONE_DAYS", "", 1, maxTombstoneDays, false))

	cfg.SweepInterval = r.duration("AUDIT_SWEEP_INTERVAL", "1h")
	cfg.SweepBatchSize = int(r.intRange("AUDIT_SWEEP_BATCH_SIZE", "500", 1, math.MaxInt32, true))

	if r.err == nil && !distinct(cfg.RecordedQueue, cfg.DeliveredQueue, cfg.DiscardedQueue) {
		r.fail("las colas de recorded, delivered y discarded deben ser distintas")
	}

	if name := forbiddenSecret(os.Environ()); name != "" {
		r.fail("%s no debe definirse: Audit no carga claves privadas ni claves AES de otros servicios", name)
	}

	if r.err != nil {
		return nil, r.err
	}
	return cfg, nil
}

// LoadCLI construye la configuración de auditctl a partir del entorno.
func LoadCLI() (*CLIConfig, error) {
	r := &reader{}

	cfg := &CLIConfig{
		DatabaseURL: r.required("DATABASE_URL"),
		AuditBucket: r.required("AUDIT_BUCKET"),
	}
	cfg.DBQueryTimeout = r.millis("DB_QUERY_TIMEOUT_MS", "1500")
	cfg.S3 = r.s3()

	if r.err != nil {
		return nil, r.err
	}
	return cfg, nil
}

// reader acumula la primera falla de lectura para que Load valide todo el
// entorno con una sola pasada y reporte el primer problema encontrado.
type reader struct {
	err error
}

func (r *reader) fail(format string, args ...any) {
	if r.err == nil {
		r.err = fmt.Errorf("config: "+format, args...)
	}
}

func (r *reader) required(name string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		r.fail("%s es obligatoria", name)
	}
	return value
}

func (r *reader) str(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

// raw devuelve el valor de la variable o fallback si no está definida. Con
// fallback vacío la variable es obligatoria.
func (r *reader) raw(name, fallback string) (string, bool) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		value = fallback
	}
	if value == "" {
		r.fail("%s es obligatoria", name)
		return "", false
	}
	return value, true
}

// intRange lee un entero dentro de [lo, hi]. Si hasDefault es false la variable
// es obligatoria.
func (r *reader) intRange(name, fallback string, lo, hi int64, hasDefault bool) int64 {
	if !hasDefault {
		fallback = ""
	}
	raw, ok := r.raw(name, fallback)
	if !ok {
		return 0
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		r.fail("%s inválido: %v", name, err)
		return 0
	}
	if value < lo || value > hi {
		r.fail("%s debe estar entre %d y %d", name, lo, hi)
		return 0
	}
	return value
}

// millis lee una cantidad positiva de milisegundos.
func (r *reader) millis(name, fallback string) time.Duration {
	ms := r.intRange(name, fallback, 1, math.MaxInt32, true)
	return time.Duration(ms) * time.Millisecond
}

// duration lee una duración en formato de time.ParseDuration (por ejemplo, 1h).
func (r *reader) duration(name, fallback string) time.Duration {
	raw, ok := r.raw(name, fallback)
	if !ok {
		return 0
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		r.fail("%s inválido: %v", name, err)
		return 0
	}
	if value <= 0 {
		r.fail("%s debe ser mayor a cero", name)
		return 0
	}
	return value
}

// s3 lee los parámetros comunes de las llamadas a S3.
func (r *reader) s3() S3 {
	return S3{
		Region:              r.required("S3_REGION"),
		PutTimeout:          r.millis("S3_PUT_TIMEOUT_MS", "5000"),
		GetTimeout:          r.millis("S3_GET_TIMEOUT_MS", "5000"),
		MaxObjectBytes:      r.intRange("S3_MAX_OBJECT_BYTES", "20971520", 1, maxObjectBytesCeiling, true),
		BreakerThreshold:    int(r.intRange("S3_BREAKER_FAILURE_THRESHOLD", "5", 1, math.MaxInt32, true)),
		BreakerWindow:       r.millis("S3_BREAKER_WINDOW_MS", "30000"),
		BreakerOpenDuration: r.millis("S3_BREAKER_OPEN_DURATION_MS", "30000"),
	}
}

func distinct(values ...string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, v := range values {
		if _, dup := seen[v]; dup {
			return false
		}
		seen[v] = struct{}{}
	}
	return true
}

// forbiddenSecret devuelve el nombre de la primera variable prohibida definida
// en environ (con formato NOMBRE=valor), o "" si no hay ninguna. Nunca devuelve
// el valor.
func forbiddenSecret(environ []string) string {
	for _, entry := range environ {
		name, value, _ := strings.Cut(entry, "=")
		if strings.TrimSpace(value) == "" {
			continue
		}
		for _, forbidden := range forbiddenSecretNames {
			if name == forbidden {
				return name
			}
		}
		if strings.HasSuffix(name, forbiddenSecretSuffix) {
			return name
		}
	}
	return ""
}
