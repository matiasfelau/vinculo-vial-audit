package config

import (
	"strings"
	"testing"
	"time"
)

// requiredEnv son las variables sin valor por defecto.
func requiredEnv() map[string]string {
	return map[string]string{
		"DATABASE_URL":           "postgres://audit:audit@localhost:5432/audit?sslmode=disable",
		"RABBITMQ_URL":           "amqp://guest:guest@localhost:5672/",
		"AUDIT_BUCKET":           "vinculo-vial-audit-dev-abc",
		"EVIDENCE_BUCKET":        "vinculo-vial-evidence-dev",
		"S3_REGION":              "us-east-1",
		"AUDIT_RETENTION_DAYS":   "1095",
		"AUDIT_OBJECT_LOCK_MODE": "GOVERNANCE",
	}
}

func setEnv(t *testing.T, overrides map[string]string) {
	t.Helper()

	// Limpia las variables opcionales para que el entorno del equipo no contamine.
	for _, name := range []string{
		"PORT", "DB_QUERY_TIMEOUT_MS", "RABBITMQ_PUBLISH_TIMEOUT_MS", "RABBITMQ_PREFETCH", "MAX_RETRIES",
		"AUDIT_RECORDED_QUEUE", "AUDIT_DELIVERED_QUEUE", "AUDIT_DISCARDED_QUEUE", "AUDIT_SWEEP_INTERVAL",
		"AUDIT_SWEEP_BATCH_SIZE", "S3_PUT_TIMEOUT_MS", "S3_GET_TIMEOUT_MS", "S3_MAX_OBJECT_BYTES",
		"S3_BREAKER_FAILURE_THRESHOLD", "S3_BREAKER_WINDOW_MS", "S3_BREAKER_OPEN_DURATION_MS",
		"AES_KEY", "PAT_AES_KEY", "AUDIT_PRIVATE_KEY",
	} {
		t.Setenv(name, "")
	}
	for name, value := range requiredEnv() {
		t.Setenv(name, value)
	}
	for name, value := range overrides {
		t.Setenv(name, value)
	}
}

func TestLoadConValoresPorDefectoDelContrato(t *testing.T) {
	setEnv(t, nil)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	if cfg.Port != "8080" {
		t.Errorf("Port = %q", cfg.Port)
	}
	if cfg.RetentionDays != 1095 {
		t.Errorf("RetentionDays = %d", cfg.RetentionDays)
	}
	if cfg.MaxRetries != 10 {
		t.Errorf("MaxRetries = %d, el contrato fija 10", cfg.MaxRetries)
	}
	if cfg.SweepInterval != time.Hour || cfg.SweepBatchSize != 500 {
		t.Errorf("sweep = %v / %d, el contrato fija 1h / 500", cfg.SweepInterval, cfg.SweepBatchSize)
	}
	if cfg.RecordedQueue != "audit.alert-recorded.q" || cfg.DeliveredQueue != "audit.alert-delivered.q" || cfg.DiscardedQueue != "audit.alert-discarded.q" {
		t.Errorf("colas = %q %q %q", cfg.RecordedQueue, cfg.DeliveredQueue, cfg.DiscardedQueue)
	}
	if cfg.RabbitMQPrefetch != 10 {
		t.Errorf("RabbitMQPrefetch = %d", cfg.RabbitMQPrefetch)
	}
	if cfg.ObjectLockMode != "GOVERNANCE" || cfg.AuditBucket == "" || cfg.EvidenceBucket == "" {
		t.Errorf("config de buckets incompleta: %+v", cfg)
	}
}

func TestLoadSinVariableObligatoriaFalla(t *testing.T) {
	for name := range requiredEnv() {
		t.Run(name, func(t *testing.T) {
			setEnv(t, map[string]string{name: ""})

			cfg, err := Load()

			if err == nil {
				t.Fatalf("esperaba error sin %s, obtuvo %+v", name, cfg)
			}
			if !strings.Contains(err.Error(), name) {
				t.Errorf("el error %q no nombra a %s", err, name)
			}
		})
	}
}

func TestLoadConValoresInvalidosFalla(t *testing.T) {
	casos := map[string]map[string]string{
		"retención cero":                  {"AUDIT_RETENTION_DAYS": "0"},
		"retención negativa":              {"AUDIT_RETENTION_DAYS": "-5"},
		"retención no numérica":           {"AUDIT_RETENTION_DAYS": "tres años"},
		"retención desmedida":             {"AUDIT_RETENTION_DAYS": "999999"},
		"modo de bloqueo desconocido":     {"AUDIT_OBJECT_LOCK_MODE": "PERMISSIVE"},
		"modo de bloqueo en minúsculas":   {"AUDIT_OBJECT_LOCK_MODE": "governance"},
		"prefetch cero":                   {"RABBITMQ_PREFETCH": "0"},
		"prefetch truncable":              {"RABBITMQ_PREFETCH": "70000"},
		"max retries negativo":            {"MAX_RETRIES": "-1"},
		"intervalo de sweep inválido":     {"AUDIT_SWEEP_INTERVAL": "cada tanto"},
		"intervalo de sweep cero":         {"AUDIT_SWEEP_INTERVAL": "0s"},
		"batch de sweep cero":             {"AUDIT_SWEEP_BATCH_SIZE": "0"},
		"timeout S3 cero":                 {"S3_PUT_TIMEOUT_MS": "0"},
		"umbral del breaker cero":         {"S3_BREAKER_FAILURE_THRESHOLD": "0"},
		"tope de objeto cero":             {"S3_MAX_OBJECT_BYTES": "0"},
		"colas repetidas":                 {"AUDIT_DELIVERED_QUEUE": "audit.alert-recorded.q"},
		"timeout de consulta no numérico": {"DB_QUERY_TIMEOUT_MS": "rápido"},
	}

	for nombre, overrides := range casos {
		t.Run(nombre, func(t *testing.T) {
			setEnv(t, overrides)

			if _, err := Load(); err == nil {
				t.Fatal("esperaba error de validación")
			}
		})
	}
}

func TestLoadRechazaClavesPrivadasYAESDeOtrosServicios(t *testing.T) {
	for _, name := range []string{"AES_KEY", "PAT_AES_KEY", "AUDIT_PRIVATE_KEY", "VEHICLE_HPKE_PRIVATE_KEY"} {
		t.Run(name, func(t *testing.T) {
			setEnv(t, map[string]string{name: "c2VjcmV0by1xdWUtbm8tZGViZS1lc3Rhci1hY2E="})

			_, err := Load()

			if err == nil {
				t.Fatalf("Audit no debe arrancar con %s definida", name)
			}
			if !strings.Contains(err.Error(), name) {
				t.Errorf("el error debe nombrar la variable: %v", err)
			}
			if strings.Contains(err.Error(), "c2VjcmV0") {
				t.Error("el error no debe reflejar el valor del secreto")
			}
		})
	}
}

func TestForbiddenSecretIgnoraVariablesVaciasYNoRelacionadas(t *testing.T) {
	environ := []string{"AES_KEY=", "PATH=/usr/bin", "AUDIT_PUBLIC_KEY=abc", "DATABASE_URL=x"}

	if name := forbiddenSecret(environ); name != "" {
		t.Errorf("forbiddenSecret = %q, esperaba vacío", name)
	}
}

func TestLoadCLINoExigeBrokerNiBucketDeEvidencia(t *testing.T) {
	setEnv(t, map[string]string{"RABBITMQ_URL": "", "EVIDENCE_BUCKET": "", "AUDIT_RETENTION_DAYS": ""})

	cfg, err := LoadCLI()

	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if cfg.DatabaseURL == "" || cfg.AuditBucket == "" || cfg.S3.Region == "" {
		t.Errorf("config incompleta: %+v", cfg)
	}
}

func TestLoadCLISinBaseFalla(t *testing.T) {
	setEnv(t, map[string]string{"DATABASE_URL": ""})

	if _, err := LoadCLI(); err == nil {
		t.Fatal("esperaba error sin DATABASE_URL")
	}
}
