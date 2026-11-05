//go:build smoke

// Package smoke verifica, contra el stack real y sin Alert, que Audit consume las
// tres colas y archiva la evidencia con Object Lock. Se ejecuta con el servicio
// corriendo (docker compose up) y:
//
//	go test -tags smoke -v -timeout 10m ./internal/smoke/
//
// Variables (las del servicio, más el acceso a su base):
//
//	RABBITMQ_URL, RABBITMQ_EXCHANGE (default vvi.topic.exchange)
//	EVIDENCE_BUCKET, AUDIT_BUCKET, S3_REGION y credenciales de AWS
//	AUDIT_RETENTION_DAYS: el mismo valor que usa el servicio
//	SMOKE_DATABASE_URL: acceso a audit-db desde esta máquina
//
// Requiere AUDIT_OBJECT_LOCK_MODE=GOVERNANCE en el servicio: nunca la corra contra
// un entorno con COMPLIANCE. Para no dejar residuos, el registro de prueba se crea
// con una alerta "antigua" cuyo destroy_at cae pocos minutos después; el sweeper lo
// destruye cuando vence.
package smoke

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/matiasfelau/vinculo-vial-audit/internal/manifest"
	"github.com/matiasfelau/vinculo-vial-audit/internal/repository/postgres"
)

const (
	defaultExchange = "vvi.topic.exchange"
	waitTimeout     = 90 * time.Second
	pollInterval    = time.Second
	// destroyIn es cuánto falta, desde ahora, para el destroy_at del registro de prueba.
	destroyIn   = 3 * time.Minute
	hoursPerDay = 24
)

type env struct {
	rabbitURL, exchange              string
	evidenceBucket, auditBucket      string
	region, databaseURL              string
	retentionDays                    int
	s3                               *s3.Client
	channel                          *amqp.Channel
	statusOf                         func(alertID uuid.UUID) (string, bool)
	createdAt                        time.Time
	expectedDestroyAt                time.Time
	cryptogramDNI, cryptogramPatente string
}

func required(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Skipf("%s no configurada: se omite el smoke", name)
	}
	return value
}

func setup(t *testing.T) *env {
	t.Helper()

	days, err := strconv.Atoi(required(t, "AUDIT_RETENTION_DAYS"))
	if err != nil || days < 1 {
		t.Fatalf("AUDIT_RETENTION_DAYS inválida: %v", err)
	}
	e := &env{
		rabbitURL:      required(t, "RABBITMQ_URL"),
		exchange:       os.Getenv("RABBITMQ_EXCHANGE"),
		evidenceBucket: required(t, "EVIDENCE_BUCKET"),
		auditBucket:    required(t, "AUDIT_BUCKET"),
		region:         required(t, "S3_REGION"),
		databaseURL:    required(t, "SMOKE_DATABASE_URL"),
		retentionDays:  days,
		// Criptogramas de relleno: Audit los guarda tal como llegan, sin descifrarlos.
		cryptogramDNI:     "c21va2UtZG5pLWNyaXB0b2dyYW1h",
		cryptogramPatente: "c21va2UtcGF0ZW50ZS1jcmlwdG9ncmFtYQ==",
	}
	if e.exchange == "" {
		e.exchange = defaultExchange
	}

	// created_at tal que destroy_at = ahora + destroyIn.
	e.expectedDestroyAt = time.Now().UTC().Add(destroyIn).Truncate(time.Second)
	e.createdAt = e.expectedDestroyAt.Add(-time.Duration(days) * hoursPerDay * time.Hour)

	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion(e.region))
	if err != nil {
		t.Fatalf("configuración de AWS: %v", err)
	}
	e.s3 = s3.NewFromConfig(awsCfg)

	conn, err := amqp.Dial(e.rabbitURL)
	if err != nil {
		t.Fatalf("no se pudo conectar al broker: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	e.channel, err = conn.Channel()
	if err != nil {
		t.Fatalf("canal: %v", err)
	}

	db, err := postgres.Connect(e.databaseURL)
	if err != nil {
		t.Fatalf("no se pudo conectar a audit-db: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	e.statusOf = func(alertID uuid.UUID) (string, bool) {
		var status string
		result := db.Raw("SELECT status FROM audit_records WHERE alert_id = ?", alertID).Scan(&status)
		return status, result.Error == nil && result.RowsAffected == 1
	}
	return e
}

func (e *env) publish(t *testing.T, eventType string, payload map[string]any) {
	t.Helper()

	rawPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{
		"eventId": uuid.NewString(), "eventType": eventType, "timestamp": time.Now().UTC().Format(time.RFC3339),
		"producer": "smoke", "actor": nil, "payload": json.RawMessage(rawPayload),
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.channel.PublishWithContext(ctx, e.exchange, eventType, true, false, amqp.Publishing{
		ContentType: "application/json", DeliveryMode: amqp.Persistent, Body: body,
	}); err != nil {
		t.Fatalf("no se pudo publicar %s: %v", eventType, err)
	}
}

func (e *env) recordedPayload(alertID uuid.UUID) map[string]any {
	return map[string]any{
		"alert_id": alertID.String(), "alert_type": "CRASHED", "created_at": e.createdAt.Format(time.RFC3339),
		"dni_enc_audit": e.cryptogramDNI, "pat_enc_audit": e.cryptogramPatente, "audit_key_id": "smoke",
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(pollInterval)
	}
	t.Fatalf("tiempo agotado esperando: %s", what)
}

func sha(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func TestSmokeRecordedDeliveredYDiscarded(t *testing.T) {
	e := setup(t)
	ctx := context.Background()

	// --- recorded + delivered: la foto y el manifiesto quedan bloqueados ---
	alertID := uuid.New()
	photo := []byte("foto-redactada-de-prueba-smoke")
	evidenceKey := "alerts/" + alertID.String() + "/redacted/GENERAL-0.jpg"
	if _, err := e.s3.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(e.evidenceBucket), Key: aws.String(evidenceKey), Body: bytes.NewReader(photo),
	}); err != nil {
		t.Fatalf("no se pudo subir la foto de prueba al bucket de evidencia: %v", err)
	}

	e.publish(t, "audit.alert.recorded", e.recordedPayload(alertID))
	waitFor(t, "registro RECORDED", func() bool { status, ok := e.statusOf(alertID); return ok && status == "RECORDED" })

	e.publish(t, "audit.alert.delivered", map[string]any{
		"alert_id": alertID.String(), "delivered_at": time.Now().UTC().Format(time.RFC3339), "bucket": e.evidenceBucket,
		"evidence": []map[string]any{{"role": "GENERAL", "index": 0, "key": evidenceKey, "sha256": sha(photo)}},
	})
	waitFor(t, "registro DELIVERED", func() bool { status, _ := e.statusOf(alertID); return status == "DELIVERED" })

	for _, key := range []string{manifest.PhotoKey(alertID.String(), "GENERAL", 0), manifest.ManifestKey(alertID.String())} {
		out, err := e.s3.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(e.auditBucket), Key: aws.String(key)})
		if err != nil {
			t.Fatalf("no se pudo leer %s del bucket de Audit: %v", key, err)
		}
		_ = out.Body.Close()
		if out.ObjectLockMode != types.ObjectLockModeGovernance {
			t.Errorf("%s: modo de bloqueo = %q, esperaba GOVERNANCE", key, out.ObjectLockMode)
		}
		if out.ObjectLockRetainUntilDate == nil || out.ObjectLockRetainUntilDate.Before(e.expectedDestroyAt.Add(-2*time.Second)) {
			t.Errorf("%s: retención hasta %v, esperaba al menos destroy_at (%v)", key, out.ObjectLockRetainUntilDate, e.expectedDestroyAt)
		}
	}

	// --- recorded + discarded sobre otro registro: se borra ---
	discardedID := uuid.New()
	e.publish(t, "audit.alert.recorded", e.recordedPayload(discardedID))
	waitFor(t, "segundo registro RECORDED", func() bool { _, ok := e.statusOf(discardedID); return ok })
	e.publish(t, "audit.alert.discarded", map[string]any{"alert_id": discardedID.String(), "reason": "REJECTED"})
	waitFor(t, "registro descartado borrado", func() bool { _, ok := e.statusOf(discardedID); return !ok })

	// Duplicados posteriores al descarte (entrega al menos una vez): el tombstone evita
	// que un recorded recree el registro y que un discarded termine en la DLQ.
	e.publish(t, "audit.alert.discarded", map[string]any{"alert_id": discardedID.String(), "reason": "REJECTED"})
	e.publish(t, "audit.alert.recorded", e.recordedPayload(discardedID))
	time.Sleep(5 * time.Second)
	if _, ok := e.statusOf(discardedID); ok {
		t.Error("un recorded duplicado tras el descarte no debe recrear el registro")
	}

	// El registro entregado no se ve afectado por un discarded.
	e.publish(t, "audit.alert.discarded", map[string]any{"alert_id": alertID.String(), "reason": "UNCLAIMED"})
	time.Sleep(5 * time.Second)
	if status, ok := e.statusOf(alertID); !ok || status != "DELIVERED" {
		t.Errorf("un discarded sobre un registro entregado no debe borrarlo (existe=%v, status=%q)", ok, status)
	}
}
