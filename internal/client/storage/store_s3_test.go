//go:build s3

package storage

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-audit/internal/domain"
	"github.com/matiasfelau/vinculo-vial-audit/internal/manifest"
)

// Prueba opcional contra el bucket de Audit de desarrollo (AWS real, con Object
// Lock). Se ejecuta con:
//
//	AUDIT_BUCKET=... S3_REGION=... go test -tags s3 -run S3 -v -timeout 10m ./internal/client/storage/
//
// y las credenciales estándar de AWS. Usa GOVERNANCE con una retención corta
// (retentionForTest) para poder borrar al final y no dejar residuos: es el
// equivalente a correr con AUDIT_RETENTION_DAYS bajo. Nunca la ejecute contra un
// bucket de producción (COMPLIANCE).
const (
	retentionForTest = 75 * time.Second
	expiryWait       = 3 * time.Minute
	expiryPoll       = 10 * time.Second
	opTimeout        = 10 * time.Second
	testObjectLimit  = 1 << 20
)

func s3Store(t *testing.T) *Store {
	t.Helper()

	bucket, region := os.Getenv("AUDIT_BUCKET"), os.Getenv("S3_REGION")
	if bucket == "" || region == "" {
		t.Skip("AUDIT_BUCKET y S3_REGION no configuradas: se omite la prueba contra S3")
	}

	store, err := New(context.Background(), Config{
		Region: region, Bucket: bucket, LockMode: "GOVERNANCE",
		PutTimeout: opTimeout, GetTimeout: opTimeout, MaxObjectBytes: testObjectLimit,
		BreakerThreshold: 5, BreakerWindow: time.Minute, BreakerOpenDuration: time.Minute,
	})
	if err != nil {
		t.Fatalf("no se pudo abrir el bucket: %v", err)
	}
	return store
}

func TestS3ObjectLockLegalHoldYBorradoDeTodasLasVersiones(t *testing.T) {
	store := s3Store(t)
	ctx := context.Background()
	id := uuid.NewString()
	photoKey, manifestKey := manifest.PhotoKey(id, "GENERAL", 0), manifest.ManifestKey(id)
	retainUntil := time.Now().Add(retentionForTest).UTC().Truncate(time.Second)

	if err := store.PutLocked(ctx, photoKey, []byte("foto v1"), manifest.ContentTypePhoto, retainUntil); err != nil {
		t.Fatalf("PutLocked: %v", err)
	}
	// Un reintento tras una subida parcial crea una versión nueva.
	if err := store.PutLocked(ctx, photoKey, []byte("foto v2"), manifest.ContentTypePhoto, retainUntil); err != nil {
		t.Fatalf("PutLocked (segunda versión): %v", err)
	}
	if err := store.PutLocked(ctx, manifestKey, []byte("{}"), manifest.ContentTypeManifest, retainUntil); err != nil {
		t.Fatalf("PutLocked (manifiesto): %v", err)
	}

	object, err := store.GetObject(ctx, photoKey)
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	if string(object.Body) != "foto v2" || object.LockMode != "GOVERNANCE" || object.RetainUntil == nil || object.RetainUntil.Before(retainUntil.Add(-time.Second)) {
		t.Fatalf("objeto = %+v, esperaba la versión vigente bloqueada hasta %v", object, retainUntil)
	}

	if err := store.DeleteAllVersions(ctx, manifest.RecordPrefix(id)); !errors.Is(err, domain.ErrRetentionActive) {
		t.Fatalf("con la retención vigente esperaba ErrRetentionActive, obtuvo %v", err)
	}

	changed, err := store.SetLegalHold(ctx, manifest.RecordPrefix(id), true)
	if err != nil || changed != 3 {
		t.Fatalf("SetLegalHold(on) modificó %d versiones (err %v), esperaba 3", changed, err)
	}
	if held, _ := store.GetObject(ctx, manifestKey); !held.LegalHold {
		t.Error("el manifiesto debía quedar con legal hold")
	}

	if _, err := store.SetLegalHold(ctx, manifest.RecordPrefix(id), false); err != nil {
		t.Fatalf("SetLegalHold(off): %v", err)
	}

	// Pasada la retención, el sweeper puede borrar todas las versiones.
	deadline := time.Now().Add(expiryWait)
	for {
		err := store.DeleteAllVersions(ctx, manifest.RecordPrefix(id))
		if err == nil {
			break
		}
		if !errors.Is(err, domain.ErrRetentionActive) || time.Now().After(deadline) {
			t.Fatalf("DeleteAllVersions: %v", err)
		}
		time.Sleep(expiryPoll)
	}

	if _, err := store.GetObject(ctx, photoKey); !errors.Is(err, domain.ErrObjectNotFound) {
		t.Errorf("tras el borrado esperaba ErrObjectNotFound, obtuvo %v", err)
	}
}
