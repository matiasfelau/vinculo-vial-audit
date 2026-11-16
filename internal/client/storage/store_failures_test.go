package storage

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/matiasfelau/vinculo-vial-audit/internal/domain"
)

func TestGetDevuelveElCuerpoYTraduceElObjetoInexistente(t *testing.T) {
	t.Run("objeto existente", func(t *testing.T) {
		store := newStore(&fakeS3{getOut: getOutput("hola", 4)}, testConfig())

		body, err := store.Get(context.Background(), "k")

		if err != nil || string(body) != "hola" {
			t.Fatalf("Get = %q, %v", body, err)
		}
	})
	t.Run("objeto inexistente", func(t *testing.T) {
		store := newStore(&fakeS3{getErr: httpError(http.StatusNotFound, "NoSuchKey")}, testConfig())

		body, err := store.Get(context.Background(), "k")

		if !errors.Is(err, domain.ErrObjectNotFound) || body != nil {
			t.Fatalf("Get = %q, %v, esperaba ErrObjectNotFound sin cuerpo", body, err)
		}
	})
}

// failingBody falla a mitad de la lectura, como una conexión cortada.
type failingBody struct{ leido bool }

func (f *failingBody) Read(p []byte) (int, error) {
	if f.leido {
		return 0, errors.New("conexión cortada")
	}
	f.leido = true
	return copy(p, "par"), nil
}

func (f *failingBody) Close() error { return nil }

func TestGetObjectConUnCuerpoCortadoEsTransitorioYNoDevuelveDatosParciales(t *testing.T) {
	out := getOutput("", 10)
	out.Body = &failingBody{}
	store := newStore(&fakeS3{getOut: out}, testConfig())

	object, err := store.GetObject(context.Background(), "k")

	if !errors.Is(err, domain.ErrStorageUnavailable) {
		t.Fatalf("esperaba ErrStorageUnavailable (se reintenta), obtuvo %v", err)
	}
	if len(object.Body) != 0 {
		t.Errorf("devolvió %d bytes de un objeto leído a medias", len(object.Body))
	}
}

func TestDeleteAllVersionsConUnBorradoCaidoNoEsRetencionYNoSigueBorrando(t *testing.T) {
	api := &fakeS3{
		listPage: []*s3.ListObjectVersionsOutput{{Versions: []types.ObjectVersion{version("records/a/m.json", "v1"), version("records/a/f.jpg", "v2")}}},
		deleteFn: func(*s3.DeleteObjectInput) error { return httpError(http.StatusInternalServerError, "InternalError") },
	}

	err := newStore(api, testConfig()).DeleteAllVersions(context.Background(), "records/a/")

	if !errors.Is(err, domain.ErrStorageUnavailable) {
		t.Fatalf("esperaba ErrStorageUnavailable, obtuvo %v", err)
	}
	if errors.Is(err, domain.ErrRetentionActive) {
		t.Error("una falla de S3 no es retención vigente: el sweeper la contaría como retenida")
	}
	if len(api.deleteIn) != 1 {
		t.Errorf("hubo %d intentos de borrado, esperaba 1 (frena al primer error)", len(api.deleteIn))
	}
}

func TestSetLegalHoldInformaCuantasVersionesModificoAntesDeFallar(t *testing.T) {
	t.Run("falla el listado", func(t *testing.T) {
		api := &fakeS3{listErr: httpError(http.StatusServiceUnavailable, "SlowDown")}

		changed, err := newStore(api, testConfig()).SetLegalHold(context.Background(), "records/a/", true)

		if !errors.Is(err, domain.ErrStorageUnavailable) || changed != 0 {
			t.Fatalf("SetLegalHold = %d, %v", changed, err)
		}
		if len(api.holdIn) != 0 {
			t.Error("sin listado no se debe aplicar ningún hold")
		}
	})

	t.Run("falla una versión a mitad de camino", func(t *testing.T) {
		api := &fakeS3{
			listPage: []*s3.ListObjectVersionsOutput{{Versions: []types.ObjectVersion{version("records/a/m.json", "v1")}}},
			holdErr:  httpError(http.StatusServiceUnavailable, "SlowDown"),
		}

		changed, err := newStore(api, testConfig()).SetLegalHold(context.Background(), "records/a/", true)

		if !errors.Is(err, domain.ErrStorageUnavailable) || changed != 0 {
			t.Fatalf("SetLegalHold = %d, %v, esperaba 0 modificadas y ErrStorageUnavailable", changed, err)
		}
	})
}

// Que el llamador desista (por ejemplo, un apagado) no es una falla de S3: no
// debe abrir el circuito.
func TestLasCancelacionesDelLlamadorNoAbrenElCircuito(t *testing.T) {
	api := &fakeS3{getErr: context.Canceled}
	store := newStore(api, testConfig())

	for i := 0; i < 5; i++ { // el umbral de testConfig es 2
		_, err := store.Get(context.Background(), "k")
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("esperaba context.Canceled, obtuvo %v", err)
		}
	}

	if !store.Healthy() {
		t.Error("las cancelaciones del llamador abrieron el circuito")
	}
	if api.calls != 5 {
		t.Errorf("llamadas a S3 = %d, esperaba 5 (el circuito debía seguir cerrado)", api.calls)
	}
}

func TestPutLockedNoEnviaElCuerpoAlLogDeLaFalla(t *testing.T) {
	logs := captureLogs(t)
	api := &fakeS3{putErr: httpError(http.StatusInternalServerError, "InternalError")}

	err := newStore(api, testConfig()).PutLocked(context.Background(), "records/a/GENERAL-0.jpg", []byte("CONTENIDO-SECRETO"), "image/jpeg", time.Now())

	if !errors.Is(err, domain.ErrStorageUnavailable) {
		t.Fatalf("esperaba ErrStorageUnavailable, obtuvo %v", err)
	}
	if strings.Contains(logs.String(), "CONTENIDO-SECRETO") || strings.Contains(err.Error(), "CONTENIDO-SECRETO") {
		t.Error("el contenido del objeto llegó a un log o a un error")
	}
}
