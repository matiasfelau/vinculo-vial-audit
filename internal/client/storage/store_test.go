package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/matiasfelau/vinculo-vial-audit/internal/domain"
)

type fakeS3 struct {
	putIn    []*s3.PutObjectInput
	putBody  [][]byte
	putErr   error
	getOut   *s3.GetObjectOutput
	getErr   error
	listPage []*s3.ListObjectVersionsOutput
	listErr  error
	listIn   []*s3.ListObjectVersionsInput
	deleteIn []*s3.DeleteObjectInput
	deleteFn func(in *s3.DeleteObjectInput) error
	holdIn   []*s3.PutObjectLegalHoldInput
	holdErr  error

	calls int
}

func (f *fakeS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	f.calls++
	f.putIn = append(f.putIn, in)
	body, _ := io.ReadAll(in.Body)
	f.putBody = append(f.putBody, body)
	return &s3.PutObjectOutput{}, f.putErr
}

func (f *fakeS3) GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	f.calls++
	return f.getOut, f.getErr
}

func (f *fakeS3) ListObjectVersions(_ context.Context, in *s3.ListObjectVersionsInput, _ ...func(*s3.Options)) (*s3.ListObjectVersionsOutput, error) {
	f.calls++
	f.listIn = append(f.listIn, in)
	if f.listErr != nil {
		return nil, f.listErr
	}
	page := f.listPage[0]
	f.listPage = f.listPage[1:]
	return page, nil
}

func (f *fakeS3) DeleteObject(_ context.Context, in *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	f.calls++
	f.deleteIn = append(f.deleteIn, in)
	if f.deleteFn != nil {
		return &s3.DeleteObjectOutput{}, f.deleteFn(in)
	}
	return &s3.DeleteObjectOutput{}, nil
}

func (f *fakeS3) PutObjectLegalHold(_ context.Context, in *s3.PutObjectLegalHoldInput, _ ...func(*s3.Options)) (*s3.PutObjectLegalHoldOutput, error) {
	f.calls++
	f.holdIn = append(f.holdIn, in)
	return &s3.PutObjectLegalHoldOutput{}, f.holdErr
}

func testConfig() Config {
	return Config{
		Bucket:              "vinculo-vial-audit-test",
		LockMode:            "GOVERNANCE",
		PutTimeout:          time.Second,
		GetTimeout:          time.Second,
		MaxObjectBytes:      16,
		BreakerThreshold:    2,
		BreakerWindow:       time.Minute,
		BreakerOpenDuration: time.Minute,
	}
}

// httpError simula una respuesta HTTP de error de S3 con la misma forma que el
// SDK: OperationError → ResponseError de AWS → ResponseError HTTP → APIError.
func httpError(status int, code string) error {
	return &smithy.OperationError{
		ServiceID:     "S3",
		OperationName: "Op",
		Err: &awshttp.ResponseError{
			ResponseError: &smithyhttp.ResponseError{
				Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status}},
				Err:      &smithy.GenericAPIError{Code: code, Message: code},
			},
		},
	}
}

func TestPutLockedEnviaModoYRetencion(t *testing.T) {
	api := &fakeS3{}
	store := newStore(api, testConfig())
	retainUntil := time.Date(2029, 11, 4, 12, 0, 0, 0, time.UTC)

	err := store.PutLocked(context.Background(), "records/a/manifest.json", []byte("{}"), "application/json", retainUntil)

	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	in := api.putIn[0]
	if aws.ToString(in.Bucket) != "vinculo-vial-audit-test" || aws.ToString(in.Key) != "records/a/manifest.json" {
		t.Errorf("destino = %s/%s", aws.ToString(in.Bucket), aws.ToString(in.Key))
	}
	if in.ObjectLockMode != types.ObjectLockModeGovernance {
		t.Errorf("modo = %s, esperaba GOVERNANCE", in.ObjectLockMode)
	}
	if got := aws.ToTime(in.ObjectLockRetainUntilDate); !got.Equal(retainUntil) {
		t.Errorf("retención hasta %v, esperaba %v", got, retainUntil)
	}
	if in.ChecksumAlgorithm != types.ChecksumAlgorithmSha256 {
		t.Errorf("checksum = %s, esperaba SHA256", in.ChecksumAlgorithm)
	}
	if aws.ToString(in.ContentType) != "application/json" || !bytes.Equal(api.putBody[0], []byte("{}")) {
		t.Error("content-type o cuerpo incorrectos")
	}
	if in.IfNoneMatch != nil {
		t.Error("la escritura no debe ser condicional: un reintento crea una versión nueva")
	}
}

func TestPutLockedEnModoCompliance(t *testing.T) {
	api := &fakeS3{}
	cfg := testConfig()
	cfg.LockMode = "COMPLIANCE"

	if err := newStore(api, cfg).PutLocked(context.Background(), "k", []byte("x"), "text/plain", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	if api.putIn[0].ObjectLockMode != types.ObjectLockModeCompliance {
		t.Errorf("modo = %s, esperaba COMPLIANCE", api.putIn[0].ObjectLockMode)
	}
}

func getOutput(body string, length int64) *s3.GetObjectOutput {
	return &s3.GetObjectOutput{
		Body:                      io.NopCloser(strings.NewReader(body)),
		ContentLength:             aws.Int64(length),
		ObjectLockMode:            types.ObjectLockModeGovernance,
		ObjectLockRetainUntilDate: aws.Time(time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC)),
		ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatusOn,
	}
}

func TestGetObjectDevuelveCuerpoYRetencion(t *testing.T) {
	api := &fakeS3{getOut: getOutput("hola", 4)}

	object, err := newStore(api, testConfig()).GetObject(context.Background(), "k")

	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if string(object.Body) != "hola" || object.LockMode != "GOVERNANCE" || !object.LegalHold {
		t.Errorf("objeto = %+v", object)
	}
	if object.RetainUntil == nil || object.RetainUntil.Year() != 2029 {
		t.Errorf("RetainUntil = %v", object.RetainUntil)
	}
}

func TestGetRechazaObjetosMasGrandesQueElTope(t *testing.T) {
	casos := map[string]*s3.GetObjectOutput{
		"declarado en Content-Length": getOutput("x", 17),
		"cuerpo real mayor al tope":   getOutput(strings.Repeat("a", 17), 1),
	}
	for nombre, out := range casos {
		t.Run(nombre, func(t *testing.T) {
			api := &fakeS3{getOut: out}

			_, err := newStore(api, testConfig()).Get(context.Background(), "k")

			if !errors.Is(err, domain.ErrObjectTooLarge) {
				t.Fatalf("esperaba ErrObjectTooLarge, obtuvo %v", err)
			}
		})
	}
}

func TestClassifyTraduceLosErroresDeS3(t *testing.T) {
	casos := []struct {
		nombre string
		err    error
		want   error
	}{
		{"nil", nil, nil},
		{"NoSuchKey tipado", &types.NoSuchKey{}, domain.ErrObjectNotFound},
		{"404", httpError(http.StatusNotFound, "Other"), domain.ErrObjectNotFound},
		{"NotFound por código", httpError(http.StatusBadRequest, "NotFound"), domain.ErrObjectNotFound},
		{"403 AccessDenied", httpError(http.StatusForbidden, "AccessDenied"), domain.ErrStorageRejected},
		{"400", httpError(http.StatusBadRequest, "InvalidRequest"), domain.ErrStorageRejected},
		{"500", httpError(http.StatusInternalServerError, "InternalError"), domain.ErrStorageUnavailable},
		{"503", httpError(http.StatusServiceUnavailable, "SlowDown"), domain.ErrStorageUnavailable},
		{"429", httpError(http.StatusTooManyRequests, "Throttling"), domain.ErrStorageUnavailable},
		{"timeout", context.DeadlineExceeded, domain.ErrStorageUnavailable},
		{"conexión", errors.New("dial tcp: connection refused"), domain.ErrStorageUnavailable},
	}

	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			got := classify(c.err)

			if c.want == nil {
				if got != nil {
					t.Fatalf("esperaba nil, obtuvo %v", got)
				}
				return
			}
			if !errors.Is(got, c.want) {
				t.Fatalf("classify = %v, esperaba %v", got, c.want)
			}
		})
	}

	if got := classify(context.Canceled); !errors.Is(got, context.Canceled) {
		t.Errorf("la cancelación debe conservarse, obtuvo %v", got)
	}
}

func TestElCircuitoSeAbreConFallasYRechazaSinAlcanzarS3(t *testing.T) {
	api := &fakeS3{putErr: httpError(http.StatusServiceUnavailable, "SlowDown")}
	store := newStore(api, testConfig())
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		if err := store.PutLocked(ctx, "k", []byte("x"), "t", time.Now()); !errors.Is(err, domain.ErrStorageUnavailable) {
			t.Fatalf("llamada %d: esperaba ErrStorageUnavailable, obtuvo %v", i, err)
		}
	}
	if store.Healthy() {
		t.Fatal("tras alcanzar el umbral el circuito debe estar abierto")
	}

	callsBefore := api.calls
	err := store.PutLocked(ctx, "k", []byte("x"), "t", time.Now())

	if !errors.Is(err, domain.ErrStorageUnavailable) {
		t.Fatalf("con el circuito abierto esperaba ErrStorageUnavailable, obtuvo %v", err)
	}
	if api.calls != callsBefore {
		t.Error("con el circuito abierto la llamada no debe alcanzar la red")
	}
}

func TestLos4xxNoAbrenElCircuito(t *testing.T) {
	api := &fakeS3{getErr: httpError(http.StatusForbidden, "AccessDenied")}
	store := newStore(api, testConfig())

	for i := 0; i < 10; i++ {
		_, _ = store.Get(context.Background(), "k")
	}

	if !store.Healthy() {
		t.Fatal("un 403 refleja un error del invocante: no computa para el breaker")
	}
}

func TestLosCircuitosDeCadaBucketSonIndependientes(t *testing.T) {
	failing := newStore(&fakeS3{putErr: httpError(http.StatusInternalServerError, "InternalError")}, testConfig())
	healthy := newStore(&fakeS3{}, testConfig())

	for i := 0; i < 2; i++ {
		_ = failing.PutLocked(context.Background(), "k", []byte("x"), "t", time.Now())
	}

	if failing.Healthy() {
		t.Fatal("el bucket degradado debía abrir su circuito")
	}
	if !healthy.Healthy() {
		t.Fatal("la degradación de un bucket no debe abrir el circuito del otro")
	}
	if err := healthy.PutLocked(context.Background(), "k", []byte("x"), "t", time.Now()); err != nil {
		t.Errorf("el bucket sano debe seguir operando: %v", err)
	}
}

func TestLaExpiracionDelTimeoutEsIndisponibilidad(t *testing.T) {
	cfg := testConfig()
	cfg.GetTimeout = 20 * time.Millisecond
	api := &blockingS3{}

	_, err := newStore(api, cfg).Get(context.Background(), "k")

	if !errors.Is(err, domain.ErrStorageUnavailable) {
		t.Fatalf("esperaba ErrStorageUnavailable por timeout, obtuvo %v", err)
	}
}

// blockingS3 espera a que venza el contexto de la llamada.
type blockingS3 struct{ fakeS3 }

func (b *blockingS3) GetObject(ctx context.Context, _ *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func version(key, id string) types.ObjectVersion {
	return types.ObjectVersion{Key: aws.String(key), VersionId: aws.String(id)}
}

func TestDeleteAllVersionsPaginaYBorraVersionesYMarcas(t *testing.T) {
	api := &fakeS3{listPage: []*s3.ListObjectVersionsOutput{
		{
			Versions:            []types.ObjectVersion{version("records/a/manifest.json", "v1"), version("records/a/GENERAL-0.jpg", "v2")},
			IsTruncated:         aws.Bool(true),
			NextKeyMarker:       aws.String("records/a/GENERAL-0.jpg"),
			NextVersionIdMarker: aws.String("v2"),
		},
		{
			Versions:      []types.ObjectVersion{version("records/a/GENERAL-0.jpg", "v3")},
			DeleteMarkers: []types.DeleteMarkerEntry{{Key: aws.String("records/a/old.jpg"), VersionId: aws.String("m1")}},
			IsTruncated:   aws.Bool(false),
		},
	}}

	err := newStore(api, testConfig()).DeleteAllVersions(context.Background(), "records/a/")

	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if len(api.deleteIn) != 4 {
		t.Fatalf("se borraron %d versiones, esperaba 4 (3 versiones y 1 marca)", len(api.deleteIn))
	}
	for _, in := range api.deleteIn {
		if in.VersionId == nil {
			t.Error("todo borrado debe indicar la versión: sin ella solo se crearía una marca de borrado")
		}
	}
	if aws.ToString(api.listIn[0].Prefix) != "records/a/" {
		t.Errorf("prefijo = %q", aws.ToString(api.listIn[0].Prefix))
	}
	if aws.ToString(api.listIn[1].KeyMarker) != "records/a/GENERAL-0.jpg" || aws.ToString(api.listIn[1].VersionIdMarker) != "v2" {
		t.Error("la segunda página no usó los marcadores de la primera")
	}
}

func TestDeleteAllVersionsConRetencionVigenteDevuelveErrRetentionActive(t *testing.T) {
	api := &fakeS3{
		listPage: []*s3.ListObjectVersionsOutput{{Versions: []types.ObjectVersion{version("records/a/m.json", "v1"), version("records/a/f.jpg", "v2")}}},
		deleteFn: func(*s3.DeleteObjectInput) error { return httpError(http.StatusForbidden, "AccessDenied") },
	}
	store := newStore(api, testConfig())

	err := store.DeleteAllVersions(context.Background(), "records/a/")

	if !errors.Is(err, domain.ErrRetentionActive) {
		t.Fatalf("esperaba ErrRetentionActive, obtuvo %v", err)
	}
	if len(api.deleteIn) != 1 {
		t.Errorf("tras el primer rechazo no debe seguir borrando (%d intentos)", len(api.deleteIn))
	}
	if !store.Healthy() {
		t.Error("la retención vigente no es una falla del destino")
	}
}

func TestDeleteAllVersionsConS3CaidoDevuelveIndisponibilidad(t *testing.T) {
	api := &fakeS3{listErr: httpError(http.StatusServiceUnavailable, "SlowDown")}

	err := newStore(api, testConfig()).DeleteAllVersions(context.Background(), "records/a/")

	if !errors.Is(err, domain.ErrStorageUnavailable) || errors.Is(err, domain.ErrRetentionActive) {
		t.Fatalf("esperaba solo ErrStorageUnavailable, obtuvo %v", err)
	}
}

func TestSetLegalHoldAplicaATodasLasVersionesSinMarcasDeBorrado(t *testing.T) {
	api := &fakeS3{listPage: []*s3.ListObjectVersionsOutput{{
		Versions:      []types.ObjectVersion{version("records/a/m.json", "v1"), version("records/a/f.jpg", "v2"), version("records/a/f.jpg", "v3")},
		DeleteMarkers: []types.DeleteMarkerEntry{{Key: aws.String("records/a/x.jpg"), VersionId: aws.String("m1")}},
	}}}

	changed, err := newStore(api, testConfig()).SetLegalHold(context.Background(), "records/a/", true)

	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if changed != 3 || len(api.holdIn) != 3 {
		t.Fatalf("modificó %d versiones (%d llamadas), esperaba 3", changed, len(api.holdIn))
	}
	for _, in := range api.holdIn {
		if in.LegalHold.Status != types.ObjectLockLegalHoldStatusOn || in.VersionId == nil {
			t.Errorf("llamada incorrecta: %+v", in)
		}
	}
}

func TestSetLegalHoldOffQuitaElHold(t *testing.T) {
	api := &fakeS3{listPage: []*s3.ListObjectVersionsOutput{{Versions: []types.ObjectVersion{version("records/a/m.json", "v1")}}}}

	if _, err := newStore(api, testConfig()).SetLegalHold(context.Background(), "records/a/", false); err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	if api.holdIn[0].LegalHold.Status != types.ObjectLockLegalHoldStatusOff {
		t.Errorf("estado = %s, esperaba OFF", api.holdIn[0].LegalHold.Status)
	}
}

// captureLogs redirige slog a un buffer durante la prueba.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &buf
}

func TestLasTransicionesDelCircuitoSeRegistran(t *testing.T) {
	logs := captureLogs(t)
	api := &fakeS3{putErr: httpError(http.StatusServiceUnavailable, "SlowDown")}
	store := newStore(api, testConfig())

	for i := 0; i < 2; i++ {
		_ = store.PutLocked(context.Background(), "k", []byte("x"), "t", time.Now())
	}

	out := logs.String()
	if !strings.Contains(out, "transición del circuito") || !strings.Contains(out, "hacia=open") || !strings.Contains(out, "desde=closed") {
		t.Errorf("la apertura del circuito debía registrarse: %s", out)
	}
	if !strings.Contains(out, "bucket=vinculo-vial-audit-test") {
		t.Errorf("el log debía identificar el bucket: %s", out)
	}
}

func TestLosErroresYLogsNoReproducenLaClaveDelObjeto(t *testing.T) {
	logs := captureLogs(t)
	const key = "records/0b8a6c5e-1f56-4e0b-9d63-4f6b8f0f2c11/manifest.json"
	// El texto de un error de red del SDK incluye la URL con la clave del objeto.
	api := &fakeS3{getErr: errors.New(`Get "https://bucket.s3.amazonaws.com/` + key + `?x-id=GetObject": dial tcp: connection refused`)}

	_, err := newStore(api, testConfig()).Get(context.Background(), key)

	if !errors.Is(err, domain.ErrStorageUnavailable) {
		t.Fatalf("esperaba ErrStorageUnavailable, obtuvo %v", err)
	}
	if strings.Contains(err.Error(), key) || strings.Contains(logs.String(), key) {
		t.Errorf("la clave del objeto no debe aparecer en el error ni en los logs (error: %v, logs: %s)", err, logs.String())
	}
}
