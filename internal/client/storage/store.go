// Package storage implementa el acceso a S3 de Audit: la lectura de las fotos
// redactadas del bucket de evidencia y la escritura, con S3 Object Lock, la
// lectura y el borrado del bucket de Audit. Las credenciales salen de la cadena
// estándar del SDK y no hay endpoint personalizado: S3 es siempre el de AWS.
//
// Cada Store habla con un único bucket y tiene su propio circuit breaker: la
// degradación de un bucket no abre el circuito del otro.
package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/matiasfelau/vinculo-vial-audit/internal/breaker"
	"github.com/matiasfelau/vinculo-vial-audit/internal/domain"
)

const (
	// sdkMaxAttempts desactiva los reintentos del SDK: nunca se reintenta en bucle
	// dentro de una operación. El reintento es del llamador (cola .retry o la
	// vuelta siguiente del sweeper).
	sdkMaxAttempts = 1

	codeNoSuchKey = "NoSuchKey"
	codeNotFound  = "NotFound"

	stateOpen     = "open"
	stateHalfOpen = "half-open"

	// readOverrun es cuántos bytes se leen de más para detectar que un objeto
	// excede el tope sin cargarlo entero.
	readOverrun = 1
)

// s3API es el subconjunto de *s3.Client que usa el adaptador, para poder
// probarlo con un doble sin tocar AWS.
type s3API interface {
	PutObject(ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(ctx context.Context, in *s3.GetObjectInput, opts ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	ListObjectVersions(ctx context.Context, in *s3.ListObjectVersionsInput, opts ...func(*s3.Options)) (*s3.ListObjectVersionsOutput, error)
	DeleteObject(ctx context.Context, in *s3.DeleteObjectInput, opts ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
	PutObjectLegalHold(ctx context.Context, in *s3.PutObjectLegalHoldInput, opts ...func(*s3.Options)) (*s3.PutObjectLegalHoldOutput, error)
}

// Config agrupa los parámetros de un Store.
type Config struct {
	Region string
	Bucket string
	// LockMode es GOVERNANCE o COMPLIANCE; solo lo usa PutLocked.
	LockMode string
	// PutTimeout acota cada escritura, borrado y cambio de legal hold.
	PutTimeout time.Duration
	// GetTimeout acota cada lectura (incluida la del cuerpo) y cada listado.
	GetTimeout time.Duration
	// MaxObjectBytes es el tope de tamaño de un objeto leído.
	MaxObjectBytes int64

	BreakerThreshold    int
	BreakerWindow       time.Duration
	BreakerOpenDuration time.Duration
}

// Store accede a un bucket de S3.
type Store struct {
	api     s3API
	cfg     Config
	breaker *breaker.Breaker
}

// New construye un Store sobre el cliente real de S3. Cada operación lleva el
// deadline de su contexto y el SDK no reintenta.
func New(ctx context.Context, cfg Config) (*Store, error) {
	// Los timeouts del transporte se derivan del mayor de los dos timeouts de
	// operación; el deadline de cada operación es la cota precisa.
	transportTimeout := max(cfg.PutTimeout, cfg.GetTimeout)
	httpClient := awshttp.NewBuildableClient().
		WithDialerOptions(func(d *net.Dialer) { d.Timeout = transportTimeout }).
		WithTransportOptions(func(t *http.Transport) {
			t.TLSHandshakeTimeout = transportTimeout
			t.ResponseHeaderTimeout = transportTimeout
		})

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(cfg.Region),
		awsconfig.WithRetryMaxAttempts(sdkMaxAttempts),
		awsconfig.WithHTTPClient(httpClient),
	)
	if err != nil {
		return nil, fmt.Errorf("storage: no se pudo cargar la configuración de AWS: %w", err)
	}
	return newStore(s3.NewFromConfig(awsCfg), cfg), nil
}

func newStore(api s3API, cfg Config) *Store {
	return &Store{
		api:     api,
		cfg:     cfg,
		breaker: breaker.New(cfg.BreakerThreshold, cfg.BreakerWindow, cfg.BreakerOpenDuration),
	}
}

// Healthy indica si el circuito de este bucket no está abierto. Lo usa /health/deps.
func (s *Store) Healthy() bool {
	return s.breaker.State() != stateOpen
}

// Get lee un objeto (su versión vigente) hasta MaxObjectBytes.
func (s *Store) Get(ctx context.Context, key string) ([]byte, error) {
	object, err := s.GetObject(ctx, key)
	if err != nil {
		return nil, err
	}
	return object.Body, nil
}

// GetObject lee un objeto (su versión vigente) con su estado de retención. El
// timeout cubre también la lectura del cuerpo.
func (s *Store) GetObject(ctx context.Context, key string) (domain.StoredObject, error) {
	var object domain.StoredObject

	err := s.do(ctx, "get", s.cfg.GetTimeout, func(ctx context.Context) error {
		out, err := s.api.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.cfg.Bucket), Key: aws.String(key)})
		if err != nil {
			return err
		}
		defer func() { _ = out.Body.Close() }()

		if aws.ToInt64(out.ContentLength) > s.cfg.MaxObjectBytes {
			return domain.ErrObjectTooLarge
		}
		body, err := io.ReadAll(io.LimitReader(out.Body, s.cfg.MaxObjectBytes+readOverrun))
		if err != nil {
			return err
		}
		if int64(len(body)) > s.cfg.MaxObjectBytes {
			return domain.ErrObjectTooLarge
		}

		object = domain.StoredObject{
			Body:        body,
			LockMode:    string(out.ObjectLockMode),
			RetainUntil: out.ObjectLockRetainUntilDate,
			LegalHold:   out.ObjectLockLegalHoldStatus == types.ObjectLockLegalHoldStatusOn,
		}
		return nil
	})
	if err != nil {
		return domain.StoredObject{}, err
	}
	return object, nil
}

// PutLocked escribe el objeto con Object Lock en el modo configurado hasta
// retainUntil. Si la clave ya existe crea una versión nueva: el bucket es
// versionado y el sweeper borra todas las versiones.
func (s *Store) PutLocked(ctx context.Context, key string, body []byte, contentType string, retainUntil time.Time) error {
	return s.do(ctx, "put", s.cfg.PutTimeout, func(ctx context.Context) error {
		_, err := s.api.PutObject(ctx, &s3.PutObjectInput{
			Bucket:                    aws.String(s.cfg.Bucket),
			Key:                       aws.String(key),
			Body:                      bytes.NewReader(body),
			ContentType:               aws.String(contentType),
			ChecksumAlgorithm:         types.ChecksumAlgorithmSha256,
			ObjectLockMode:            types.ObjectLockMode(s.cfg.LockMode),
			ObjectLockRetainUntilDate: aws.Time(retainUntil.UTC()),
		})
		return err
	})
}

// DeleteAllVersions borra todas las versiones (y marcas de borrado) de los
// objetos bajo prefix. Si S3 rechaza un borrado porque la retención o el legal
// hold siguen vigentes devuelve domain.ErrRetentionActive: lo borrado hasta ahí
// se conserva borrado y la vuelta siguiente retoma el resto.
func (s *Store) DeleteAllVersions(ctx context.Context, prefix string) error {
	versions, err := s.listVersions(ctx, prefix)
	if err != nil {
		return err
	}

	for _, v := range versions {
		err := s.do(ctx, "delete", s.cfg.PutTimeout, func(ctx context.Context) error {
			_, err := s.api.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket:    aws.String(s.cfg.Bucket),
				Key:       aws.String(v.key),
				VersionId: aws.String(v.versionID),
			})
			return err
		})
		switch {
		case err == nil:
		case errors.Is(err, domain.ErrStorageRejected):
			return fmt.Errorf("%w: %w", domain.ErrRetentionActive, err)
		default:
			return err
		}
	}
	return nil
}

// SetLegalHold aplica (on) o quita (!on) el legal hold de S3 Object Lock en
// todas las versiones de los objetos bajo prefix y devuelve cuántas modificó.
func (s *Store) SetLegalHold(ctx context.Context, prefix string, on bool) (int, error) {
	versions, err := s.listVersions(ctx, prefix)
	if err != nil {
		return 0, err
	}

	status := types.ObjectLockLegalHoldStatusOff
	if on {
		status = types.ObjectLockLegalHoldStatusOn
	}

	changed := 0
	for _, v := range versions {
		if v.deleteMarker {
			continue
		}
		err := s.do(ctx, "legal-hold", s.cfg.PutTimeout, func(ctx context.Context) error {
			_, err := s.api.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
				Bucket:    aws.String(s.cfg.Bucket),
				Key:       aws.String(v.key),
				VersionId: aws.String(v.versionID),
				LegalHold: &types.ObjectLockLegalHold{Status: status},
			})
			return err
		})
		if err != nil {
			return changed, err
		}
		changed++
	}
	return changed, nil
}

// objectVersion identifica una versión (o marca de borrado) de un objeto.
type objectVersion struct {
	key          string
	versionID    string
	deleteMarker bool
}

// listVersions lista todas las versiones y marcas de borrado bajo prefix,
// paginando.
func (s *Store) listVersions(ctx context.Context, prefix string) ([]objectVersion, error) {
	var result []objectVersion
	var keyMarker, versionMarker *string

	for {
		var page *s3.ListObjectVersionsOutput
		err := s.do(ctx, "list", s.cfg.GetTimeout, func(ctx context.Context) error {
			out, err := s.api.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
				Bucket:          aws.String(s.cfg.Bucket),
				Prefix:          aws.String(prefix),
				KeyMarker:       keyMarker,
				VersionIdMarker: versionMarker,
			})
			page = out
			return err
		})
		if err != nil {
			return nil, err
		}

		for _, v := range page.Versions {
			result = append(result, objectVersion{key: aws.ToString(v.Key), versionID: aws.ToString(v.VersionId)})
		}
		for _, m := range page.DeleteMarkers {
			result = append(result, objectVersion{key: aws.ToString(m.Key), versionID: aws.ToString(m.VersionId), deleteMarker: true})
		}

		if !aws.ToBool(page.IsTruncated) {
			return result, nil
		}
		keyMarker, versionMarker = page.NextKeyMarker, page.NextVersionIdMarker
	}
}

// do ejecuta una operación con su timeout, detrás del circuit breaker.
func (s *Store) do(ctx context.Context, op string, timeout time.Duration, call func(ctx context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return s.guard(op, func() error { return call(ctx) })
}

// guard envuelve la llamada con el circuit breaker, clasifica el error y
// registra el resultado. Con el circuito abierto falla de inmediato, sin llamar
// a S3. Cada transición del circuito se registra.
func (s *Store) guard(op string, call func() error) error {
	before := s.breaker.State()
	defer s.logTransition(before)

	if !s.breaker.Allow() {
		slog.Warn("storage: circuito de S3 abierto, no se llama a S3", "bucket", s.cfg.Bucket, "op", op)
		return domain.ErrStorageUnavailable
	}

	err := call()
	classified := classify(err)

	switch {
	case classified == nil,
		errors.Is(classified, domain.ErrObjectNotFound),
		errors.Is(classified, domain.ErrStorageRejected),
		errors.Is(classified, domain.ErrObjectTooLarge):
		// S3 respondió con normalidad: aun un 404 o un 403 prueban que el destino
		// está vivo, y una prueba half-open no puede quedar sin resolver.
		s.breaker.RecordSuccess()
	case errors.Is(classified, context.Canceled):
		// El llamador desistió: no es una falla de S3. Pero una prueba half-open
		// sin resolver dejaría el circuito trabado, así que en ese estado se reabre.
		if s.breaker.State() == stateHalfOpen {
			s.breaker.RecordFailure()
		}
	default:
		s.breaker.RecordFailure()
		slog.Error("storage: falla de S3", "bucket", s.cfg.Bucket, "op", op, "causa", classified.Error())
	}

	return classified
}

// logTransition registra el cambio de estado del circuito respecto de before.
func (s *Store) logTransition(before string) {
	after := s.breaker.State()
	if after == before {
		return
	}
	if after == stateOpen {
		slog.Warn("storage: transición del circuito de S3", "bucket", s.cfg.Bucket, "desde", before, "hacia", after)
		return
	}
	slog.Info("storage: transición del circuito de S3", "bucket", s.cfg.Bucket, "desde", before, "hacia", after)
}

// classify traduce un error del SDK al error de dominio correspondiente:
//   - nil → nil;
//   - NoSuchKey / 404 → ErrObjectNotFound;
//   - cancelación del llamador → context.Canceled;
//   - timeout, error de conexión, 5xx y 429 → ErrStorageUnavailable (computan para
//     el breaker);
//   - cualquier otro 4xx (p. ej. AccessDenied) → ErrStorageRejected.
//
// Sin s3:ListBucket, S3 responde 403 en lugar de NoSuchKey para un objeto
// inexistente: ese permiso es requisito del despliegue.
func classify(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, domain.ErrObjectTooLarge) {
		return err
	}

	var noSuchKey *types.NoSuchKey
	if errors.As(err, &noSuchKey) {
		return fmt.Errorf("%w: %s", domain.ErrObjectNotFound, describe(err))
	}

	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case codeNoSuchKey, codeNotFound:
			return fmt.Errorf("%w: %s", domain.ErrObjectNotFound, describe(err))
		}
	}

	var respErr *smithyhttp.ResponseError
	if errors.As(err, &respErr) {
		status := respErr.HTTPStatusCode()
		switch {
		case status == http.StatusNotFound:
			return fmt.Errorf("%w: %s", domain.ErrObjectNotFound, describe(err))
		case status >= http.StatusInternalServerError, status == http.StatusTooManyRequests:
			return fmt.Errorf("%w: %s", domain.ErrStorageUnavailable, describe(err))
		default:
			return fmt.Errorf("%w: %s", domain.ErrStorageRejected, describe(err))
		}
	}

	if errors.Is(err, context.Canceled) {
		return err
	}

	// Sin respuesta HTTP: timeout (context.DeadlineExceeded incluido), DNS,
	// conexión rechazada, TLS o corte a mitad de camino.
	return fmt.Errorf("%w: %s", domain.ErrStorageUnavailable, describe(err))
}

// describe resume un error del SDK sin reproducir su texto: el mensaje de un error
// de red incluye la URL del objeto (con la clave), que no debe llegar a logs ni a
// errores. Devuelve el código HTTP y el código de error de S3, o la clase de falla.
func describe(err error) string {
	var respErr *smithyhttp.ResponseError
	if errors.As(err, &respErr) {
		description := fmt.Sprintf("HTTP %d", respErr.HTTPStatusCode())
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			description += " " + apiErr.ErrorCode()
		}
		return description
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return "error de red"
}
