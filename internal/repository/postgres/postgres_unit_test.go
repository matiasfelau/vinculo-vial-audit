package postgres

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/matiasfelau/vinculo-vial-audit/internal/domain"
	"github.com/matiasfelau/vinculo-vial-audit/internal/manifest"
)

// classifyError decide si un fallo de la base se reintenta (indisponibilidad,
// va a .retry) o es terminal (va a .dlq). Una clasificación equivocada pierde
// mensajes o los reintenta para siempre.
func TestClassifyErrorSoloMarcaLaIndisponibilidadDeInfraestructura(t *testing.T) {
	casos := []struct {
		nombre       string
		err          error
		reintentable bool // true: indisponibilidad, el mensaje va a .retry
	}{
		{"plazo vencido", context.DeadlineExceeded, true},
		{"contexto cancelado", context.Canceled, true},
		{"plazo vencido envuelto", fmt.Errorf("consulta: %w", context.DeadlineExceeded), true},
		{"error de red", &net.OpError{Op: "dial", Err: errors.New("connection refused")}, true},
		{"clase 08: conexión", &pgconn.PgError{Code: "08006"}, true},
		{"clase 53: recursos insuficientes", &pgconn.PgError{Code: "53300"}, true},
		{"consulta cancelada (57014)", &pgconn.PgError{Code: "57014"}, true},
		{"apagado del servidor (57P01)", &pgconn.PgError{Code: "57P01"}, true},
		{"servidor iniciando (57P03)", &pgconn.PgError{Code: "57P03"}, true},
		{"violación de unicidad (23505)", &pgconn.PgError{Code: "23505"}, false},
		{"error de sintaxis (42601)", &pgconn.PgError{Code: "42601"}, false},
		{"código demasiado corto", &pgconn.PgError{Code: "5"}, false},
		{"57 que no es cancelación ni apagado", &pgconn.PgError{Code: "57000"}, false},
		{"error genérico", errors.New("fallo cualquiera"), false},
	}

	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			got := classifyError(c.err)

			if indisponible := errors.Is(got, domain.ErrRepositoryUnavailable); indisponible != c.reintentable {
				t.Errorf("errors.Is(ErrRepositoryUnavailable) = %v, esperaba %v", indisponible, c.reintentable)
			}
			if !errors.Is(got, c.err) {
				t.Errorf("el error original se perdió: %v", got)
			}
			if !c.reintentable && got != c.err {
				t.Errorf("un error terminal debe devolverse sin envolver, obtuvo %v", got)
			}
		})
	}
}

func TestClassifyErrorConNilDevuelveNil(t *testing.T) {
	if got := classifyError(nil); got != nil {
		t.Errorf("classifyError(nil) = %v, esperaba nil", got)
	}
}

func TestWithConnectTimeout(t *testing.T) {
	casos := []struct {
		nombre string
		dsn    string
		want   string // valor esperado de connect_timeout
		extra  string // parámetro que debe conservarse
	}{
		{"agrega el plazo por defecto", "postgres://audit:pw@db:5432/audit?sslmode=disable", "5", "sslmode=disable"},
		{"respeta el plazo explícito del operador", "postgres://audit:pw@db:5432/audit?connect_timeout=30&sslmode=disable", "30", "sslmode=disable"},
		{"sin parámetros previos", "postgres://audit:pw@db:5432/audit", "5", ""},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			got, err := withConnectTimeout(c.dsn, 5)
			if err != nil {
				t.Fatalf("withConnectTimeout falló: %v", err)
			}

			parsed, err := url.Parse(got)
			if err != nil {
				t.Fatalf("la cadena resultante no es una URL: %v", err)
			}
			if timeout := parsed.Query().Get("connect_timeout"); timeout != c.want {
				t.Errorf("connect_timeout = %q, esperaba %q", timeout, c.want)
			}
			if c.extra != "" && !strings.Contains(got, c.extra) {
				t.Errorf("se perdió el parámetro %q en %q", c.extra, got)
			}
			if parsed.User.String() != "audit:pw" || parsed.Host != "db:5432" || parsed.Path != "/audit" {
				t.Errorf("se alteró la parte de conexión: %q", got)
			}
		})
	}
}

func TestWithConnectTimeoutRechazaUnaCadenaInvalida(t *testing.T) {
	if _, err := withConnectTimeout("postgres://audit@localhost:puerto-malo/audit", 5); err == nil {
		t.Error("una URL con puerto inválido debe rechazarse")
	}
}

func TestEvidenciaSeSerializaYSeRecuperaSinPerdida(t *testing.T) {
	items := []manifest.EvidenceItem{{}, {}}

	texto, err := encodeEvidence(items)
	if err != nil || texto == nil {
		t.Fatalf("encodeEvidence = %v, %v", texto, err)
	}
	got, err := decodeEvidence(texto)
	if err != nil {
		t.Fatalf("decodeEvidence falló: %v", err)
	}
	if len(got) != len(items) {
		t.Errorf("se recuperaron %d ítems, esperaba %d", len(got), len(items))
	}
}

func TestEvidenciaNulaQuedaComoNULL(t *testing.T) {
	texto, err := encodeEvidence(nil)
	if err != nil || texto != nil {
		t.Fatalf("una evidencia nula debe quedar como NULL, obtuvo %v, %v", texto, err)
	}
	items, err := decodeEvidence(nil)
	if err != nil || items != nil {
		t.Fatalf("NULL debe leerse como evidencia nula, obtuvo %v, %v", items, err)
	}
}

func TestEvidenciaIlegibleSeRechazaEnVezDeDevolverseVacia(t *testing.T) {
	ilegible := `{"no": "es una lista"}`

	if _, err := decodeEvidence(&ilegible); err == nil {
		t.Fatal("decodeEvidence aceptó una evidencia que no es una lista")
	}
	if _, err := (auditRecordModel{Evidence: &ilegible}).toDomain(); err == nil {
		t.Error("toDomain devolvió un registro con evidencia ilegible")
	}
}

func TestMigrationNamesListaSoloSQLEnOrdenDeVersion(t *testing.T) {
	names, err := migrationNames()
	if err != nil {
		t.Fatalf("migrationNames falló: %v", err)
	}
	if len(names) < 2 {
		t.Fatalf("esperaba al menos 2 migraciones, obtuvo %v", names)
	}
	for i, name := range names {
		if !strings.HasSuffix(name, ".sql") {
			t.Errorf("%q no es un .sql", name)
		}
		if i > 0 && names[i-1] >= name {
			t.Errorf("las migraciones no están en orden de versión: %v", names)
		}
	}
}
