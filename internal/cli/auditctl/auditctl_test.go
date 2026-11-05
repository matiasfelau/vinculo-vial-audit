package auditctl

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-audit/internal/domain"
	"github.com/matiasfelau/vinculo-vial-audit/internal/service/export"
)

type fakeExporter struct {
	filter  domain.ExportFilter
	outDir  string
	summary export.Summary
	err     error
	calls   int
}

func (f *fakeExporter) Export(_ context.Context, filter domain.ExportFilter, outDir string) (export.Summary, error) {
	f.calls++
	f.filter, f.outDir = filter, outDir
	return f.summary, f.err
}

type fakeHolder struct {
	id    uuid.UUID
	on    bool
	err   error
	calls int
}

func (f *fakeHolder) Hold(_ context.Context, id uuid.UUID, on bool) (int, error) {
	f.calls++
	f.id, f.on = id, on
	return 3, f.err
}

type harness struct {
	exporter *fakeExporter
	holder   *fakeHolder
	built    int
	closed   int
	buildErr error
}

func (h *harness) factory(context.Context) (Services, func(), error) {
	h.built++
	if h.buildErr != nil {
		return Services{}, nil, h.buildErr
	}
	return Services{Exporter: h.exporter, Holder: h.holder}, func() { h.closed++ }, nil
}

func (h *harness) run(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), args, &stdout, &stderr, h.factory)
	return code, stdout.String(), stderr.String()
}

func newHarness() *harness {
	return &harness{exporter: &fakeExporter{}, holder: &fakeHolder{}}
}

func TestExportPorAlertID(t *testing.T) {
	h := newHarness()
	id := uuid.New()
	h.exporter.summary = export.Summary{Exported: 1}

	code, stdout, stderr := h.run("export", "-alert-id", id.String(), "-out", "/tmp/salida")

	if code != exitOK {
		t.Fatalf("código = %d, stderr: %s", code, stderr)
	}
	if h.exporter.filter.AlertID == nil || *h.exporter.filter.AlertID != id || h.exporter.outDir != "/tmp/salida" {
		t.Errorf("filtro = %+v, out = %q", h.exporter.filter, h.exporter.outDir)
	}
	if !strings.Contains(stdout, "exportados: 1") {
		t.Errorf("stdout = %q", stdout)
	}
	if h.closed != 1 {
		t.Error("debe cerrar las dependencias")
	}
}

func TestExportPorRangoDeFechas(t *testing.T) {
	h := newHarness()

	code, _, stderr := h.run("export", "-from", "2026-11-01T00:00:00Z", "-to", "2026-11-30T23:59:59-03:00", "-out", "/tmp/salida")

	if code != exitOK {
		t.Fatalf("código = %d, stderr: %s", code, stderr)
	}
	wantFrom := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	if !h.exporter.filter.From.Equal(wantFrom) || h.exporter.filter.To.IsZero() || h.exporter.filter.AlertID != nil {
		t.Errorf("filtro = %+v", h.exporter.filter)
	}
}

func TestExportConDiferenciasSalePorElCodigoDedicado(t *testing.T) {
	h := newHarness()
	id := uuid.NewString()
	h.exporter.summary = export.Summary{Exported: 2, Discrepancies: []string{id}}

	code, stdout, _ := h.run("export", "-alert-id", uuid.NewString(), "-out", "/tmp/salida")

	if code != exitDiscrepancies {
		t.Fatalf("código = %d, esperaba %d", code, exitDiscrepancies)
	}
	if !strings.Contains(stdout, id) || !strings.Contains(stdout, "con diferencias: 1") {
		t.Errorf("stdout = %q", stdout)
	}
}

func TestExportConErrorDelServicio(t *testing.T) {
	h := newHarness()
	h.exporter.err = errors.New("falló")

	code, _, stderr := h.run("export", "-alert-id", uuid.NewString(), "-out", "/tmp/salida")

	if code != exitError || !strings.Contains(stderr, "falló") {
		t.Fatalf("código = %d, stderr: %s", code, stderr)
	}
}

func TestUsoIncorrectoNoConstruyeLasDependencias(t *testing.T) {
	id := uuid.NewString()
	casos := map[string][]string{
		"sin subcomando":               nil,
		"subcomando desconocido":       {"borrar"},
		"export sin filtro":            {"export", "-out", "/tmp/x"},
		"export sin -out":              {"export", "-alert-id", id},
		"export con alert-id inválido": {"export", "-alert-id", "x", "-out", "/tmp/x"},
		"export con alert-id nulo":     {"export", "-alert-id", uuid.Nil.String(), "-out", "/tmp/x"},
		"export con alert-id y rango":  {"export", "-alert-id", id, "-from", "2026-11-01T00:00:00Z", "-to", "2026-11-02T00:00:00Z", "-out", "/tmp/x"},
		"export con solo -from":        {"export", "-from", "2026-11-01T00:00:00Z", "-out", "/tmp/x"},
		"export con solo -to":          {"export", "-to", "2026-11-01T00:00:00Z", "-out", "/tmp/x"},
		"export con -from inválido":    {"export", "-from", "ayer", "-to", "2026-11-02T00:00:00Z", "-out", "/tmp/x"},
		"export con rango invertido":   {"export", "-from", "2026-11-02T00:00:00Z", "-to", "2026-11-01T00:00:00Z", "-out", "/tmp/x"},
		"export con flag desconocido":  {"export", "-dni", "123", "-out", "/tmp/x"},
		"hold sin alert-id":            {"hold", "-on"},
		"hold con alert-id inválido":   {"hold", "-alert-id", "x", "-on"},
		"hold sin -on ni -off":         {"hold", "-alert-id", id},
		"hold con -on y -off":          {"hold", "-alert-id", id, "-on", "-off"},
	}

	for nombre, args := range casos {
		t.Run(nombre, func(t *testing.T) {
			h := newHarness()

			code, _, _ := h.run(args...)

			if code != exitUsage {
				t.Errorf("código = %d, esperaba %d", code, exitUsage)
			}
			if h.built != 0 {
				t.Error("con argumentos inválidos no debe abrir la base ni el bucket")
			}
		})
	}
}

func TestNoHayBusquedaPorDNIniPatente(t *testing.T) {
	h := newHarness()

	for _, flagName := range []string{"-dni", "-patente", "-pat"} {
		code, _, _ := h.run("export", flagName, "x", "-out", "/tmp/x")
		if code != exitUsage {
			t.Errorf("%s: código = %d, el export no admite búsqueda por DNI ni patente", flagName, code)
		}
	}
}

func TestHoldOnYOff(t *testing.T) {
	id := uuid.New()

	for _, c := range []struct {
		flag     string
		wantOn   bool
		wantText string
	}{{"-on", true, "aplicada"}, {"-off", false, "quitada"}} {
		t.Run(c.flag, func(t *testing.T) {
			h := newHarness()

			code, stdout, stderr := h.run("hold", "-alert-id", id.String(), c.flag)

			if code != exitOK {
				t.Fatalf("código = %d, stderr: %s", code, stderr)
			}
			if h.holder.id != id || h.holder.on != c.wantOn {
				t.Errorf("hold(%v, %v)", h.holder.id, h.holder.on)
			}
			if !strings.Contains(stdout, c.wantText) {
				t.Errorf("stdout = %q", stdout)
			}
			if h.closed != 1 {
				t.Error("debe cerrar las dependencias")
			}
		})
	}
}

func TestHoldConErrorDelServicio(t *testing.T) {
	h := newHarness()
	h.holder.err = domain.ErrRecordNotFound

	code, _, stderr := h.run("hold", "-alert-id", uuid.NewString(), "-on")

	if code != exitError || !strings.Contains(stderr, "inexistente") {
		t.Fatalf("código = %d, stderr: %s", code, stderr)
	}
}

func TestErrorAlConstruirLasDependencias(t *testing.T) {
	h := newHarness()
	h.buildErr = errors.New("config: DATABASE_URL es obligatoria")

	code, _, stderr := h.run("hold", "-alert-id", uuid.NewString(), "-on")

	if code != exitError || !strings.Contains(stderr, "DATABASE_URL") {
		t.Fatalf("código = %d, stderr: %s", code, stderr)
	}
}
