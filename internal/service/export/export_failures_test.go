package export

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/matiasfelau/vinculo-vial-audit/internal/domain"
	"github.com/matiasfelau/vinculo-vial-audit/internal/manifest"
	"github.com/matiasfelau/vinculo-vial-audit/internal/testsupport"
)

func informeSano() Report {
	hasta := destroyAt
	retencion := &Retention{LockMode: "GOVERNANCE", RetainUntil: &hasta, OK: true}
	return Report{
		ManifestFound:      true,
		RowMatchesManifest: true,
		ManifestRetention:  retencion,
		Photos:             []PhotoReport{{Role: "GENERAL", Found: true, SHA256Matches: true, Retention: retencion}},
	}
}

// Un informe solo es OK si pasa todas las verificaciones: cualquier hueco es una
// discrepancia que el operador tiene que ver.
func TestReportOKExigeTodasLasVerificaciones(t *testing.T) {
	if !informeSano().OK() {
		t.Fatal("el informe base debería pasar todas las verificaciones")
	}

	casos := []struct {
		nombre string
		rompe  func(*Report)
	}{
		{"con error", func(r *Report) { r.Error = "falló algo" }},
		{"sin manifiesto", func(r *Report) { r.ManifestFound = false }},
		{"la fila no coincide con el manifiesto", func(r *Report) { r.RowMatchesManifest = false }},
		{"sin retención del manifiesto", func(r *Report) { r.ManifestRetention = nil }},
		{"retención del manifiesto insuficiente", func(r *Report) { r.ManifestRetention = &Retention{} }},
		{"foto no encontrada", func(r *Report) { r.Photos[0].Found = false }},
		{"SHA-256 de la foto distinto", func(r *Report) { r.Photos[0].SHA256Matches = false }},
		{"foto sin retención", func(r *Report) { r.Photos[0].Retention = nil }},
		{"retención de la foto insuficiente", func(r *Report) { r.Photos[0].Retention = &Retention{} }},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			informe := informeSano()
			c.rompe(&informe)

			if informe.OK() {
				t.Error("el informe con un hueco no debe ser OK")
			}
		})
	}
}

type failingRecords struct{ err error }

func (f failingRecords) ListForExport(context.Context, domain.ExportFilter) ([]domain.Record, error) {
	return nil, f.err
}

func TestExportInformaQueNoPudoListarLosRegistros(t *testing.T) {
	causa := domain.ErrRepositoryUnavailable
	outDir := filepath.Join(t.TempDir(), "export")

	summary, err := New(failingRecords{err: causa}, testsupport.NewMemoryObjects()).
		Export(context.Background(), domain.ExportFilter{From: createdAt, To: createdAt.Add(time.Hour)}, outDir)

	if !errors.Is(err, causa) || !strings.Contains(err.Error(), "no se pudieron listar") {
		t.Fatalf("error = %v, esperaba el de la base con contexto", err)
	}
	if summary.Exported != 0 {
		t.Errorf("resumen = %+v, no debería haber exportado nada", summary)
	}
}

// El export nunca pisa una exportación anterior: es evidencia para un juzgado.
func TestExportNoSobrescribeUnaExportacionAnterior(t *testing.T) {
	f := newFixture(t)
	_, outDir := f.export(t)
	manifestPath := filepath.Join(outDir, f.id.String(), manifest.ManifestFileName)
	antes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}

	_, err = New(f.source, f.objects).Export(context.Background(), domain.ExportFilter{AlertID: &f.id}, outDir)

	if err == nil || !strings.Contains(err.Error(), "no se pudo crear el directorio del registro") {
		t.Fatalf("error = %v, esperaba que se negara a reutilizar el directorio", err)
	}
	despues, err := os.ReadFile(manifestPath)
	if err != nil || string(antes) != string(despues) {
		t.Error("la exportación anterior se modificó")
	}
}

func TestExportInformaLaFilaConEvidenciaDistintaAlManifiesto(t *testing.T) {
	f := newFixture(t)
	f.record.Evidence = slices.Clone(f.record.Evidence)
	f.record.Evidence[1].SHA256 = strings.Repeat("0", 64)
	f.source.records = []domain.Record{f.record}

	summary, outDir := f.export(t)

	report := readReport(t, outDir, f.id.String())
	if report.RowMatchesManifest || !slices.Contains(report.RowDifferences, fieldEvidence) {
		t.Errorf("la evidencia distinta no se informó: %+v", report)
	}
	if len(summary.Discrepancies) != 1 {
		t.Errorf("resumen = %+v, esperaba 1 discrepancia", summary)
	}
}

// cancelOn cancela el contexto al pedir la clave indicada, como si el operador
// interrumpiera la CLI a mitad de la exportación.
type cancelOn struct {
	*testsupport.MemoryObjects
	cancel context.CancelFunc
	key    string
}

func (c cancelOn) GetObject(ctx context.Context, key string) (domain.StoredObject, error) {
	if key == c.key {
		c.cancel()
		return domain.StoredObject{}, context.Canceled
	}
	return c.MemoryObjects.GetObject(ctx, key)
}

// Una interrupción no es una discrepancia del registro: la exportación se corta
// con el error del contexto en vez de escribir un informe engañoso.
func TestExportInterrumpidaPorElContextoDevuelveElErrorDelContexto(t *testing.T) {
	casos := []struct {
		nombre string
		clave  func(id string) string
	}{
		{"al leer el manifiesto", manifest.ManifestKey},
		{"al leer una foto", func(id string) string { return manifest.PhotoKey(id, "GENERAL", 0) }},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			f := newFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			objects := cancelOn{MemoryObjects: f.objects, cancel: cancel, key: c.clave(f.id.String())}

			_, err := New(f.source, objects).Export(ctx, domain.ExportFilter{AlertID: &f.id}, filepath.Join(t.TempDir(), "export"))

			if !errors.Is(err, context.Canceled) {
				t.Fatalf("error = %v, esperaba context.Canceled", err)
			}
		})
	}
}
