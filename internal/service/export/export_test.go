package export

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-audit/internal/domain"
	"github.com/matiasfelau/vinculo-vial-audit/internal/manifest"
	"github.com/matiasfelau/vinculo-vial-audit/internal/testsupport"
)

var (
	createdAt = time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	destroyAt = createdAt.Add(1095 * 24 * time.Hour)
)

type fakeRecords struct {
	records []domain.Record
	filter  domain.ExportFilter
}

func (f *fakeRecords) ListForExport(_ context.Context, filter domain.ExportFilter) ([]domain.Record, error) {
	f.filter = filter
	return f.records, nil
}

func sha(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// fixture arma un registro DELIVERED coherente: fila, manifiesto y dos fotos
// bloqueadas en el bucket de Audit.
type fixture struct {
	id      uuid.UUID
	record  domain.Record
	objects *testsupport.MemoryObjects
	source  *fakeRecords
	photos  map[string][]byte
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	f := &fixture{
		id:      uuid.New(),
		objects: testsupport.NewMemoryObjects(),
		photos:  map[string][]byte{"GENERAL": []byte("foto-general"), "PLATE": []byte("foto-patente")},
	}
	id := f.id.String()

	var evidence []manifest.EvidenceItem
	for _, role := range []string{"GENERAL", "PLATE"} {
		key := manifest.PhotoKey(id, role, 0)
		if err := f.objects.PutLocked(context.Background(), key, f.photos[role], manifest.ContentTypePhoto, destroyAt); err != nil {
			t.Fatal(err)
		}
		evidence = append(evidence, manifest.EvidenceItem{Role: role, Index: 0, Key: key, SHA256: sha(f.photos[role])})
	}

	deliveredAt := createdAt.Add(time.Hour)
	body, err := manifest.Marshal(manifest.Manifest{
		AlertID: id, AlertType: "CRASHED", AlertCreatedAt: createdAt, DeliveredAt: deliveredAt,
		DNIEncAudit: "ZG5p", PatEncAudit: "cGF0", AuditKeyID: "2026-11", Evidence: evidence,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.objects.PutLocked(context.Background(), manifest.ManifestKey(id), body, manifest.ContentTypeManifest, destroyAt); err != nil {
		t.Fatal(err)
	}

	manifestKey, manifestSHA := manifest.ManifestKey(id), sha(body)
	f.record = domain.Record{
		AlertID: f.id, AlertType: "CRASHED", AlertCreatedAt: createdAt,
		DNIEncAudit: "ZG5p", PatEncAudit: "cGF0", AuditKeyID: "2026-11",
		Status: domain.StatusDelivered, RecordedAt: createdAt, DeliveredAt: &deliveredAt,
		Evidence: evidence, ManifestKey: &manifestKey, ManifestSHA256: &manifestSHA, DestroyAt: destroyAt,
	}
	f.source = &fakeRecords{records: []domain.Record{f.record}}
	return f
}

func (f *fixture) export(t *testing.T) (Summary, string) {
	t.Helper()
	outDir := filepath.Join(t.TempDir(), "export")

	summary, err := New(f.source, f.objects).Export(context.Background(), domain.ExportFilter{AlertID: &f.id}, outDir)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	return summary, outDir
}

func readReport(t *testing.T, outDir, alertID string) Report {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(outDir, alertID, ReportFileName))
	if err != nil {
		t.Fatalf("no se escribió el informe: %v", err)
	}
	var report Report
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("informe ilegible: %v", err)
	}
	return report
}

func TestExportEscribeManifiestoFotosEInformeSinDiferencias(t *testing.T) {
	f := newFixture(t)

	summary, outDir := f.export(t)

	if summary.Exported != 1 || len(summary.Discrepancies) != 0 {
		t.Fatalf("resumen = %+v", summary)
	}
	dir := filepath.Join(outDir, f.id.String())
	for _, name := range []string{manifest.ManifestFileName, "GENERAL-0.jpg", "PLATE-0.jpg", ReportFileName} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("falta %s: %v", name, err)
		}
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "GENERAL-0.jpg")); string(got) != "foto-general" {
		t.Error("la foto exportada no coincide")
	}

	report := readReport(t, outDir, f.id.String())
	if !report.OK() || !report.ManifestFound || !report.RowMatchesManifest {
		t.Errorf("informe = %+v", report)
	}
	if len(report.Photos) != 2 {
		t.Fatalf("fotos en el informe = %d", len(report.Photos))
	}
	for _, photo := range report.Photos {
		if !photo.Found || !photo.SHA256Matches || photo.Retention == nil || !photo.Retention.OK {
			t.Errorf("foto %s-%d: %+v", photo.Role, photo.Index, photo)
		}
	}
}

func TestExportFiltraComoSeLePide(t *testing.T) {
	f := newFixture(t)
	from, to := createdAt.Add(-time.Hour), createdAt.Add(time.Hour)

	_, err := New(f.source, f.objects).Export(context.Background(), domain.ExportFilter{From: from, To: to}, filepath.Join(t.TempDir(), "x"))

	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if !f.source.filter.From.Equal(from) || !f.source.filter.To.Equal(to) || f.source.filter.AlertID != nil {
		t.Errorf("filtro = %+v", f.source.filter)
	}
}

func TestExportInformaUnaFilaAlterada(t *testing.T) {
	campos := map[string]func(r *domain.Record){
		"dni_enc_audit":    func(r *domain.Record) { r.DNIEncAudit = "b3Rybw==" },
		"pat_enc_audit":    func(r *domain.Record) { r.PatEncAudit = "b3Rybw==" },
		"audit_key_id":     func(r *domain.Record) { r.AuditKeyID = "1999-01" },
		"alert_type":       func(r *domain.Record) { r.AlertType = "PARKED_ON_GARAGE" },
		"alert_created_at": func(r *domain.Record) { r.AlertCreatedAt = r.AlertCreatedAt.Add(time.Hour) },
		"delivered_at": func(r *domain.Record) {
			other := r.DeliveredAt.Add(time.Hour)
			r.DeliveredAt = &other
		},
		"evidence":        func(r *domain.Record) { r.Evidence = r.Evidence[:1] },
		"manifest_sha256": func(r *domain.Record) { other := sha([]byte("otro")); r.ManifestSHA256 = &other },
	}

	for campo, alterar := range campos {
		t.Run(campo, func(t *testing.T) {
			f := newFixture(t)
			alterar(&f.source.records[0])

			summary, outDir := f.export(t)

			if len(summary.Discrepancies) != 1 {
				t.Fatalf("resumen = %+v, esperaba una discrepancia", summary)
			}
			report := readReport(t, outDir, f.id.String())
			if report.RowMatchesManifest || !slices.Contains(report.RowDifferences, campo) {
				t.Errorf("el informe debía marcar %q: %+v", campo, report.RowDifferences)
			}
		})
	}
}

func TestExportInformaUnaFotoAlterada(t *testing.T) {
	f := newFixture(t)
	f.objects.Replace(manifest.PhotoKey(f.id.String(), "PLATE", 0), []byte("foto adulterada"))

	summary, outDir := f.export(t)

	if len(summary.Discrepancies) != 1 {
		t.Fatalf("resumen = %+v", summary)
	}
	report := readReport(t, outDir, f.id.String())
	var plate *PhotoReport
	for i := range report.Photos {
		if report.Photos[i].Role == "PLATE" {
			plate = &report.Photos[i]
		}
	}
	if plate == nil || plate.SHA256Matches {
		t.Errorf("la foto alterada debía marcarse: %+v", plate)
	}
	if !report.RowMatchesManifest {
		t.Error("la fila coincide con el manifiesto: solo la foto cambió")
	}
}

func TestExportInformaUnaFotoFaltante(t *testing.T) {
	f := newFixture(t)
	if err := f.objects.DeleteAllVersions(context.Background(), manifest.PhotoKey(f.id.String(), "GENERAL", 0)); err != nil {
		t.Fatal(err)
	}

	summary, outDir := f.export(t)

	if len(summary.Discrepancies) != 1 {
		t.Fatalf("resumen = %+v", summary)
	}
	for _, photo := range readReport(t, outDir, f.id.String()).Photos {
		if photo.Role == "GENERAL" && (photo.Found || photo.Error == "") {
			t.Errorf("la foto faltante debía informarse: %+v", photo)
		}
	}
}

func TestExportInformaUnManifiestoAusente(t *testing.T) {
	f := newFixture(t)
	if err := f.objects.DeleteAllVersions(context.Background(), manifest.ManifestKey(f.id.String())); err != nil {
		t.Fatal(err)
	}

	summary, outDir := f.export(t)

	if len(summary.Discrepancies) != 1 {
		t.Fatalf("resumen = %+v", summary)
	}
	if report := readReport(t, outDir, f.id.String()); report.ManifestFound || report.Error == "" {
		t.Errorf("informe = %+v", report)
	}
}

func TestExportInformaUnManifiestoIlegible(t *testing.T) {
	f := newFixture(t)
	f.objects.Replace(manifest.ManifestKey(f.id.String()), []byte("no es json"))

	summary, _ := f.export(t)

	if len(summary.Discrepancies) != 1 {
		t.Fatalf("resumen = %+v", summary)
	}
}

func TestExportInformaRetencionInsuficiente(t *testing.T) {
	casos := map[string]func(f *fixture){
		"retención más corta que destroy_at": func(f *fixture) {
			key := manifest.PhotoKey(f.id.String(), "GENERAL", 0)
			f.objects.Replace(key, f.photos["GENERAL"])
			// Se reescribe la foto con una retención que vence antes de destroy_at.
			_ = f.objects.DeleteAllVersions(context.Background(), key)
			_ = f.objects.PutLocked(context.Background(), key, f.photos["GENERAL"], manifest.ContentTypePhoto, destroyAt.Add(-48*time.Hour))
		},
		"sin retención": func(f *fixture) {
			key := manifest.PhotoKey(f.id.String(), "GENERAL", 0)
			_ = f.objects.DeleteAllVersions(context.Background(), key)
			f.objects.Seed(key, f.photos["GENERAL"])
		},
	}

	for nombre, preparar := range casos {
		t.Run(nombre, func(t *testing.T) {
			f := newFixture(t)
			preparar(f)

			summary, outDir := f.export(t)

			if len(summary.Discrepancies) != 1 {
				t.Fatalf("resumen = %+v", summary)
			}
			for _, photo := range readReport(t, outDir, f.id.String()).Photos {
				if photo.Role == "GENERAL" && photo.Retention != nil && photo.Retention.OK {
					t.Error("la retención insuficiente debía marcarse")
				}
			}
		})
	}
}

func TestExportNoSigueClavesAjenasDelManifiesto(t *testing.T) {
	f := newFixture(t)
	other := manifest.PhotoKey(uuid.NewString(), "GENERAL", 0)
	f.objects.Seed(other, []byte("foto de otra alerta"))
	tampered := f.record.Evidence
	tampered[0].Key = other
	body, _ := manifest.Marshal(manifest.Manifest{
		AlertID: f.id.String(), AlertType: "CRASHED", AlertCreatedAt: createdAt, DeliveredAt: *f.record.DeliveredAt,
		DNIEncAudit: "ZG5p", PatEncAudit: "cGF0", AuditKeyID: "2026-11", Evidence: tampered,
	})
	f.objects.Replace(manifest.ManifestKey(f.id.String()), body)

	summary, outDir := f.export(t)

	if len(summary.Discrepancies) != 1 {
		t.Fatalf("resumen = %+v", summary)
	}
	entries, _ := os.ReadDir(filepath.Join(outDir, f.id.String()))
	for _, entry := range entries {
		if raw, _ := os.ReadFile(filepath.Join(outDir, f.id.String(), entry.Name())); string(raw) == "foto de otra alerta" {
			t.Error("se exportó una foto de otra alerta")
		}
	}
}

func TestExportRechazaRolesConCaracteresDePath(t *testing.T) {
	f := newFixture(t)
	evil := []manifest.EvidenceItem{{Role: "../escape", Index: 0, Key: "records/x/y.jpg", SHA256: sha([]byte("x"))}}
	body, _ := manifest.Marshal(manifest.Manifest{
		AlertID: f.id.String(), AlertType: "CRASHED", AlertCreatedAt: createdAt, DeliveredAt: *f.record.DeliveredAt,
		DNIEncAudit: "ZG5p", PatEncAudit: "cGF0", AuditKeyID: "2026-11", Evidence: evil,
	})
	f.objects.Replace(manifest.ManifestKey(f.id.String()), body)

	summary, outDir := f.export(t)

	if len(summary.Discrepancies) != 1 {
		t.Fatalf("resumen = %+v", summary)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(outDir), "escape-0.jpg")); err == nil {
		t.Error("un rol con path escribió fuera del directorio de exportación")
	}
}

func TestExportOmiteLosRegistrosSinEntregar(t *testing.T) {
	f := newFixture(t)
	pending := domain.Record{AlertID: uuid.New(), Status: domain.StatusRecorded, DestroyAt: destroyAt}
	f.source.records = append(f.source.records, pending)

	summary, outDir := f.export(t)

	if summary.Exported != 1 || summary.Skipped != 1 {
		t.Fatalf("resumen = %+v", summary)
	}
	if _, err := os.Stat(filepath.Join(outDir, pending.AlertID.String())); err == nil {
		t.Error("un registro sin entregar no tiene manifiesto que exportar")
	}
}

func TestExportRechazaUnDirectorioDentroDeUnRepositorio(t *testing.T) {
	f := newFixture(t)
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}

	_, err := New(f.source, f.objects).Export(context.Background(), domain.ExportFilter{AlertID: &f.id}, filepath.Join(repo, "export"))

	if err == nil {
		t.Fatal("esperaba error: la exportación contiene material sensible")
	}
	if _, statErr := os.Stat(filepath.Join(repo, "export")); statErr == nil {
		t.Error("no debe crear el directorio dentro del repo")
	}
}

func TestExportNoIncluyeCriptogramasEnElInforme(t *testing.T) {
	f := newFixture(t)

	_, outDir := f.export(t)

	raw, _ := os.ReadFile(filepath.Join(outDir, f.id.String(), ReportFileName))
	for _, secret := range []string{"ZG5p", "cGF0"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("el informe refleja un criptograma (%q)", secret)
		}
	}
}
