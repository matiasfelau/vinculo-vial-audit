package open

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/matiasfelau/vinculo-vial-audit/internal/auditcrypto"
	"github.com/matiasfelau/vinculo-vial-audit/internal/manifest"
	"github.com/matiasfelau/vinculo-vial-audit/internal/opener"
)

const (
	keyID   = "2026-11"
	dniTest = "30123456"
	patTest = "AB123CD"
)

type keys struct {
	privateB64 string
	publicB64  string
}

func newKeys(t *testing.T) keys {
	t.Helper()
	private, public, err := auditcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return keys{privateB64: base64.StdEncoding.EncodeToString(private), publicB64: base64.StdEncoding.EncodeToString(public)}
}

// stdin arma las claves privadas en el formato audit_key_id=base64.
func (k keys) stdin() *strings.Reader {
	return strings.NewReader(keyID + "=" + k.privateB64 + "\n")
}

// writeManifest escribe exportDir/{alertID}/manifest.json con los criptogramas
// sellados hacia k, como lo harían Identity y Vehicle.
func writeManifest(t *testing.T, exportDir, alertID string, k keys, mutate func(*manifest.Manifest)) {
	t.Helper()

	dni, err := auditcrypto.Seal(k.publicB64, []byte(dniTest), auditcrypto.InfoDNI(alertID))
	if err != nil {
		t.Fatal(err)
	}
	pat, err := auditcrypto.Seal(k.publicB64, []byte(patTest), auditcrypto.InfoPat(alertID))
	if err != nil {
		t.Fatal(err)
	}

	m := manifest.Manifest{
		AlertID:        alertID,
		AlertType:      "CRASHED",
		AlertCreatedAt: time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC),
		DeliveredAt:    time.Date(2026, 11, 4, 11, 0, 0, 0, time.UTC),
		DNIEncAudit:    dni,
		PatEncAudit:    pat,
		AuditKeyID:     keyID,
		Evidence:       []manifest.EvidenceItem{},
	}
	if mutate != nil {
		mutate(&m)
	}

	body, err := manifest.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(exportDir, alertID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, manifest.ManifestFileName), body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readOutput(t *testing.T, path string) []opener.Record {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no se escribió la salida: %v", err)
	}
	var records []opener.Record
	if err := json.Unmarshal(raw, &records); err != nil {
		t.Fatalf("salida ilegible: %v", err)
	}
	return records
}

func TestIdaYVueltaAbreElDNIYLaPatente(t *testing.T) {
	k := newKeys(t)
	exportDir := t.TempDir()
	alertID := "0b8a6c5e-1f56-4e0b-9d63-4f6b8f0f2c11"
	writeManifest(t, exportDir, alertID, k, nil)
	out := filepath.Join(t.TempDir(), "abierto.json")
	var stdout, stderr bytes.Buffer

	code := Run([]string{"-in", exportDir, "-out", out}, k.stdin(), &stdout, &stderr)

	if code != exitOK {
		t.Fatalf("código = %d, stderr: %s", code, stderr.String())
	}
	records := readOutput(t, out)
	if len(records) != 1 || records[0].AlertID != alertID || records[0].DNI != dniTest || records[0].Patente != patTest {
		t.Errorf("registros abiertos = %+v", records)
	}
	for _, secret := range []string{dniTest, patTest, k.privateB64} {
		if strings.Contains(stdout.String(), secret) || strings.Contains(stderr.String(), secret) {
			t.Errorf("nunca debe imprimir datos abiertos ni claves (apareció %q)", secret)
		}
	}
}

func TestAbreVariosRegistrosYVariasClaves(t *testing.T) {
	old, current := newKeys(t), newKeys(t)
	exportDir := t.TempDir()
	first, second := "0b8a6c5e-1f56-4e0b-9d63-4f6b8f0f2c11", "1c9b7d6f-2a67-4f1c-8e74-5a7c9a1a3d22"
	writeManifest(t, exportDir, first, old, func(m *manifest.Manifest) { m.AuditKeyID = "2025-11" })
	writeManifest(t, exportDir, second, current, nil)
	out := filepath.Join(t.TempDir(), "abierto.json")
	stdin := strings.NewReader("2025-11=" + old.privateB64 + "\n\n" + keyID + "=" + current.privateB64 + "\n")
	var stdout, stderr bytes.Buffer

	code := Run([]string{"-in", exportDir, "-out", out}, stdin, &stdout, &stderr)

	if code != exitOK {
		t.Fatalf("código = %d, stderr: %s", code, stderr.String())
	}
	if records := readOutput(t, out); len(records) != 2 {
		t.Errorf("abrió %d registros, esperaba 2 (rotación de claves por audit_key_id)", len(records))
	}
}

func TestUnAlertIDDistintoEnElManifiestoFallaLaApertura(t *testing.T) {
	k := newKeys(t)
	exportDir := t.TempDir()
	sealedFor := "0b8a6c5e-1f56-4e0b-9d63-4f6b8f0f2c11"
	movedTo := "ffffffff-2a67-4f1c-8e74-5a7c9a1a3d22"
	// Los criptogramas se sellaron para otra alerta y se movieron a este registro.
	writeManifest(t, exportDir, sealedFor, k, nil)
	moved := readManifest(t, exportDir, sealedFor)
	moved.AlertID = movedTo
	writeRaw(t, exportDir, movedTo, moved)
	if err := os.RemoveAll(filepath.Join(exportDir, sealedFor)); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "abierto.json")
	var stdout, stderr bytes.Buffer

	code := Run([]string{"-in", exportDir, "-out", out}, k.stdin(), &stdout, &stderr)

	if code != exitPartial {
		t.Fatalf("código = %d, esperaba %d", code, exitPartial)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("sin registros abiertos no debe escribirse la salida")
	}
	if strings.Contains(stderr.String(), dniTest) || strings.Contains(stderr.String(), patTest) {
		t.Error("el error no debe reflejar datos")
	}
}

func TestElDNIIntercambiadoConLaPatenteFallaLaApertura(t *testing.T) {
	k := newKeys(t)
	exportDir := t.TempDir()
	alertID := "0b8a6c5e-1f56-4e0b-9d63-4f6b8f0f2c11"
	writeManifest(t, exportDir, alertID, k, func(m *manifest.Manifest) { m.DNIEncAudit, m.PatEncAudit = m.PatEncAudit, m.DNIEncAudit })
	out := filepath.Join(t.TempDir(), "abierto.json")
	var stdout, stderr bytes.Buffer

	code := Run([]string{"-in", exportDir, "-out", out}, k.stdin(), &stdout, &stderr)

	if code != exitPartial {
		t.Fatalf("código = %d, esperaba %d", code, exitPartial)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("no debe escribirse un registro cuyos criptogramas están intercambiados")
	}
}

func TestUnManifiestoAlteradoNoSeAbre(t *testing.T) {
	k := newKeys(t)
	exportDir := t.TempDir()
	alertID := "0b8a6c5e-1f56-4e0b-9d63-4f6b8f0f2c11"
	writeManifest(t, exportDir, alertID, k, func(m *manifest.Manifest) {
		raw := []byte(m.DNIEncAudit)
		raw[len(raw)-6] ^= 1
		m.DNIEncAudit = string(raw)
	})
	var stdout, stderr bytes.Buffer

	code := Run([]string{"-in", exportDir, "-out", filepath.Join(t.TempDir(), "x.json")}, k.stdin(), &stdout, &stderr)

	if code != exitPartial {
		t.Fatalf("código = %d, esperaba %d", code, exitPartial)
	}
}

func TestSinLaClaveDelAuditKeyIDInformaLaFalla(t *testing.T) {
	k := newKeys(t)
	exportDir := t.TempDir()
	writeManifest(t, exportDir, "0b8a6c5e-1f56-4e0b-9d63-4f6b8f0f2c11", k, func(m *manifest.Manifest) { m.AuditKeyID = "2030-01" })
	var stdout, stderr bytes.Buffer

	code := Run([]string{"-in", exportDir, "-out", filepath.Join(t.TempDir(), "x.json")}, k.stdin(), &stdout, &stderr)

	if code != exitPartial {
		t.Fatalf("código = %d, esperaba %d", code, exitPartial)
	}
	if !strings.Contains(stderr.String(), "no hay clave privada") {
		t.Errorf("stderr = %s", stderr.String())
	}
}

func TestOtraClavePrivadaNoAbreNada(t *testing.T) {
	sealer, stranger := newKeys(t), newKeys(t)
	exportDir := t.TempDir()
	writeManifest(t, exportDir, "0b8a6c5e-1f56-4e0b-9d63-4f6b8f0f2c11", sealer, nil)
	var stdout, stderr bytes.Buffer

	code := Run([]string{"-in", exportDir, "-out", filepath.Join(t.TempDir(), "x.json")}, stranger.stdin(), &stdout, &stderr)

	if code != exitPartial {
		t.Fatalf("código = %d, esperaba %d", code, exitPartial)
	}
}

func TestRechazaUnaSalidaDentroDeUnRepositorioSinLeerLasClaves(t *testing.T) {
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(repo, "abierto.json")
	var stdout, stderr bytes.Buffer

	code := Run([]string{"-in", t.TempDir(), "-out", out}, strings.NewReader(""), &stdout, &stderr)

	if code != exitError {
		t.Fatalf("código = %d, esperaba %d", code, exitError)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("no debe escribir datos abiertos dentro de un repositorio")
	}
}

func TestNoSobrescribeUnaSalidaExistente(t *testing.T) {
	k := newKeys(t)
	exportDir := t.TempDir()
	writeManifest(t, exportDir, "0b8a6c5e-1f56-4e0b-9d63-4f6b8f0f2c11", k, nil)
	out := filepath.Join(t.TempDir(), "abierto.json")
	if err := os.WriteFile(out, []byte("previo"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer

	code := Run([]string{"-in", exportDir, "-out", out}, k.stdin(), &stdout, &stderr)

	if code != exitError {
		t.Fatalf("código = %d, esperaba %d", code, exitError)
	}
	if got, _ := os.ReadFile(out); string(got) != "previo" {
		t.Error("se sobrescribió la salida existente")
	}
}

func TestEntradasInvalidas(t *testing.T) {
	k := newKeys(t)
	exportDir := t.TempDir()
	writeManifest(t, exportDir, "0b8a6c5e-1f56-4e0b-9d63-4f6b8f0f2c11", k, nil)
	out := func() string { return filepath.Join(t.TempDir(), "x.json") }

	casos := map[string]struct {
		args  []string
		stdin string
		want  int
	}{
		"sin -in ni -out":                   {nil, k.privateB64, exitUsage},
		"sin -out":                          {[]string{"-in", exportDir}, k.privateB64, exitUsage},
		"sin claves por stdin":              {[]string{"-in", exportDir, "-out", out()}, "", exitError},
		"línea sin formato id=base64":       {[]string{"-in", exportDir, "-out", out()}, k.privateB64 + "\n", exitError},
		"clave privada inválida":            {[]string{"-in", exportDir, "-out", out()}, keyID + "=***\n", exitError},
		"audit_key_id repetido":             {[]string{"-in", exportDir, "-out", out()}, keyID + "=" + k.privateB64 + "\n" + keyID + "=" + k.privateB64 + "\n", exitError},
		"directorio de entrada sin datos":   {[]string{"-in", t.TempDir(), "-out", out()}, keyID + "=" + k.privateB64 + "\n", exitError},
		"directorio de entrada inexistente": {[]string{"-in", filepath.Join(t.TempDir(), "no"), "-out", out()}, keyID + "=" + k.privateB64 + "\n", exitError},
	}
	for nombre, c := range casos {
		t.Run(nombre, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := Run(c.args, strings.NewReader(c.stdin), &stdout, &stderr)

			if code != c.want {
				t.Fatalf("código = %d, esperaba %d (stderr: %s)", code, c.want, stderr.String())
			}
			if strings.Contains(stderr.String(), k.privateB64) {
				t.Error("el error no debe reflejar la clave privada")
			}
		})
	}
}

func readManifest(t *testing.T, exportDir, alertID string) manifest.Manifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(exportDir, alertID, manifest.ManifestFileName))
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func writeRaw(t *testing.T, exportDir, alertID string, m manifest.Manifest) {
	t.Helper()
	body, err := manifest.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(exportDir, alertID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, manifest.ManifestFileName), body, 0o600); err != nil {
		t.Fatal(err)
	}
}
