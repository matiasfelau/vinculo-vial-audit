package keygen

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/matiasfelau/vinculo-vial-audit/internal/auditcrypto"
)

func TestGeneraElParEscribeLaPrivadaEImprimeLaPublica(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "audit", "private.key")
	var stdout, stderr bytes.Buffer

	code := Run([]string{"-out", keyPath}, &stdout, &stderr)

	if code != exitOK {
		t.Fatalf("código = %d, stderr: %s", code, stderr.String())
	}
	privateRaw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("no se escribió la clave privada: %v", err)
	}
	privateB64 := strings.TrimSpace(string(privateRaw))
	publicB64 := strings.TrimSpace(stdout.String())

	opener, err := auditcrypto.NewOpener(privateB64)
	if err != nil {
		t.Fatalf("la clave privada escrita no es válida: %v", err)
	}
	sealed, err := auditcrypto.Seal(publicB64, []byte("30123456"), auditcrypto.InfoDNI("a"))
	if err != nil {
		t.Fatalf("la clave pública impresa no es válida: %v", err)
	}
	if got, err := opener.Open(sealed, auditcrypto.InfoDNI("a")); err != nil || string(got) != "30123456" {
		t.Errorf("el par generado no es coherente: %q, %v", got, err)
	}
	if strings.Contains(stdout.String(), privateB64) || strings.Contains(stderr.String(), privateB64) {
		t.Error("la clave privada no debe imprimirse")
	}
	if raw, _ := base64.StdEncoding.DecodeString(publicB64); len(raw) != 32 {
		t.Errorf("la clave pública mide %d bytes, esperaba 32 (X25519)", len(raw))
	}
}

func TestRechazaUnaRutaDentroDeUnRepositorio(t *testing.T) {
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(repo, "keys", "private.key")
	var stdout, stderr bytes.Buffer

	code := Run([]string{"-out", keyPath}, &stdout, &stderr)

	if code != exitError {
		t.Fatalf("código = %d, esperaba %d", code, exitError)
	}
	if _, err := os.Stat(keyPath); err == nil {
		t.Error("no debe escribir la clave privada dentro de un repositorio")
	}
	if stdout.Len() != 0 {
		t.Errorf("no debe imprimir la clave pública si no pudo guardar la privada: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "repositorio git") {
		t.Errorf("el error debe explicar el motivo: %s", stderr.String())
	}
}

func TestNoSobrescribeUnaClaveExistente(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "private.key")
	if err := os.WriteFile(keyPath, []byte("clave previa"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer

	code := Run([]string{"-out", keyPath}, &stdout, &stderr)

	if code != exitError {
		t.Fatalf("código = %d, esperaba %d", code, exitError)
	}
	if got, _ := os.ReadFile(keyPath); string(got) != "clave previa" {
		t.Error("se sobrescribió una clave existente")
	}
}

func TestSinOutEsUsoIncorrecto(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if code := Run(nil, &stdout, &stderr); code != exitUsage {
		t.Fatalf("código = %d, esperaba %d", code, exitUsage)
	}
}

func TestDosEjecucionesGeneranClavesDistintas(t *testing.T) {
	dir := t.TempDir()
	var first, second bytes.Buffer
	var discard bytes.Buffer

	Run([]string{"-out", filepath.Join(dir, "a.key")}, &first, &discard)
	Run([]string{"-out", filepath.Join(dir, "b.key")}, &second, &discard)

	if first.String() == second.String() {
		t.Error("dos ejecuciones no pueden producir la misma clave")
	}
}
