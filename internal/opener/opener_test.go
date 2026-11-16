package opener

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/matiasfelau/vinculo-vial-audit/internal/auditcrypto"
	"github.com/matiasfelau/vinculo-vial-audit/internal/manifest"
)

const (
	testKeyID  = "2026-11"
	testAlert  = "7d9c3f4e-1a2b-4c3d-8e5f-6a7b8c9d0e1f"
	testDNI    = "30123456"
	testPlaca  = "AB123CD"
	secretoLog = "no-debe-aparecer"
)

func nuevaClave(t *testing.T) (privada, publica string) {
	t.Helper()
	priv, pub, err := auditcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub)
}

// escribirManifiesto escribe dir/manifest.json con el cuerpo dado.
func escribirManifiesto(t *testing.T, dir string, cuerpo []byte) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, manifest.ManifestFileName), cuerpo, 0o600); err != nil {
		t.Fatal(err)
	}
}

func manifiestoSellado(t *testing.T, publica, alertID string) []byte {
	t.Helper()
	dni, err := auditcrypto.Seal(publica, []byte(testDNI), auditcrypto.InfoDNI(alertID))
	if err != nil {
		t.Fatal(err)
	}
	pat, err := auditcrypto.Seal(publica, []byte(testPlaca), auditcrypto.InfoPat(alertID))
	if err != nil {
		t.Fatal(err)
	}
	cuerpo, err := manifest.Marshal(manifest.Manifest{
		AlertID: alertID, AlertType: "CRASHED", AlertCreatedAt: time.Now(), DeliveredAt: time.Now(),
		DNIEncAudit: dni, PatEncAudit: pat, AuditKeyID: testKeyID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return cuerpo
}

func TestReadKeysRechazaLasLineasInvalidasSinReflejarLaClave(t *testing.T) {
	privada, _ := nuevaClave(t)
	casos := []struct {
		nombre  string
		entrada string
		esperar string
	}{
		{"sin separador", secretoLog + "\n", "línea 1: se esperaba audit_key_id=base64"},
		{"id con caracteres inválidos", "id con espacios=" + privada + "\n", "se esperaba audit_key_id=base64"},
		{"clave vacía", testKeyID + "=\n", "se esperaba audit_key_id=base64"},
		{"id repetido", testKeyID + "=" + privada + "\n" + testKeyID + "=" + privada + "\n", "línea 2: audit_key_id repetido"},
		{"clave que no es base64", testKeyID + "=" + secretoLog + "!!\n", "línea 1"},
		{"sin ninguna clave", "\n   \n", "no se recibió ninguna clave"},
		{"línea más larga que el tope", testKeyID + "=" + strings.Repeat(secretoLog, 500) + "\n", "no se pudieron leer las claves"},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			keys, err := ReadKeys(strings.NewReader(c.entrada))

			if err == nil {
				t.Fatalf("ReadKeys aceptó la entrada y devolvió %d claves", len(keys))
			}
			if !strings.Contains(err.Error(), c.esperar) {
				t.Errorf("error %q, esperaba que contuviera %q", err, c.esperar)
			}
			if strings.Contains(err.Error(), secretoLog) || strings.Contains(err.Error(), privada) {
				t.Errorf("el error refleja el contenido de la clave: %q", err)
			}
		})
	}
}

func TestReadKeysIgnoraLineasVaciasYDevuelveUnOpenerPorId(t *testing.T) {
	privada1, _ := nuevaClave(t)
	privada2, _ := nuevaClave(t)

	keys, err := ReadKeys(strings.NewReader("\n2026-11=" + privada1 + "\n\n   \n2026-12=" + privada2 + "\n"))

	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys["2026-11"] == nil || keys["2026-12"] == nil {
		t.Errorf("claves = %v, esperaba 2026-11 y 2026-12", keys)
	}
}

func TestOpenDirAbreElManifiestoDelPropioDirectorioYElDeSusSubdirectorios(t *testing.T) {
	privada, publica := nuevaClave(t)
	keys, err := ReadKeys(strings.NewReader(testKeyID + "=" + privada))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("el manifiesto está en el propio directorio", func(t *testing.T) {
		dir := t.TempDir()
		escribirManifiesto(t, dir, manifiestoSellado(t, publica, testAlert))

		records, failures, err := OpenDir(dir, keys)

		if err != nil || len(failures) != 0 || len(records) != 1 {
			t.Fatalf("records=%v failures=%v err=%v", records, failures, err)
		}
		if got := records[0]; got.AlertID != testAlert || got.DNI != testDNI || got.Patente != testPlaca {
			t.Errorf("registro abierto = %+v", got)
		}
	})

	t.Run("un subdirectorio por registro, ignorando lo que no tiene manifiesto", func(t *testing.T) {
		dir := t.TempDir()
		escribirManifiesto(t, filepath.Join(dir, testAlert), manifiestoSellado(t, publica, testAlert))
		if err := os.MkdirAll(filepath.Join(dir, "sin-manifiesto"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "suelto.txt"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}

		records, failures, err := OpenDir(dir, keys)

		if err != nil || len(failures) != 0 || len(records) != 1 {
			t.Fatalf("records=%v failures=%v err=%v", records, failures, err)
		}
	})
}

func TestOpenDirFallaSiNoPuedeLeerElDirectorioONoHayManifiestos(t *testing.T) {
	privada, _ := nuevaClave(t)
	keys, _ := ReadKeys(strings.NewReader(testKeyID + "=" + privada))

	if _, _, err := OpenDir(filepath.Join(t.TempDir(), "no-existe"), keys); err == nil {
		t.Error("OpenDir no falló con un directorio inexistente")
	}
	if _, _, err := OpenDir(t.TempDir(), keys); err == nil || !strings.Contains(err.Error(), "ningún manifest.json") {
		t.Errorf("error = %v, esperaba que informara que no hay manifiestos", err)
	}
}

// Una falla de un registro se informa con un motivo fijo y no corta a los demás.
func TestOpenDirInformaCadaFallaConUnMotivoFijoYSigueConLosDemas(t *testing.T) {
	privada, publica := nuevaClave(t)
	keys, _ := ReadKeys(strings.NewReader(testKeyID + "=" + privada))
	dir := t.TempDir()

	escribirManifiesto(t, filepath.Join(dir, "bueno"), manifiestoSellado(t, publica, testAlert))
	escribirManifiesto(t, filepath.Join(dir, "no-json"), []byte(secretoLog))
	escribirManifiesto(t, filepath.Join(dir, "enorme"), []byte(`{"alert_id":"`+strings.Repeat("a", maxManifestBytes)+`"}`))
	escribirManifiesto(t, filepath.Join(dir, "alert-invalido"), manifiestoSellado(t, publica, "no-es-un-uuid"))

	records, failures, err := OpenDir(dir, keys)

	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].AlertID != testAlert {
		t.Errorf("registros = %+v, esperaba solo el bueno", records)
	}
	motivos := map[string]string{}
	for _, f := range failures {
		motivos[f.Dir] = f.Reason
	}
	esperados := map[string]string{
		"no-json":        reasonManifestUnreadable,
		"enorme":         reasonManifestUnreadable,
		"alert-invalido": reasonInvalidAlertID,
	}
	for dir, motivo := range esperados {
		if motivos[dir] != motivo {
			t.Errorf("motivo de %s = %q, esperaba %q", dir, motivos[dir], motivo)
		}
	}
	for _, f := range failures {
		if strings.Contains(f.Reason, secretoLog) {
			t.Errorf("el motivo refleja el contenido del archivo: %q", f.Reason)
		}
	}
}
