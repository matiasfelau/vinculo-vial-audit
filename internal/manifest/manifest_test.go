package manifest

import (
	"strings"
	"testing"
	"time"
)

func sample() Manifest {
	return Manifest{
		AlertID:        "0b8a6c5e-1f56-4e0b-9d63-4f6b8f0f2c11",
		AlertType:      "CRASHED",
		AlertCreatedAt: time.Date(2026, 11, 4, 10, 0, 0, 0, time.FixedZone("ART", -3*3600)),
		DeliveredAt:    time.Date(2026, 11, 4, 11, 0, 0, 0, time.UTC),
		DNIEncAudit:    "ZG5p",
		PatEncAudit:    "cGF0",
		AuditKeyID:     "2026-11",
		Evidence:       []EvidenceItem{{Role: "GENERAL", Index: 0, Key: "records/x/GENERAL-0.jpg", SHA256: strings.Repeat("a", 64)}},
	}
}

func TestMarshalEsDeterministaYNormalizaAUTC(t *testing.T) {
	first, err := Marshal(sample())
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	second, _ := Marshal(sample())

	if string(first) != string(second) {
		t.Error("los mismos datos deben producir los mismos bytes")
	}
	if !strings.Contains(string(first), `"alert_created_at":"2026-11-04T13:00:00Z"`) {
		t.Errorf("los instantes deben normalizarse a UTC: %s", first)
	}
}

func TestMarshalUsaLosNombresDeCampoDelContrato(t *testing.T) {
	body, _ := Marshal(sample())

	for _, field := range []string{"alert_id", "alert_type", "alert_created_at", "delivered_at", "dni_enc_audit", "pat_enc_audit", "audit_key_id", "evidence", "role", "index", "key", "sha256"} {
		if !strings.Contains(string(body), `"`+field+`"`) {
			t.Errorf("falta el campo %q: %s", field, body)
		}
	}
}

func TestParseIdaYVuelta(t *testing.T) {
	body, _ := Marshal(sample())

	parsed, err := Parse(body)

	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	original := sample()
	if parsed.AlertID != original.AlertID || parsed.DNIEncAudit != original.DNIEncAudit || len(parsed.Evidence) != 1 {
		t.Errorf("manifiesto = %+v", parsed)
	}
	if !parsed.AlertCreatedAt.Equal(original.AlertCreatedAt) {
		t.Errorf("alert_created_at = %v", parsed.AlertCreatedAt)
	}
}

func TestParseRechazaDocumentosQueNoEscribioAudit(t *testing.T) {
	casos := map[string]string{
		"no es JSON":          "hola",
		"campo desconocido":   `{"alert_id":"a","extra":1}`,
		"contenido posterior": `{"alert_id":"a"}{"alert_id":"b"}`,
		"sin alert_id":        `{"alert_type":"CRASHED"}`,
	}
	for nombre, body := range casos {
		t.Run(nombre, func(t *testing.T) {
			if _, err := Parse([]byte(body)); err == nil {
				t.Fatal("esperaba error")
			}
		})
	}
}

func TestMarshalSinEvidenciaSerializaListaVacia(t *testing.T) {
	m := sample()
	m.Evidence = nil

	body, _ := Marshal(m)

	if !strings.Contains(string(body), `"evidence":[]`) {
		t.Errorf("la evidencia debe ser [] y no null: %s", body)
	}
}

func TestClavesDeObjeto(t *testing.T) {
	id := "0b8a6c5e-1f56-4e0b-9d63-4f6b8f0f2c11"

	if got := PhotoKey(id, "PLATE", 2); got != "records/"+id+"/PLATE-2.jpg" {
		t.Errorf("PhotoKey = %q", got)
	}
	if got := ManifestKey(id); got != "records/"+id+"/manifest.json" {
		t.Errorf("ManifestKey = %q", got)
	}
	if got := RecordPrefix(id); got != "records/"+id+"/" {
		t.Errorf("RecordPrefix = %q", got)
	}
}

func TestValidRole(t *testing.T) {
	for _, role := range []string{"GENERAL", "PLATE", "detail", "ctx_1"} {
		if !ValidRole(role) {
			t.Errorf("%q debía ser válido", role)
		}
	}
	for _, role := range []string{"", "a-b", "../x", "a/b", "1abc", "con espacio", strings.Repeat("a", 33)} {
		if ValidRole(role) {
			t.Errorf("%q debía ser inválido", role)
		}
	}
}
