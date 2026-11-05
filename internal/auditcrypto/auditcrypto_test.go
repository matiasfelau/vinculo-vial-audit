package auditcrypto

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

const alertID = "0b8a6c5e-1f56-4e0b-9d63-4f6b8f0f2c11"

func newPair(t *testing.T) (privateB64, publicB64 string) {
	t.Helper()
	private, public, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("no se pudo generar el par: %v", err)
	}
	return base64.StdEncoding.EncodeToString(private), base64.StdEncoding.EncodeToString(public)
}

func TestSellarYAbrirConElInfoDelCampo(t *testing.T) {
	privateB64, publicB64 := newPair(t)
	opener, err := NewOpener(privateB64)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}

	for nombre, c := range map[string]struct {
		plaintext string
		info      []byte
	}{
		"dni":     {"30123456", InfoDNI(alertID)},
		"patente": {"AB123CD", InfoPat(alertID)},
	} {
		t.Run(nombre, func(t *testing.T) {
			sealed, err := Seal(publicB64, []byte(c.plaintext), c.info)
			if err != nil {
				t.Fatalf("no se pudo sellar: %v", err)
			}

			got, err := opener.Open(sealed, c.info)

			if err != nil {
				t.Fatalf("no se pudo abrir: %v", err)
			}
			if string(got) != c.plaintext {
				t.Errorf("abrió %q, esperaba %q", got, c.plaintext)
			}
		})
	}
}

func TestLaAperturaFallaSiElInfoNoCoincide(t *testing.T) {
	privateB64, publicB64 := newPair(t)
	opener, _ := NewOpener(privateB64)
	sealedDNI, _ := Seal(publicB64, []byte("30123456"), InfoDNI(alertID))

	casos := map[string][]byte{
		"otro alert_id":                 InfoDNI("ffffffff-1f56-4e0b-9d63-4f6b8f0f2c11"),
		"DNI abierto como patente":      InfoPat(alertID),
		"info vacío":                    nil,
		"prefijo correcto sin alert_id": []byte("vv-audit:dni:"),
	}
	for nombre, info := range casos {
		t.Run(nombre, func(t *testing.T) {
			if _, err := opener.Open(sealedDNI, info); !errors.Is(err, ErrOpen) {
				t.Fatalf("esperaba ErrOpen, obtuvo %v", err)
			}
		})
	}
}

func TestLaAperturaFallaConOtraClave(t *testing.T) {
	_, publicB64 := newPair(t)
	otherPrivate, _ := newPair(t)
	other, _ := NewOpener(otherPrivate)
	sealed, _ := Seal(publicB64, []byte("30123456"), InfoDNI(alertID))

	if _, err := other.Open(sealed, InfoDNI(alertID)); !errors.Is(err, ErrOpen) {
		t.Fatalf("esperaba ErrOpen, obtuvo %v", err)
	}
}

func TestLaAperturaFallaConCriptogramasInvalidos(t *testing.T) {
	privateB64, publicB64 := newPair(t)
	opener, _ := NewOpener(privateB64)
	sealed, _ := Seal(publicB64, []byte("30123456"), InfoDNI(alertID))
	raw, _ := base64.StdEncoding.DecodeString(sealed)
	raw[len(raw)-1] ^= 0xff

	casos := map[string]string{
		"vacío":           "",
		"no es base64":    "***",
		"demasiado corto": base64.StdEncoding.EncodeToString([]byte("corto")),
		"alterado":        base64.StdEncoding.EncodeToString(raw),
	}
	for nombre, ciphertext := range casos {
		t.Run(nombre, func(t *testing.T) {
			if _, err := opener.Open(ciphertext, InfoDNI(alertID)); !errors.Is(err, ErrOpen) {
				t.Fatalf("esperaba ErrOpen, obtuvo %v", err)
			}
		})
	}
}

func TestNewOpenerRechazaClavesInvalidasSinReflejarlas(t *testing.T) {
	casos := map[string]string{
		"no es base64":     "***secreto***",
		"largo incorrecto": base64.StdEncoding.EncodeToString([]byte("corta")),
	}
	for nombre, key := range casos {
		t.Run(nombre, func(t *testing.T) {
			_, err := NewOpener(key)
			if err == nil {
				t.Fatal("esperaba error")
			}
			if strings.Contains(err.Error(), key) {
				t.Errorf("el error refleja la clave: %v", err)
			}
		})
	}
}

func TestSealRechazaClavesPublicasInvalidas(t *testing.T) {
	if _, err := Seal("***", []byte("x"), nil); err == nil {
		t.Error("esperaba error con una clave pública que no es base64")
	}
	if _, err := Seal(base64.StdEncoding.EncodeToString([]byte("corta")), []byte("x"), nil); err == nil {
		t.Error("esperaba error con una clave pública de largo incorrecto")
	}
}

func TestInfoSigueElContrato(t *testing.T) {
	if string(InfoDNI("abc")) != "vv-audit:dni:abc" || string(InfoPat("abc")) != "vv-audit:pat:abc" {
		t.Error("el info HPKE debe ser vv-audit:dni:<alert_id> y vv-audit:pat:<alert_id>")
	}
}
