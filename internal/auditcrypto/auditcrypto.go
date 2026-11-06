// Package auditcrypto implementa la criptografía de las CLIs de Audit: generar el
// par de claves X25519 y abrir los criptogramas dni_enc_audit y pat_enc_audit.
// Solo lo importan audit-keygen, audit-open y los tests: el servicio nunca
// descifra ni carga claves privadas.
//
// El esquema es HPKE (RFC 9180) en modo base: DHKEM(X25519, HKDF-SHA256) /
// HKDF-SHA256 / AES-256-GCM. El criptograma es base64 estándar de enc‖ct.
package auditcrypto

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/hpke"
)

const (
	kemID  = hpke.KEM_X25519_HKDF_SHA256
	kdfID  = hpke.KDF_HKDF_SHA256
	aeadID = hpke.AEAD_AES256GCM

	infoPrefixDNI = "vv-audit:dni:"
	infoPrefixPat = "vv-audit:pat:"
)

// ErrOpen indica que un criptograma no pudo abrirse: clave incorrecta, criptograma
// alterado, o info distinto (otro alert_id, o DNI y patente intercambiados). No
// distingue las causas ni refleja el contenido.
var ErrOpen = errors.New("auditcrypto: no se pudo abrir el criptograma")

// InfoDNI devuelve el info HPKE que ata el DNI a su alerta.
func InfoDNI(alertID string) []byte { return []byte(infoPrefixDNI + alertID) }

// InfoPat devuelve el info HPKE que ata la patente a su alerta.
func InfoPat(alertID string) []byte { return []byte(infoPrefixPat + alertID) }

// GenerateKeyPair genera un par X25519 y devuelve la clave privada y la pública,
// ambas en bytes crudos.
func GenerateKeyPair() (private, public []byte, err error) {
	pub, priv, err := kemID.Scheme().GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("auditcrypto: no se pudo generar el par de claves: %w", err)
	}
	private, err = priv.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("auditcrypto: no se pudo serializar la clave privada: %w", err)
	}
	public, err = pub.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("auditcrypto: no se pudo serializar la clave pública: %w", err)
	}
	return private, public, nil
}

// Opener abre criptogramas con una clave privada.
type Opener struct {
	suite      hpke.Suite
	privateKey []byte
}

// NewOpener construye un Opener a partir de la clave privada en base64 estándar.
// El error no refleja la clave.
func NewOpener(privateKeyBase64 string) (*Opener, error) {
	raw, err := base64.StdEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		return nil, errors.New("auditcrypto: la clave privada no es base64")
	}
	if _, err := kemID.Scheme().UnmarshalBinaryPrivateKey(raw); err != nil {
		return nil, errors.New("auditcrypto: clave privada inválida")
	}
	return &Opener{suite: hpke.NewSuite(kemID, kdfID, aeadID), privateKey: raw}, nil
}

// Open abre el criptograma (base64 estándar de enc‖ct) atado a info y devuelve el
// texto en claro.
func (o *Opener) Open(ciphertextBase64 string, info []byte) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return nil, ErrOpen
	}

	encSize := kemID.Scheme().CiphertextSize()
	if len(raw) <= encSize {
		return nil, ErrOpen
	}
	enc, sealed := raw[:encSize], raw[encSize:]

	privateKey, err := kemID.Scheme().UnmarshalBinaryPrivateKey(o.privateKey)
	if err != nil {
		return nil, ErrOpen
	}
	receiver, err := o.suite.NewReceiver(privateKey, info)
	if err != nil {
		return nil, ErrOpen
	}
	opener, err := receiver.Setup(enc)
	if err != nil {
		return nil, ErrOpen
	}
	plaintext, err := opener.Open(sealed, nil)
	if err != nil {
		return nil, ErrOpen
	}
	return plaintext, nil
}

// Seal cifra plaintext hacia la clave pública (base64 estándar) atado a info y
// devuelve el criptograma en base64 estándar de enc‖ct. Lo usan los tests para
// reproducir lo que sellan Identity y Vehicle; el servicio no lo invoca.
func Seal(publicKeyBase64 string, plaintext, info []byte) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return "", errors.New("auditcrypto: la clave pública no es base64")
	}
	publicKey, err := kemID.Scheme().UnmarshalBinaryPublicKey(raw)
	if err != nil {
		return "", errors.New("auditcrypto: clave pública inválida")
	}

	suite := hpke.NewSuite(kemID, kdfID, aeadID)
	sender, err := suite.NewSender(publicKey, info)
	if err != nil {
		return "", fmt.Errorf("auditcrypto: no se pudo inicializar el emisor: %w", err)
	}
	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("auditcrypto: no se pudo completar el establecimiento HPKE: %w", err)
	}
	sealed, err := sealer.Seal(plaintext, nil)
	if err != nil {
		return "", fmt.Errorf("auditcrypto: no se pudo sellar: %w", err)
	}
	return base64.StdEncoding.EncodeToString(append(enc, sealed...)), nil
}
