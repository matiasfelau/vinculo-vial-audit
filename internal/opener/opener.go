// Package opener abre, fuera de línea, los criptogramas de los manifiestos de una
// exportación de auditctl. Lo usa audit-open, que no puede importar paquetes de
// red, base de datos ni AWS: este paquete depende solo de la biblioteca estándar,
// de auditcrypto y de manifest.
package opener

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/matiasfelau/vinculo-vial-audit/internal/auditcrypto"
	"github.com/matiasfelau/vinculo-vial-audit/internal/manifest"
)

const (
	// maxManifestBytes acota el tamaño de un manifiesto leído del disco.
	maxManifestBytes = 1 << 20

	// maxKeyLineBytes acota el largo de una línea audit_key_id=base64 de stdin.
	maxKeyLineBytes = 4096

	keySeparator = "="
)

// Motivos de falla: textos fijos, que nunca reflejan el contenido de los datos.
const (
	reasonManifestUnreadable = "manifest.json ilegible"
	reasonInvalidAlertID     = "alert_id inválido"
	reasonUnknownKey         = "no hay clave privada para el audit_key_id del manifiesto"
	reasonCannotOpenDNI      = "no se pudo abrir el DNI"
	reasonCannotOpenPat      = "no se pudo abrir la patente"
)

var (
	// uuidPattern valida el alert_id del manifiesto sin importar paquetes de red
	// (github.com/google/uuid importa net).
	uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

	keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)
)

// Record es un registro abierto.
type Record struct {
	AlertID string `json:"alert_id"`
	DNI     string `json:"dni"`
	Patente string `json:"patente"`
}

// Failure es un manifiesto que no pudo abrirse. Dir es el directorio del
// registro en la exportación; no contiene datos sensibles.
type Failure struct {
	Dir    string
	Reason string
}

// ReadKeys lee las claves privadas del formato audit_key_id=base64, una por
// línea (las líneas vacías se ignoran). Devuelve un Opener por audit_key_id. Los
// errores no reflejan las claves.
func ReadKeys(r io.Reader) (map[string]*auditcrypto.Opener, error) {
	keys := make(map[string]*auditcrypto.Opener)

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, maxKeyLineBytes), maxKeyLineBytes)

	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		id, key, found := strings.Cut(line, keySeparator)
		if !found || !keyIDPattern.MatchString(id) || key == "" {
			return nil, fmt.Errorf("línea %d: se esperaba audit_key_id=base64", lineNumber)
		}
		if _, dup := keys[id]; dup {
			return nil, fmt.Errorf("línea %d: audit_key_id repetido", lineNumber)
		}

		opener, err := auditcrypto.NewOpener(key)
		if err != nil {
			return nil, fmt.Errorf("línea %d: %w", lineNumber, err)
		}
		keys[id] = opener
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("no se pudieron leer las claves: %w", err)
	}
	if len(keys) == 0 {
		return nil, errors.New("no se recibió ninguna clave privada por stdin")
	}
	return keys, nil
}

// OpenDir abre todos los manifiestos de una exportación: el manifest.json de cada
// subdirectorio de dir (o el del propio dir, si lo tiene). Devuelve los registros
// abiertos y las fallas, y falla solo si no puede leer dir o no encuentra ningún
// manifiesto.
func OpenDir(dir string, keys map[string]*auditcrypto.Opener) ([]Record, []Failure, error) {
	manifestDirs, err := findManifestDirs(dir)
	if err != nil {
		return nil, nil, err
	}
	if len(manifestDirs) == 0 {
		return nil, nil, errors.New("no se encontró ningún manifest.json en el directorio de entrada")
	}

	var records []Record
	var failures []Failure
	for _, manifestDir := range manifestDirs {
		record, reason := openOne(manifestDir, keys)
		if reason != "" {
			failures = append(failures, Failure{Dir: filepath.Base(manifestDir), Reason: reason})
			continue
		}
		records = append(records, record)
	}
	return records, failures, nil
}

// findManifestDirs devuelve los directorios que contienen un manifest.json.
func findManifestDirs(dir string) ([]string, error) {
	if hasManifest(dir) {
		return []string{dir}, nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("no se pudo leer el directorio de entrada: %w", err)
	}

	var dirs []string
	for _, entry := range entries {
		candidate := filepath.Join(dir, entry.Name())
		if entry.IsDir() && hasManifest(candidate) {
			dirs = append(dirs, candidate)
		}
	}
	return dirs, nil
}

func hasManifest(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, manifest.ManifestFileName))
	return err == nil && info.Mode().IsRegular()
}

// openOne abre el manifiesto de manifestDir. Devuelve el registro, o el motivo
// de falla.
func openOne(manifestDir string, keys map[string]*auditcrypto.Opener) (Record, string) {
	body, err := readLimited(filepath.Join(manifestDir, manifest.ManifestFileName))
	if err != nil {
		return Record{}, reasonManifestUnreadable
	}
	m, err := manifest.Parse(body)
	if err != nil {
		return Record{}, reasonManifestUnreadable
	}
	if !uuidPattern.MatchString(m.AlertID) {
		return Record{}, reasonInvalidAlertID
	}

	key, ok := keys[m.AuditKeyID]
	if !ok {
		return Record{}, reasonUnknownKey
	}

	// El info ata cada criptograma a su alerta y a su campo: si el manifiesto se
	// movió a otro registro, o el DNI y la patente se intercambiaron, la apertura
	// falla.
	dni, err := key.Open(m.DNIEncAudit, auditcrypto.InfoDNI(m.AlertID))
	if err != nil {
		return Record{}, reasonCannotOpenDNI
	}
	pat, err := key.Open(m.PatEncAudit, auditcrypto.InfoPat(m.AlertID))
	if err != nil {
		return Record{}, reasonCannotOpenPat
	}

	return Record{AlertID: m.AlertID, DNI: string(dni), Patente: string(pat)}, ""
}

// readLimited lee un archivo de hasta maxManifestBytes.
func readLimited(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	body, err := io.ReadAll(io.LimitReader(file, maxManifestBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxManifestBytes {
		return nil, errors.New("manifiesto demasiado grande")
	}
	return body, nil
}
