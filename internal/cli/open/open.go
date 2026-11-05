// Package open implementa audit-open: abre, fuera de línea, los criptogramas de
// una exportación de auditctl con las claves privadas recibidas por stdin y
// escribe el resultado en un archivo fuera de cualquier repositorio. Nunca imprime
// ni loguea los datos abiertos. Depende solo de la biblioteca estándar y de
// paquetes locales sin red: un test lo verifica con go list -deps.
package open

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/matiasfelau/vinculo-vial-audit/internal/opener"
	"github.com/matiasfelau/vinculo-vial-audit/internal/pathguard"
)

// Códigos de salida.
const (
	exitOK      = 0
	exitError   = 1
	exitUsage   = 2
	exitPartial = 3
)

// outputIndent es la sangría del JSON de salida.
const outputIndent = "  "

// Run ejecuta audit-open con args (sin el nombre del programa). Lee de stdin las
// claves privadas (audit_key_id=base64, una por línea). En stdout escribe solo
// cantidades; los errores van a stderr sin datos. Devuelve el código de salida:
// 3 si algún manifiesto no pudo abrirse.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("audit-open", flag.ContinueOnError)
	flags.SetOutput(stderr)
	in := flags.String("in", "", "directorio de la exportación de auditctl")
	out := flags.String("out", "", "archivo donde se escriben los datos abiertos (fuera de cualquier repositorio)")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *in == "" || *out == "" {
		_, _ = fmt.Fprintln(stderr, "audit-open: faltan -in <dir> y -out <archivo>")
		return exitUsage
	}

	// La ruta de salida se valida antes de leer las claves.
	if err := pathguard.EnsureOutsideRepo(*out); err != nil {
		_, _ = fmt.Fprintf(stderr, "audit-open: %s: %v\n", *out, err)
		return exitError
	}

	keys, err := opener.ReadKeys(stdin)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "audit-open: %v\n", err)
		return exitError
	}

	records, failures, err := opener.OpenDir(*in, keys)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "audit-open: %v\n", err)
		return exitError
	}

	for _, failure := range failures {
		_, _ = fmt.Fprintf(stderr, "audit-open: %s: %s\n", failure.Dir, failure.Reason)
	}

	if len(records) > 0 {
		if err := writeRecords(*out, records); err != nil {
			_, _ = fmt.Fprintf(stderr, "audit-open: %v\n", err)
			return exitError
		}
	}

	_, _ = fmt.Fprintf(stdout, "registros abiertos: %d, con falla: %d\n", len(records), len(failures))
	if len(failures) > 0 {
		return exitPartial
	}
	return exitOK
}

// writeRecords escribe los registros abiertos como un arreglo JSON, en un archivo
// nuevo con permisos 0600.
func writeRecords(path string, records []opener.Record) error {
	file, err := pathguard.CreateFile(path)
	if err != nil {
		return err
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", outputIndent)
	encodeErr := encoder.Encode(records)
	closeErr := file.Close()
	if encodeErr != nil || closeErr != nil {
		return fmt.Errorf("no se pudo escribir %s", path)
	}
	return nil
}
