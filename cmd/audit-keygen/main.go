// Command audit-keygen genera el par de claves X25519 de Audit. La clave privada
// se escribe fuera de cualquier repositorio y la custodia el responsable legal,
// fuera de línea; la pública se imprime para configurar AUDIT_PUBLIC_KEY.
package main

import (
	"os"

	"github.com/matiasfelau/vinculo-vial-audit/internal/cli/keygen"
)

func main() {
	os.Exit(keygen.Run(os.Args[1:], os.Stdout, os.Stderr))
}
