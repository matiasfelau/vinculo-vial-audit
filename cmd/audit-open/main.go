// Command audit-open abre, fuera de línea, los criptogramas de una exportación de
// auditctl con las claves privadas recibidas por stdin. No importa paquetes de
// red, base de datos ni AWS.
package main

import (
	"os"

	"github.com/matiasfelau/vinculo-vial-audit/internal/cli/open"
)

func main() {
	os.Exit(open.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
