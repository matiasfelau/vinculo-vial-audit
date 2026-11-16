// Package keygen implementa audit-keygen: genera el par X25519 de Audit, escribe
// la clave privada fuera de cualquier repositorio e imprime la pública.
package keygen

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"

	"github.com/matiasfelau/vinculo-vial-audit/internal/auditcrypto"
	"github.com/matiasfelau/vinculo-vial-audit/internal/pathguard"
)

// Códigos de salida.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

// Run ejecuta audit-keygen con args (sin el nombre del programa). Escribe en
// stdout únicamente la clave pública en base64 (el valor de AUDIT_PUBLIC_KEY); el
// resto va a stderr. Devuelve el código de salida.
func Run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("audit-keygen", flag.ContinueOnError)
	flags.SetOutput(stderr)
	out := flags.String("out", "", "ruta del archivo donde se escribe la clave privada (fuera de cualquier repositorio)")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *out == "" {
		_, _ = fmt.Fprintln(stderr, "audit-keygen: falta -out <ruta>")
		return exitUsage
	}

	// Se valida la ruta antes de generar nada: una ruta dentro de un repo no deja
	// ninguna clave en el disco.
	file, err := pathguard.CreateFile(*out)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "audit-keygen: %v\n", err)
		return exitError
	}

	private, public, err := auditcrypto.GenerateKeyPair()
	if err != nil {
		_ = file.Close()
		_, _ = fmt.Fprintf(stderr, "audit-keygen: %v\n", err)
		return exitError
	}
	defer wipe(private)

	encoded := base64.StdEncoding.EncodeToString(private)
	_, writeErr := io.WriteString(file, encoded+"\n")
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		_, _ = fmt.Fprintln(stderr, "audit-keygen: no se pudo escribir la clave privada")
		return exitError
	}

	_, _ = fmt.Fprintln(stderr, "audit-keygen: clave privada escrita; entréguela al responsable legal y bórrela de este equipo")
	_, _ = fmt.Fprintln(stdout, base64.StdEncoding.EncodeToString(public))
	return exitOK
}

// wipe pone en cero el material de clave en memoria.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
