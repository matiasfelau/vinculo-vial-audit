// Package auditctl implementa la CLI auditctl: export (exportar registros para un
// requerimiento judicial) y hold (retención judicial). Usa las credenciales de la
// base y del bucket de Audit; nunca abre los criptogramas.
package auditctl

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"

	"github.com/matiasfelau/vinculo-vial-audit/internal/domain"
	"github.com/matiasfelau/vinculo-vial-audit/internal/service/export"
)

// Códigos de salida.
const (
	exitOK            = 0
	exitError         = 1
	exitUsage         = 2
	exitDiscrepancies = 3
)

const usage = `uso:
  auditctl export (-alert-id <uuid> | -from <RFC3339> -to <RFC3339>) -out <dir>
  auditctl hold -alert-id <uuid> (-on | -off)`

// exporter exporta registros a un directorio.
type exporter interface {
	Export(ctx context.Context, filter domain.ExportFilter, outDir string) (export.Summary, error)
}

// holder aplica y quita la retención judicial.
type holder interface {
	Hold(ctx context.Context, alertID uuid.UUID, on bool) (int, error)
}

// Services son las dependencias de los subcomandos.
type Services struct {
	Exporter exporter
	Holder   holder
}

// Factory construye las dependencias (base y bucket) y devuelve la función que las
// cierra. Se invoca solo cuando los argumentos ya fueron validados.
type Factory func(ctx context.Context) (Services, func(), error)

// Run ejecuta auditctl con args (sin el nombre del programa) y devuelve el código
// de salida: 0 ok, 1 error, 2 uso incorrecto, 3 si la exportación encontró
// diferencias.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer, factory Factory) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, usage)
		return exitUsage
	}

	switch args[0] {
	case "export":
		return runExport(ctx, args[1:], stdout, stderr, factory)
	case "hold":
		return runHold(ctx, args[1:], stdout, stderr, factory)
	default:
		_, _ = fmt.Fprintf(stderr, "auditctl: subcomando desconocido %q\n%s\n", args[0], usage)
		return exitUsage
	}
}

func runExport(ctx context.Context, args []string, stdout, stderr io.Writer, factory Factory) int {
	flags := flag.NewFlagSet("auditctl export", flag.ContinueOnError)
	flags.SetOutput(stderr)
	alertID := flags.String("alert-id", "", "alert_id del registro a exportar")
	from := flags.String("from", "", "inicio del rango de alert_created_at (RFC3339)")
	to := flags.String("to", "", "fin del rango de alert_created_at (RFC3339)")
	out := flags.String("out", "", "directorio de salida (fuera de cualquier repositorio)")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	filter, err := exportFilter(*alertID, *from, *to)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "auditctl export: %v\n%s\n", err, usage)
		return exitUsage
	}
	if *out == "" {
		_, _ = fmt.Fprintf(stderr, "auditctl export: falta -out <dir>\n%s\n", usage)
		return exitUsage
	}

	services, closeServices, err := factory(ctx)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "auditctl: %v\n", err)
		return exitError
	}
	defer closeServices()

	summary, err := services.Exporter.Export(ctx, filter, *out)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "auditctl export: %v\n", err)
		return exitError
	}

	_, _ = fmt.Fprintf(stdout, "registros exportados: %d, omitidos (sin entregar): %d, con diferencias: %d\n",
		summary.Exported, summary.Skipped, len(summary.Discrepancies))
	for _, id := range summary.Discrepancies {
		_, _ = fmt.Fprintf(stdout, "diferencias en el registro %s: ver %s/report.json\n", id, id)
	}
	if len(summary.Discrepancies) > 0 {
		return exitDiscrepancies
	}
	return exitOK
}

// exportFilter valida las opciones de filtro: alert_id, o un rango completo.
func exportFilter(alertID, from, to string) (domain.ExportFilter, error) {
	hasRange := from != "" || to != ""

	switch {
	case alertID != "" && hasRange:
		return domain.ExportFilter{}, errors.New("-alert-id no se combina con -from/-to")
	case alertID != "":
		id, err := uuid.Parse(alertID)
		if err != nil || id == uuid.Nil {
			return domain.ExportFilter{}, errors.New("-alert-id no es un UUID válido")
		}
		return domain.ExportFilter{AlertID: &id}, nil
	case hasRange:
		start, err := time.Parse(time.RFC3339, from)
		if err != nil {
			return domain.ExportFilter{}, errors.New("-from no es RFC3339")
		}
		end, err := time.Parse(time.RFC3339, to)
		if err != nil {
			return domain.ExportFilter{}, errors.New("-to no es RFC3339")
		}
		if end.Before(start) {
			return domain.ExportFilter{}, errors.New("-to es anterior a -from")
		}
		return domain.ExportFilter{From: start, To: end}, nil
	default:
		return domain.ExportFilter{}, errors.New("falta -alert-id o el rango -from/-to")
	}
}

func runHold(ctx context.Context, args []string, stdout, stderr io.Writer, factory Factory) int {
	flags := flag.NewFlagSet("auditctl hold", flag.ContinueOnError)
	flags.SetOutput(stderr)
	alertID := flags.String("alert-id", "", "alert_id del registro")
	on := flags.Bool("on", false, "aplica la retención judicial")
	off := flags.Bool("off", false, "quita la retención judicial")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	id, err := uuid.Parse(*alertID)
	if err != nil || id == uuid.Nil {
		_, _ = fmt.Fprintf(stderr, "auditctl hold: falta un -alert-id válido\n%s\n", usage)
		return exitUsage
	}
	if *on == *off {
		_, _ = fmt.Fprintf(stderr, "auditctl hold: indique exactamente uno de -on o -off\n%s\n", usage)
		return exitUsage
	}

	services, closeServices, err := factory(ctx)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "auditctl: %v\n", err)
		return exitError
	}
	defer closeServices()

	changed, err := services.Holder.Hold(ctx, id, *on)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "auditctl hold: %v\n", err)
		return exitError
	}

	state := "aplicada"
	if !*on {
		state = "quitada"
	}
	_, _ = fmt.Fprintf(stdout, "retención judicial %s en el registro %s (versiones de objetos modificadas en S3: %d)\n", state, id, changed)
	return exitOK
}
