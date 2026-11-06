// Command auditctl exporta registros de auditoría para un requerimiento judicial
// y aplica la retención judicial. Usa las credenciales de la base (DATABASE_URL) y
// del bucket de Audit (AUDIT_BUCKET, credenciales estándar de AWS).
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/matiasfelau/vinculo-vial-audit/internal/cli/auditctl"
	"github.com/matiasfelau/vinculo-vial-audit/internal/client/storage"
	"github.com/matiasfelau/vinculo-vial-audit/internal/repository/postgres"
	"github.com/matiasfelau/vinculo-vial-audit/internal/service/export"
	"github.com/matiasfelau/vinculo-vial-audit/internal/service/hold"
	"github.com/matiasfelau/vinculo-vial-audit/pkg/config"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	code := auditctl.Run(ctx, os.Args[1:], os.Stdout, os.Stderr, buildServices)
	stop()
	os.Exit(code)
}

// buildServices abre la base y el bucket de Audit con la configuración del
// entorno. Devuelve la función que cierra el pool de la base.
func buildServices(ctx context.Context) (auditctl.Services, func(), error) {
	cfg, err := config.LoadCLI()
	if err != nil {
		return auditctl.Services{}, nil, err
	}

	db, err := postgres.Connect(cfg.DatabaseURL)
	if err != nil {
		return auditctl.Services{}, nil, err
	}
	closeDB := func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	}

	store, err := storage.New(ctx, storage.Config{
		Region:              cfg.S3.Region,
		Bucket:              cfg.AuditBucket,
		PutTimeout:          cfg.S3.PutTimeout,
		GetTimeout:          cfg.S3.GetTimeout,
		MaxObjectBytes:      cfg.S3.MaxObjectBytes,
		BreakerThreshold:    cfg.S3.BreakerThreshold,
		BreakerWindow:       cfg.S3.BreakerWindow,
		BreakerOpenDuration: cfg.S3.BreakerOpenDuration,
	})
	if err != nil {
		closeDB()
		return auditctl.Services{}, nil, fmt.Errorf("no se pudo abrir el bucket de Audit: %w", err)
	}

	repository := postgres.NewAuditRepository(db, postgres.WithQueryTimeout(cfg.DBQueryTimeout))
	return auditctl.Services{
		Exporter: export.New(repository, store),
		Holder:   hold.New(repository, store),
	}, closeDB, nil
}
