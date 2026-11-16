package postgres

import (
	"context"
	"embed"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

const (
	migrationsDir = "migrations"

	// migrationLockID es la clave del advisory lock que serializa las migraciones
	// entre réplicas que arrancan a la vez.
	migrationLockID = 726_3011

	// migrationTimeout acota la ejecución completa de las migraciones al arrancar.
	migrationTimeout = 30 * time.Second
)

// Migrate aplica, en orden, las migraciones versionadas pendientes. Cada archivo
// de migrations/ se aplica una sola vez, dentro de una transacción, y se registra
// en schema_migrations. Un advisory lock serializa a las réplicas concurrentes.
// El esquema se gestiona exclusivamente por este camino.
func Migrate(db *gorm.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), migrationTimeout)
	defer cancel()

	names, err := migrationNames()
	if err != nil {
		return err
	}

	err = db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", migrationLockID).Error; err != nil {
			return fmt.Errorf("no se pudo tomar el lock de migraciones: %w", err)
		}
		if err := tx.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
			version    text        PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`).Error; err != nil {
			return fmt.Errorf("no se pudo crear schema_migrations: %w", err)
		}

		for _, name := range names {
			if err := applyMigration(tx, name); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("postgres: no se pudo migrar el esquema: %w", err)
	}
	return nil
}

// applyMigration aplica la migración name si todavía no está registrada.
func applyMigration(tx *gorm.DB, name string) error {
	var applied int64
	if err := tx.Raw("SELECT count(*) FROM schema_migrations WHERE version = ?", name).Scan(&applied).Error; err != nil {
		return fmt.Errorf("no se pudo consultar la migración %s: %w", name, err)
	}
	if applied > 0 {
		return nil
	}

	script, err := migrationFiles.ReadFile(path.Join(migrationsDir, name))
	if err != nil {
		return fmt.Errorf("no se pudo leer la migración %s: %w", name, err)
	}
	if err := tx.Exec(string(script)).Error; err != nil {
		return fmt.Errorf("falló la migración %s: %w", name, err)
	}
	if err := tx.Exec("INSERT INTO schema_migrations (version) VALUES (?)", name).Error; err != nil {
		return fmt.Errorf("no se pudo registrar la migración %s: %w", name, err)
	}
	return nil
}

// migrationNames lista los archivos de migración en orden de versión.
func migrationNames() ([]string, error) {
	entries, err := migrationFiles.ReadDir(migrationsDir)
	if err != nil {
		return nil, fmt.Errorf("postgres: no se pudieron listar las migraciones: %w", err)
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}
