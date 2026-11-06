//go:build integration

package postgrestest

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/matiasfelau/vinculo-vial-audit/internal/repository/postgres"
)

// EnvDatabaseURL es la variable con la cadena de conexión de la instancia de prueba.
const EnvDatabaseURL = "DATABASE_URL"

// New devuelve una conexión a un esquema nuevo y migrado, que se destruye al
// terminar la prueba. Si DATABASE_URL no está definida, omite la prueba.
func New(t *testing.T) *gorm.DB {
	t.Helper()

	dsn := os.Getenv(EnvDatabaseURL)
	if dsn == "" {
		t.Skip("DATABASE_URL no configurada: se omite la prueba contra PostgreSQL")
	}

	admin, err := postgres.Connect(dsn)
	if err != nil {
		t.Fatalf("no se pudo conectar a la base de prueba: %v", err)
	}

	schema := "t_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if err := admin.Exec(fmt.Sprintf("CREATE SCHEMA %s", schema)).Error; err != nil {
		t.Fatalf("no se pudo crear el esquema de prueba: %v", err)
	}

	scoped, err := withSearchPath(dsn, schema)
	if err != nil {
		t.Fatalf("DATABASE_URL inválida: %v", err)
	}
	db, err := postgres.Connect(scoped)
	if err != nil {
		t.Fatalf("no se pudo conectar al esquema de prueba: %v", err)
	}

	t.Cleanup(func() {
		closeDB(db)
		if err := admin.Exec(fmt.Sprintf("DROP SCHEMA %s CASCADE", schema)).Error; err != nil {
			t.Errorf("no se pudo borrar el esquema de prueba: %v", err)
		}
		closeDB(admin)
	})

	if err := postgres.Migrate(db); err != nil {
		t.Fatalf("no se pudo migrar el esquema de prueba: %v", err)
	}
	return db
}

// Schema devuelve el esquema al que apunta db, para pruebas que abren más
// conexiones.
func Schema(t *testing.T, db *gorm.DB) string {
	t.Helper()

	var schema string
	if err := db.Raw("SELECT current_schema()").Scan(&schema).Error; err != nil {
		t.Fatalf("no se pudo leer el esquema actual: %v", err)
	}
	return schema
}

// DSN devuelve la cadena de conexión apuntando al esquema dado.
func DSN(t *testing.T, schema string) string {
	t.Helper()

	scoped, err := withSearchPath(os.Getenv(EnvDatabaseURL), schema)
	if err != nil {
		t.Fatalf("DATABASE_URL inválida: %v", err)
	}
	return scoped
}

func withSearchPath(dsn, schema string) (string, error) {
	parsed, err := url.Parse(dsn)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func closeDB(db *gorm.DB) {
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
}
