package store

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	migratesqlite "github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"

	"warden/migrations"
)

// migrateDB applies all embedded migrations. Rerunning against an already
// migrated database is a no-op.
func migrateDB(db *sql.DB) error {
	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("store: load embedded migrations: %w", err)
	}

	driver, err := migratesqlite.WithInstance(db, &migratesqlite.Config{})
	if err != nil {
		return fmt.Errorf("store: init migrate driver: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", src, "sqlite", driver)
	if err != nil {
		return fmt.Errorf("store: create migrator: %w", err)
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("store: apply migrations: %w", err)
	}
	// m.Close() would close the shared *sql.DB; the driver's Close closes its
	// instance handle. We intentionally do not close it: the caller owns db.
	return nil
}
