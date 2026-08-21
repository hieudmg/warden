// Package migrations embeds the numbered SQLite migration files so the
// warden-server binary is self-contained and never depends on a migration
// directory at runtime.
package migrations

import "embed"

// FS holds all *.sql migration files in this directory.
//
//go:embed *.sql
var FS embed.FS
