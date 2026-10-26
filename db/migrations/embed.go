// Package migrations содержит goose SQL-миграции metadata database.
// Встроенная FS позволяет применять миграции из кода: в тестах (pgtest)
// и в будущем db-migrate Job (docs/architecture.md, раздел 27).
package migrations

import "embed"

// FS — встроенные goose-миграции (*.sql) в порядке нумерации файлов.
//
//go:embed *.sql
var FS embed.FS
