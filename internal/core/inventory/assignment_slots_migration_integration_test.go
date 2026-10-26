//go:build integration

package inventory_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArtefactoO/grantor/db/migrations"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

const assignmentMigrationFile = "00027_assignment_slots.sql"

// assignmentBackfillStatements читает ровно data-UPDATE из embedded migration.
// DDL уже применён pgtest; replay в откатываемой транзакции проверяет backfill,
// не копируя его SQL в тест и не затрагивая строки соседних тестов.
func assignmentBackfillStatements(t *testing.T) []string {
	t.Helper()
	raw, err := migrations.FS.ReadFile(assignmentMigrationFile)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	body := string(raw)
	up := strings.Index(body, "-- +goose Up")
	down := strings.Index(body, "-- +goose Down")
	if up < 0 || down < 0 || down < up {
		t.Fatalf("migration %s has no Up/Down sections", assignmentMigrationFile)
	}
	var code strings.Builder
	for _, line := range strings.Split(body[up:down], "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		code.WriteString(line)
		code.WriteByte('\n')
	}
	var updates []string
	for _, chunk := range strings.Split(code.String(), ";") {
		stmt := strings.TrimSpace(chunk)
		if strings.HasPrefix(stmt, "update permission_definitions") || strings.HasPrefix(stmt, "update bindings") {
			updates = append(updates, stmt)
		}
	}
	if len(updates) != 2 {
		t.Fatalf("migration data statements = %d, want 2: %q", len(updates), updates)
	}
	return updates
}

func TestAssignmentSlotMigrationRabbitLegacyBackfill(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	conn, err := connections.NewStore().Create(ctx, tx, connections.CreateParams{
		DisplayName: "assignment-backfill-" + uuid.NewString(),
		Engine:      "rabbitmq",
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	var accountID, permissionID, bindingID uuid.UUID
	if err := tx.QueryRow(ctx, `
		insert into accounts (connection_id, kind, engine_identity)
		values ($1, 'login', 'legacy-svc') returning id`, conn.ID).Scan(&accountID); err != nil {
		t.Fatalf("insert account: %v", err)
	}
	if err := tx.QueryRow(ctx, `
		insert into permission_definitions (
			connection_id, engine, external_id, name, assignable, attributes
		) values ($1, 'rabbitmq', 'vhost-access:app', 'vhost-access:app', true,
			'{"configure":".*","write":".*","read":".*"}'::jsonb)
		returning id`, conn.ID).Scan(&permissionID); err != nil {
		t.Fatalf("insert permission: %v", err)
	}
	if err := tx.QueryRow(ctx, `
		insert into bindings (
			account_id, permission_definition_id, source, desired_state,
			observed_state, observed_effective, status
		) values ($1, $2, 'service', 'present', 'present', true, 'synced')
		returning id`, accountID, permissionID).Scan(&bindingID); err != nil {
		t.Fatalf("insert binding: %v", err)
	}

	for i, stmt := range assignmentBackfillStatements(t) {
		if _, err := tx.Exec(ctx, stmt); err != nil {
			t.Fatalf("backfill statement %d: %v", i, err)
		}
	}
	var permissionKey, bindingKey string
	var observedPermissionID *uuid.UUID
	var observedAttributes []byte
	var bindingVersion int64
	var transitionOperationID *uuid.UUID
	if err := tx.QueryRow(ctx, `select assignment_key from permission_definitions where id = $1`, permissionID).
		Scan(&permissionKey); err != nil {
		t.Fatalf("read permission backfill: %v", err)
	}
	if err := tx.QueryRow(ctx, `
		select assignment_key, observed_permission_definition_id, observed_attributes,
		       binding_version, transition_operation_id
		from bindings where id = $1`, bindingID).
		Scan(&bindingKey, &observedPermissionID, &observedAttributes, &bindingVersion, &transitionOperationID); err != nil {
		t.Fatalf("read binding backfill: %v", err)
	}
	if permissionKey != assignmentSlot || bindingKey != assignmentSlot {
		t.Errorf("assignment keys = permission %q binding %q, want %q", permissionKey, bindingKey, assignmentSlot)
	}
	if observedPermissionID == nil || *observedPermissionID != permissionID {
		t.Errorf("observed permission = %v, want %s", observedPermissionID, permissionID)
	}
	if !strings.Contains(string(observedAttributes), `"configure": ".*"`) &&
		!strings.Contains(string(observedAttributes), `"configure":".*"`) {
		t.Errorf("observed attributes = %s, want full regex triple", observedAttributes)
	}
	if bindingVersion != 0 || transitionOperationID != nil {
		t.Errorf("transition defaults = version %d operation %v, want 0/nil", bindingVersion, transitionOperationID)
	}
}

func TestAssignmentSlotUniqueIndexAbortsDuplicates(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	conn, err := connections.NewStore().Create(ctx, tx, connections.CreateParams{
		DisplayName: "assignment-duplicate-" + uuid.NewString(),
		Engine:      "rabbitmq",
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	var accountID uuid.UUID
	if err := tx.QueryRow(ctx, `
		insert into accounts (connection_id, kind, engine_identity)
		values ($1, 'login', 'duplicate-svc') returning id`, conn.ID).Scan(&accountID); err != nil {
		t.Fatalf("insert account: %v", err)
	}
	var permissions [2]uuid.UUID
	for i := range permissions {
		if err := tx.QueryRow(ctx, `
			insert into permission_definitions (
				connection_id, engine, external_id, name, assignment_key
			) values ($1, 'rabbitmq', $2, $2, $3) returning id`,
			conn.ID, "template:"+string(rune('a'+i)), assignmentSlot,
		).Scan(&permissions[i]); err != nil {
			t.Fatalf("insert permission %d: %v", i, err)
		}
	}
	var bindings [2]uuid.UUID
	for i := range bindings {
		// Empty keys model pre-backfill rows and are intentionally outside the
		// partial unique index until migration assigns the slot.
		if err := tx.QueryRow(ctx, `
			insert into bindings (account_id, permission_definition_id)
			values ($1, $2) returning id`, accountID, permissions[i]).Scan(&bindings[i]); err != nil {
			t.Fatalf("insert binding %d: %v", i, err)
		}
	}
	if _, err := tx.Exec(ctx, `update bindings set assignment_key = $2 where id = $1`, bindings[0], assignmentSlot); err != nil {
		t.Fatalf("assign first slot: %v", err)
	}
	_, err = tx.Exec(ctx, `update bindings set assignment_key = $2 where id = $1`, bindings[1], assignmentSlot)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		t.Fatalf("duplicate assignment error = %v, want unique violation", err)
	}
}
