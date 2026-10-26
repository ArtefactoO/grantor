//go:build integration

package connections_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

func TestGetEnvironmentUsesOnlyScopeColumnsAndFreshState(t *testing.T) {
	ctx := t.Context()
	pool := pgtest.Pool(t)
	store := connections.NewStore()
	c, err := store.Create(ctx, pool, connections.CreateParams{DisplayName: "scope-projection-" + uuid.NewString(), Engine: "postgres", Environment: "before"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := pool.Exec(cleanup, `delete from connections where id=$1`, c.ID); err != nil {
			t.Error(err)
		}
	})
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background()) //nolint:errcheck
	role := pgx.Identifier{"scope_projection_" + uuid.NewString()[:8]}.Sanitize()
	for _, sql := range []string{`create role ` + role + ` nologin`, `grant usage on schema public to ` + role, `grant select(id,environment) on connections to ` + role, `set local role ` + role} {
		if _, err := tx.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := store.GetEnvironment(ctx, tx, c.ID); err != nil || got != "before" {
		t.Fatalf("scope projection: %q %v", got, err)
	}
	if _, err := store.GetEnvironment(ctx, tx, uuid.New()); !errors.Is(err, connections.ErrNotFound) {
		t.Fatalf("unknown connection: %v", err)
	}
	if _, err := tx.Exec(ctx, `reset role`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `update connections set environment='after' where id=$1`, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `set local role `+role); err != nil {
		t.Fatal(err)
	}
	if got, err := store.GetEnvironment(ctx, tx, c.ID); err != nil || got != "after" {
		t.Fatalf("scope projection reused an old environment: %q %v", got, err)
	}
	_, err = store.Get(ctx, tx, c.ID)
	var denied *pgconn.PgError
	if !errors.As(err, &denied) || denied.Code != "42501" {
		t.Fatalf("fixture unexpectedly allows the full discovery snapshot: %v", err)
	}
}
