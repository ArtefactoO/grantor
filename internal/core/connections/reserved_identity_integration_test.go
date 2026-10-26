//go:build integration

package connections_test

import (
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

func TestStoreCreateUsesServerReservedIdentity(t *testing.T) {
	pool := pgtest.Pool(t)
	store := connections.NewStore()
	reserved := uuid.New()
	conn, err := store.Create(t.Context(), pool, connections.CreateParams{ID: &reserved, DisplayName: "reserved", Engine: "postgres", Environment: "test", Endpoints: []string{"10.42.0.1:5432"}})
	if err != nil {
		t.Fatal(err)
	}
	if conn.ID != reserved {
		t.Fatal("server-reserved connection identity was replaced")
	}
	if _, err := store.Create(t.Context(), pool, connections.CreateParams{ID: &reserved, DisplayName: "duplicate", Engine: "postgres"}); err == nil {
		t.Fatal("duplicate reserved identity replaced existing connection")
	}
}
