//go:build integration

package apikey_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/apikey"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

func TestAPIKeyOwnerAndCredentialBoundaries(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := apikey.NewStore()
	now := time.Now().UTC()
	owner, err := store.SaveLogin(ctx, pool, apikey.User{Issuer: "https://idp.test", Subject: uuid.NewString(), Username: "alice",
		DirectoryUID: "immutable-person-1", Email: "alice@example.test", Role: auth.RoleAdmin, Active: true, DirectoryManaged: true,
		AuthorizedUntil: now.Add(time.Hour), AuthenticatedAt: now, IdentityBoundAt: now})
	if err != nil {
		t.Fatal(err)
	}
	plaintext, key, err := store.Create(ctx, pool, apikey.CreateParams{UserID: owner.ID, Name: "automation", Role: auth.RoleAdmin,
		ExpiresAt: now.Add(2 * time.Hour), Environments: []string{"test"}})
	if err != nil {
		t.Fatal(err)
	}
	var storedHash string
	if err := pool.QueryRow(ctx, `select token_hash from personal_api_keys where id=$1`, key.ID).Scan(&storedHash); err != nil {
		t.Fatal(err)
	}
	if storedHash != apikey.HashToken(plaintext) || storedHash == plaintext {
		t.Fatal("database contains plaintext or wrong hash")
	}
	got, err := store.Authenticate(ctx, pool, plaintext)
	if err != nil || got.User.ID != owner.ID || got.Role != auth.RoleAdmin || len(got.Environments) != 1 {
		t.Fatalf("initial auth: %+v %v", got, err)
	}
	if err := store.Refresh(ctx, pool, owner, true, auth.RoleViewer, owner.Email, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, err = store.Authenticate(ctx, pool, plaintext)
	if err != nil || got.Role != auth.RoleViewer {
		t.Fatalf("role downgrade did not constrain existing key: %+v %v", got, err)
	}
	if _, _, err := store.Create(ctx, pool, apikey.CreateParams{UserID: owner.ID, Name: "escalation", Role: auth.RoleAdmin, ExpiresAt: now.Add(time.Hour)}); !errors.Is(err, apikey.ErrOwnerUnavailable) {
		t.Fatalf("cap escalation: %v", err)
	}
	for _, tc := range []struct {
		name   string
		active bool
		until  time.Time
	}{
		{"disabled owner", false, now.Add(time.Hour)},
		{"stale owner", true, now.Add(-time.Second)},
	} {
		if err := store.Refresh(ctx, pool, owner, tc.active, auth.RoleViewer, owner.Email, tc.until); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Authenticate(ctx, pool, plaintext); !errors.Is(err, apikey.ErrInvalidToken) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	if err := store.Refresh(ctx, pool, owner, true, auth.RoleAdmin, owner.Email, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke(ctx, pool, uuid.New(), key.ID); !errors.Is(err, apikey.ErrNotFound) {
		t.Fatalf("another owner revoked key: %v", err)
	}
	if err := store.Revoke(ctx, pool, owner.ID, key.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke(ctx, pool, owner.ID, key.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Authenticate(ctx, pool, plaintext); !errors.Is(err, apikey.ErrInvalidToken) {
		t.Fatalf("revoked key: %v", err)
	}
	second, secondKey, err := store.Create(ctx, pool, apikey.CreateParams{UserID: owner.ID, Name: "expires", Role: auth.RoleViewer, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `update personal_api_keys set created_at=now()-interval '2 hours',expires_at=now()-interval '1 hour' where id=$1`, secondKey.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Authenticate(ctx, pool, second); !errors.Is(err, apikey.ErrInvalidToken) {
		t.Fatalf("expired key: %v", err)
	}
	third, _, err := store.Create(ctx, pool, apikey.CreateParams{UserID: owner.ID, Name: "uid-bound", Role: auth.RoleOperator, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	owner.DirectoryUID = "immutable-person-2"
	owner.AuthenticatedAt = now.Add(time.Minute)
	owner.IdentityBoundAt = owner.AuthenticatedAt
	if _, err := store.SaveLogin(ctx, pool, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Authenticate(ctx, pool, third); !errors.Is(err, apikey.ErrInvalidToken) {
		t.Fatalf("reassigned username inherited previous key: %v", err)
	}
}
