//go:build integration

// Integration-тесты store service tokens против реального PostgreSQL
// (pgtest, GRANTOR_TEST_DB_DSN): выпуск, аутентификация, отзыв, а также отказ
// аутентификации для отозванного токена и не-service принципала.
package servicetoken_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/core/principals"
	"github.com/ArtefactoO/grantor/internal/core/servicetoken"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

func TestServiceTokenStoreFlow(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := servicetoken.NewStore()
	principalStore := principals.NewStore()

	service, err := principalStore.Create(ctx, pool, principals.CreateParams{
		Type:        principals.TypeService,
		DisplayName: "itest-service-" + uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create service principal: %v", err)
	}

	// Выпуск: возвращается plaintext-токен нужного формата.
	plaintext, rec, err := store.Create(ctx, pool, service.ID, "ci-runner")
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	if !servicetoken.HasTokenPrefix(plaintext) {
		t.Fatalf("token %q has no service prefix", plaintext)
	}
	if rec.Name != "ci-runner" || rec.PrincipalID != service.ID {
		t.Fatalf("unexpected token record: %+v", rec)
	}
	if rec.RevokedAt != nil || rec.LastUsedAt != nil {
		t.Fatalf("fresh token must not be revoked or used: %+v", rec)
	}

	// token_hash не совпадает с самим токеном (в базе только хеш).
	if servicetoken.HashToken(plaintext) == plaintext {
		t.Fatal("hash equals plaintext")
	}

	// Аутентификация возвращает того же принципала и проставляет last_used_at.
	authed, err := store.Authenticate(ctx, pool, plaintext)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if authed.ID != service.ID || authed.Type != principals.TypeService {
		t.Fatalf("authenticated principal = %+v, want service %s", authed, service.ID)
	}
	tokens, err := store.List(ctx, pool, &service.ID)
	if err != nil {
		t.Fatalf("list tokens: %v", err)
	}
	if len(tokens) != 1 || tokens[0].LastUsedAt == nil {
		t.Fatalf("last_used_at not updated after authenticate: %+v", tokens)
	}

	// Неверный токен — ErrInvalidToken.
	if _, err := store.Authenticate(ctx, pool, "grt_wrong-value"); !errors.Is(err, servicetoken.ErrInvalidToken) {
		t.Fatalf("authenticate wrong token err = %v, want ErrInvalidToken", err)
	}
	// Значение без префикса — тоже ErrInvalidToken (без запроса к базе).
	if _, err := store.Authenticate(ctx, pool, "not-a-token"); !errors.Is(err, servicetoken.ErrInvalidToken) {
		t.Fatalf("authenticate non-prefixed err = %v, want ErrInvalidToken", err)
	}

	// Отзыв: после него аутентификация не проходит.
	if err := store.Revoke(ctx, pool, rec.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := store.Authenticate(ctx, pool, plaintext); !errors.Is(err, servicetoken.ErrInvalidToken) {
		t.Fatalf("authenticate revoked token err = %v, want ErrInvalidToken", err)
	}
	// Повторный отзыв идемпотентен (id существует).
	if err := store.Revoke(ctx, pool, rec.ID); err != nil {
		t.Fatalf("re-revoke: %v", err)
	}
	// Отзыв несуществующего токена — ErrNotFound.
	if err := store.Revoke(ctx, pool, uuid.New()); !errors.Is(err, servicetoken.ErrNotFound) {
		t.Fatalf("revoke missing token err = %v, want ErrNotFound", err)
	}
}

func TestServiceTokenAuthenticateNonServicePrincipal(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := servicetoken.NewStore()
	principalStore := principals.NewStore()

	// Токен, выпущенный для human-принципала (обход API-проверки типа), не
	// должен аутентифицироваться: Authenticate требует type=service.
	human, err := principalStore.Create(ctx, pool, principals.CreateParams{
		Type:        principals.TypeHuman,
		DisplayName: "itest-human-" + uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create human principal: %v", err)
	}
	plaintext, _, err := store.Create(ctx, pool, human.ID, "should-not-auth")
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	if _, err := store.Authenticate(ctx, pool, plaintext); !errors.Is(err, servicetoken.ErrInvalidToken) {
		t.Fatalf("authenticate non-service token err = %v, want ErrInvalidToken", err)
	}
}

func TestServiceTokenCreateMissingPrincipal(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := servicetoken.NewStore()

	if _, _, err := store.Create(ctx, pool, uuid.New(), "orphan"); !errors.Is(err, servicetoken.ErrPrincipalNotFound) {
		t.Fatalf("create for missing principal err = %v, want ErrPrincipalNotFound", err)
	}
}
