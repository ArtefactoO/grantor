//go:build integration

// Integration-тесты store scope policies против реального PostgreSQL
// (pgtest, GRANTOR_TEST_DB_DSN). Проверяется сборка разрешённых окружений из
// role- и principal-политик, а также deny-by-default (пустой набор).
package policy_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/core/policy"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

func TestScopePolicyStoreFlow(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := policy.NewStore()

	// Уникальные значения на прогон: общая тестовая база разделяется тестами.
	principalID := uuid.NewString()
	env := "itest-" + uuid.NewString()

	// Deny-by-default: у роли без политик окружений нет.
	role := "operator-" + uuid.NewString()
	allowed, allowAll, err := store.AllowedEnvironments(ctx, pool, role, principalID)
	if err != nil {
		t.Fatalf("allowed (empty): %v", err)
	}
	if allowAll || len(allowed) != 0 {
		t.Fatalf("empty policies: allowed=%v allowAll=%v, want none", allowed, allowAll)
	}

	// Политика на роль даёт окружение.
	rolePolicy, err := store.Create(ctx, pool, policy.CreateParams{
		SubjectKind: policy.SubjectRole,
		Subject:     role,
		Environment: env,
	})
	if err != nil {
		t.Fatalf("create role policy: %v", err)
	}
	allowed, allowAll, err = store.AllowedEnvironments(ctx, pool, role, principalID)
	if err != nil {
		t.Fatalf("allowed (role policy): %v", err)
	}
	if allowAll || !slices.Contains(allowed, env) {
		t.Fatalf("role policy: allowed=%v allowAll=%v, want %q", allowed, allowAll, env)
	}

	// Дубликат тройки — ErrAlreadyExists.
	if _, err := store.Create(ctx, pool, policy.CreateParams{
		SubjectKind: policy.SubjectRole,
		Subject:     role,
		Environment: env,
	}); !errors.Is(err, policy.ErrAlreadyExists) {
		t.Fatalf("duplicate policy err = %v, want ErrAlreadyExists", err)
	}

	// Политика на принципала добавляет ещё одно окружение.
	principalEnv := "itest-p-" + uuid.NewString()
	if _, err := store.Create(ctx, pool, policy.CreateParams{
		SubjectKind: policy.SubjectPrincipal,
		Subject:     principalID,
		Environment: principalEnv,
	}); err != nil {
		t.Fatalf("create principal policy: %v", err)
	}
	allowed, _, err = store.AllowedEnvironments(ctx, pool, role, principalID)
	if err != nil {
		t.Fatalf("allowed (role+principal): %v", err)
	}
	if !slices.Contains(allowed, env) || !slices.Contains(allowed, principalEnv) {
		t.Fatalf("combined policies allowed=%v, want both %q and %q", allowed, env, principalEnv)
	}

	// Другой принципал не подхватывает чужую principal-политику.
	other := uuid.NewString()
	allowed, _, err = store.AllowedEnvironments(ctx, pool, role, other)
	if err != nil {
		t.Fatalf("allowed (other principal): %v", err)
	}
	if slices.Contains(allowed, principalEnv) {
		t.Fatalf("principal policy leaked to other principal: %v", allowed)
	}

	// '*' даёт allowAll.
	starRole := "operator-star-" + uuid.NewString()
	if _, err := store.Create(ctx, pool, policy.CreateParams{
		SubjectKind: policy.SubjectRole,
		Subject:     starRole,
		Environment: policy.EnvironmentAll,
	}); err != nil {
		t.Fatalf("create star policy: %v", err)
	}
	_, allowAll, err = store.AllowedEnvironments(ctx, pool, starRole, "")
	if err != nil {
		t.Fatalf("allowed (star): %v", err)
	}
	if !allowAll {
		t.Fatalf("star policy: allowAll = false, want true")
	}

	// Delete удаляет политику; повтор — ErrNotFound.
	if err := store.Delete(ctx, pool, rolePolicy.ID); err != nil {
		t.Fatalf("delete policy: %v", err)
	}
	if err := store.Delete(ctx, pool, rolePolicy.ID); !errors.Is(err, policy.ErrNotFound) {
		t.Fatalf("delete missing policy err = %v, want ErrNotFound", err)
	}
	allowed, _, err = store.AllowedEnvironments(ctx, pool, role, principalID)
	if err != nil {
		t.Fatalf("allowed (after delete): %v", err)
	}
	if slices.Contains(allowed, env) {
		t.Fatalf("deleted role policy still returns %q: %v", env, allowed)
	}

	// List содержит заведённые политики.
	list, err := store.List(ctx, pool)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) == 0 {
		t.Fatalf("list is empty, want at least the principal and star policies")
	}
}
