//go:build integration

// E2E-регрессия на разблокировку повторной выдачи после провала access.grant
// против живого PostgreSQL (GRANTOR_TEST_TARGET_PG_DSN).
//
// Сценарий бага: грант падает на target (роль удалена), binding остаётся
// failed/present/unknown, и до следующего discovery повторная выдача отвечала
// 409 access is already assigned — оператор видел поломку и не мог её
// устранить. Теперь failed считается доказанной поломкой (BindingNeedsRepair),
// и повторная выдача сама возвращает binding в pending и чинит его.
package api_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
)

// bindingRow читает статусную тройку binding напрямую из metadata: API
// намеренно не отдаёт часть полей, а тест проверяет именно строку хранилища.
func bindingRow(ctx context.Context, t *testing.T, env *testEnv,
	accountID, permID uuid.UUID) (status string, desired *string, observed string) {
	t.Helper()
	err := env.pool.QueryRow(ctx, `
		select status, desired_state, observed_state from bindings
		where account_id = $1 and permission_definition_id = $2`,
		accountID, permID).Scan(&status, &desired, &observed)
	if err != nil {
		t.Fatalf("read binding row: %v", err)
	}
	return status, desired, observed
}

func TestIntegrationFailedGrantRegrantPostgresE2E(t *testing.T) {
	targetDSN := os.Getenv("GRANTOR_TEST_TARGET_PG_DSN")
	if targetDSN == "" {
		t.Skip("GRANTOR_TEST_TARGET_PG_DSN is not set; skipping failed-grant regrant e2e test")
	}
	vaultClient := newTestVault(t)
	registerPostgresOnceAPI.Do(func() {
		adapter.Register(postgres.Engine, func() adapter.Adapter { return postgres.New() })
	})
	ctx := context.Background()
	env := newCascadeWorkerEnv(t, vaultClient)
	operator := session(auth.RoleOperator)
	admin := session(auth.RoleAdmin)

	cc, err := pgx.ParseConfig(targetDSN)
	if err != nil {
		t.Fatalf("parse GRANTOR_TEST_TARGET_PG_DSN: %v", err)
	}
	sfx := uniqueSuffix()[:8]
	role := "gr_regr_ro_" + sfx
	targetExec(ctx, t, targetDSN,
		`do $$ begin create role `+role+` nologin; exception when duplicate_object then null; end $$`)
	t.Cleanup(func() {
		cctx := context.Background()
		targetExec(cctx, t, targetDSN, `drop role if exists `+role)
	})

	connID := createTargetConnection(t, env, admin, operator, "regr-"+sfx, targetConnectionParams{
		engine:          postgres.Engine,
		endpoint:        fmt.Sprintf("%s:%d", cc.Host, cc.Port),
		adminUser:       cc.User,
		adminPassword:   cc.Password,
		discoveryConfig: map[string]string{"database": cc.Database},
	})
	perm := findPermission(t, env.pool, connID, "role:"+role)

	base := "gr_regr_p_" + sfx
	principalID := createServicePrincipal(t, env, operator, base)
	t.Cleanup(func() {
		cctx := context.Background()
		targetExec(cctx, t, targetDSN, `drop role if exists `+base)
	})

	// Роль удаляется с target ПОСЛЕ discovery: permission в инвентаре ещё
	// жив, account.create пройдёт, а сам grant упадёт — ровно прод-сценарий.
	targetExec(ctx, t, targetDSN, `drop role `+role)

	items := []map[string]any{{"connection_id": connID, "permission_id": perm.ID}}
	first := grantAccessDefaultIdentity(t, env, operator, principalID, items)
	if len(first.Children) != 1 || first.Children[0].AccountCreateOperationID == nil {
		t.Fatalf("access children = %+v, want single created account", first.Children)
	}
	accountID := first.Children[0].AccountID
	waitOperation(t, env, *first.Children[0].AccountCreateOperationID, operations.StatusSuccess, 120*time.Second)
	waitOperation(t, env, first.Children[0].GrantOperationID, operations.StatusFailed, 120*time.Second)

	// 1. Провал зафиксирован в строке binding, desired не откатывается.
	status, desired, observed := bindingRow(ctx, t, env, accountID, perm.ID)
	if status != string(inventory.BindingStatusFailed) ||
		desired == nil || *desired != string(inventory.BindingPresent) ||
		observed != string(inventory.BindingUnknown) {
		t.Fatalf("after failed grant binding = %s/%v/%s, want failed/present/unknown",
			status, desired, observed)
	}

	// 2. Повторная выдача принимается (раньше — 409 access is already
	// assigned до следующего discovery) и после починки роли доводит
	// binding до synced.
	targetExec(ctx, t, targetDSN,
		`do $$ begin create role `+role+` nologin; exception when duplicate_object then null; end $$`)
	retry := grantAccessDefaultIdentity(t, env, operator, principalID, items)
	if len(retry.Children) != 1 {
		t.Fatalf("retry children = %+v, want single child", retry.Children)
	}
	if retry.Children[0].AccountID != accountID {
		t.Errorf("retry account id = %s, want reused %s", retry.Children[0].AccountID, accountID)
	}
	if retry.Children[0].BindingID != first.Children[0].BindingID {
		t.Errorf("retry binding id = %s, want reused %s (no duplicate rows)",
			retry.Children[0].BindingID, first.Children[0].BindingID)
	}
	waitOperation(t, env, retry.Children[0].GrantOperationID, operations.StatusSuccess, 120*time.Second)

	status, desired, observed = bindingRow(ctx, t, env, accountID, perm.ID)
	if status != string(inventory.BindingStatusSynced) ||
		desired == nil || *desired != string(inventory.BindingPresent) ||
		observed != string(inventory.BindingPresent) {
		t.Fatalf("after regrant binding = %s/%v/%s, want synced/present/present",
			status, desired, observed)
	}

	// 3. Право реально действует на target: членство роли восстановлено.
	if !targetHasMembership(ctx, t, targetDSN, role, base) {
		t.Errorf("target role %s has no member %s after regrant", role, base)
	}
}
