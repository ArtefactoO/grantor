//go:build integration

// Тест data-миграции 00015_binding_scope_backfill: переноса managed bindings,
// созданных без области действия, в собственную область их права.
//
// Миграция исполняется прямо из встроенной FS (единственный источник истины) в
// транзакции, которая в конце откатывается: миграция изменяет строки по всей
// базе, а тестовая база общая для пакетов.
package inventory_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/db/migrations"
	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

// backfillMigrationFile — файл проверяемой миграции во встроенной FS.
const backfillMigrationFile = "00015_binding_scope_backfill.sql"

// backfillUpStatements возвращает statements секции `+goose Up` миграции.
// Комментарии отбрасываются до разбиения: точка с запятой встречается и в
// русскоязычном тексте комментария. В самой миграции нет ни функций, ни
// DO-блоков, поэтому вне комментариев `;` разделяет ровно statements.
func backfillUpStatements(t *testing.T) []string {
	t.Helper()
	raw, err := migrations.FS.ReadFile(backfillMigrationFile)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	body := string(raw)
	up := strings.Index(body, "-- +goose Up")
	down := strings.Index(body, "-- +goose Down")
	if up < 0 || down < 0 || down < up {
		t.Fatalf("migration %s has no Up/Down sections", backfillMigrationFile)
	}
	var code strings.Builder
	for _, line := range strings.Split(body[up:down], "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		code.WriteString(line)
		code.WriteString("\n")
	}
	var out []string
	for _, chunk := range strings.Split(code.String(), ";") {
		if strings.TrimSpace(chunk) != "" {
			out = append(out, chunk)
		}
	}
	if len(out) != 2 {
		t.Fatalf("parsed %d statements from %s, want 2: %q", len(out), backfillMigrationFile, out)
	}
	return out
}

// runBackfill выполняет миграцию в переданной транзакции.
func runBackfill(ctx context.Context, t *testing.T, tx pgx.Tx, statements []string) {
	t.Helper()
	for i, stmt := range statements {
		if _, err := tx.Exec(ctx, stmt); err != nil {
			t.Fatalf("backfill statement %d: %v", i, err)
		}
	}
}

// legacyManagedBinding вставляет строку, какую создавала выдача до вывода
// области: managed, desired present, без scope и в ложном drift.
func legacyManagedBinding(ctx context.Context, t *testing.T, tx pgx.Tx, accountID, permissionID uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := tx.QueryRow(ctx, `
		insert into bindings (
			account_id, permission_definition_id, scope_resource_id,
			source, desired_state, observed_state, status
		) values ($1, $2, null, 'service', 'present', 'absent', 'drift')
		returning id`, accountID, permissionID).Scan(&id); err != nil {
		t.Fatalf("insert legacy binding: %v", err)
	}
	return id
}

// bindingsOf возвращает bindings аккаунта на конкретное право.
func bindingsOf(ctx context.Context, t *testing.T, tx pgx.Tx, accountID, permissionID uuid.UUID) []inventory.Binding {
	t.Helper()
	all, err := inventory.NewStore().ListBindingsByAccount(ctx, tx, accountID)
	if err != nil {
		t.Fatalf("list bindings: %v", err)
	}
	var out []inventory.Binding
	for i := range all {
		if all[i].PermissionDefinitionID == permissionID {
			out = append(out, all[i])
		}
	}
	return out
}

// scopedSnapshot — инвентарь движка, у которого право неотделимо от ресурса:
// база app, право role:app.read с областью db:app и наблюдаемый доступ
// svc_observed в этой же области. svc_orphan доступа в целевой системе не
// имеет — его legacy-строке переносить область не с чего.
func scopedSnapshot() *adapter.Snapshot {
	return &adapter.Snapshot{
		ServerVersion: "7.0",
		Resources: []adapter.ObservedResource{
			{Kind: "database", ExternalID: "db:app", Name: "app", CanonicalPath: "app", Fingerprint: "fp-db"},
		},
		Accounts: []adapter.ObservedAccount{
			{Kind: "login", EngineIdentity: "svc_observed"},
			{Kind: "login", EngineIdentity: "svc_orphan"},
		},
		Permissions: []adapter.ObservedPermission{
			{ExternalID: "role:app.read", Name: "read", ScopeExternalID: "db:app", Assignable: true},
			{ExternalID: "role:cluster-admin", Name: "cluster-admin", Assignable: true},
		},
		Bindings: []adapter.ObservedBinding{
			{AccountEngineIdentity: "svc_observed", PermissionExternalID: "role:app.read", ScopeExternalID: "db:app"},
		},
		ObservedAt: time.Now(),
	}
}

func TestBindingScopeBackfillMigration(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	statements := backfillUpStatements(t)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	// Миграция затрагивает строки по всей базе, поэтому весь тест живёт в
	// откатываемой транзакции.
	defer tx.Rollback(ctx) //nolint:errcheck

	conn, err := connections.NewStore().Create(ctx, tx, connections.CreateParams{
		DisplayName: "itest-backfill-" + uuid.NewString(),
		Engine:      "mongodb",
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	store := inventory.NewStore()
	if _, err := store.UpsertSnapshot(ctx, tx, conn.ID, scopedSnapshot(), time.Now()); err != nil {
		t.Fatalf("upsert snapshot: %v", err)
	}

	resources, err := store.ListResources(ctx, tx, conn.ID)
	if err != nil {
		t.Fatalf("list resources: %v", err)
	}
	dbResource := resourceByExternalID(t, resources, "db:app")

	permissions, err := store.ListPermissions(ctx, tx, conn.ID)
	if err != nil {
		t.Fatalf("list permissions: %v", err)
	}
	var scoped, clusterWide inventory.Permission
	for _, p := range permissions {
		switch p.ExternalID {
		case "role:app.read":
			scoped = p
		case "role:cluster-admin":
			clusterWide = p
		}
	}
	if scoped.ScopeResourceID == nil || *scoped.ScopeResourceID != dbResource.ID {
		t.Fatalf("permission role:app.read scope = %v, want %s", scoped.ScopeResourceID, dbResource.ID)
	}

	accounts, err := store.ListAccounts(ctx, tx, conn.ID)
	if err != nil {
		t.Fatalf("list accounts: %v", err)
	}
	var observedAcct, orphanAcct inventory.Account
	for _, a := range accounts {
		switch a.EngineIdentity {
		case "svc_observed":
			observedAcct = a
		case "svc_orphan":
			orphanAcct = a
		}
	}

	// Legacy-состояние: managed-строка без области у обоих аккаунтов плюс
	// managed-строка на cluster-wide право (её трогать нельзя).
	managedID := legacyManagedBinding(ctx, t, tx, observedAcct.ID, scoped.ID)
	orphanID := legacyManagedBinding(ctx, t, tx, orphanAcct.ID, scoped.ID)
	clusterWideID := legacyManagedBinding(ctx, t, tx, observedAcct.ID, clusterWide.ID)
	if got := bindingsOf(ctx, t, tx, observedAcct.ID, scoped.ID); len(got) != 2 {
		t.Fatalf("legacy rows on scoped permission = %d, want 2 (managed + observed twin)", len(got))
	}

	runBackfill(ctx, t, tx, statements)

	// 1. Пара схлопнулась в одну строку — ту же managed, в области права.
	merged := bindingsOf(ctx, t, tx, observedAcct.ID, scoped.ID)
	if len(merged) != 1 {
		t.Fatalf("rows after backfill = %d, want 1: %+v", len(merged), merged)
	}
	if merged[0].ID != managedID {
		t.Errorf("surviving binding = %s, want the managed row %s", merged[0].ID, managedID)
	}
	if !inventory.SameScope(merged[0].ScopeResourceID, scoped.ScopeResourceID) {
		t.Errorf("scope = %v, want %v", merged[0].ScopeResourceID, scoped.ScopeResourceID)
	}
	if merged[0].Source != string(inventory.BindingSourceService) ||
		merged[0].DesiredState == nil || *merged[0].DesiredState != inventory.BindingPresent {
		t.Errorf("managed intent lost: source=%q desired=%v", merged[0].Source, merged[0].DesiredState)
	}
	if merged[0].ObservedState != inventory.BindingUnknown || merged[0].Status != inventory.BindingStatusPending {
		t.Errorf("observed/status = %q/%q, want unknown/pending (false drift must be cleared)",
			merged[0].ObservedState, merged[0].Status)
	}

	// 2. Managed-строка без наблюдаемого двойника тоже получает область.
	orphan := bindingsOf(ctx, t, tx, orphanAcct.ID, scoped.ID)
	if len(orphan) != 1 {
		t.Fatalf("orphan rows = %d, want 1", len(orphan))
	}
	if orphan[0].ID != orphanID || !inventory.SameScope(orphan[0].ScopeResourceID, scoped.ScopeResourceID) {
		t.Errorf("orphan binding = %+v, want %s in permission scope", orphan[0], orphanID)
	}

	// 3. Cluster-wide право не затронуто: область остаётся пустой.
	untouched := bindingsOf(ctx, t, tx, observedAcct.ID, clusterWide.ID)
	if len(untouched) != 1 || untouched[0].ID != clusterWideID || untouched[0].ScopeResourceID != nil {
		t.Errorf("cluster-wide binding changed: %+v", untouched)
	}
	if untouched[0].Status != inventory.BindingStatusDrift {
		t.Errorf("cluster-wide binding status = %q, want drift (must stay as it was)", untouched[0].Status)
	}

	// 4. Идемпотентность: повторный прогон ничего не меняет.
	runBackfill(ctx, t, tx, statements)
	again := bindingsOf(ctx, t, tx, observedAcct.ID, scoped.ID)
	if len(again) != 1 || again[0].ID != merged[0].ID || again[0].UpdatedAt != merged[0].UpdatedAt {
		t.Errorf("second backfill run changed rows: %+v, want %+v", again, merged)
	}
}

// TestBindingScopeBackfillKeepsAdoptedTwin: если наблюдаемый двойник уже
// усыновлён (по нему принято решение), обе строки выражают разные намерения —
// миграция их не трогает и оставляет оператору.
func TestBindingScopeBackfillKeepsAdoptedTwin(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	statements := backfillUpStatements(t)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	conn, err := connections.NewStore().Create(ctx, tx, connections.CreateParams{
		DisplayName: "itest-backfill-adopted-" + uuid.NewString(),
		Engine:      "mongodb",
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	store := inventory.NewStore()
	if _, err := store.UpsertSnapshot(ctx, tx, conn.ID, scopedSnapshot(), time.Now()); err != nil {
		t.Fatalf("upsert snapshot: %v", err)
	}
	permissions, err := store.ListPermissions(ctx, tx, conn.ID)
	if err != nil {
		t.Fatalf("list permissions: %v", err)
	}
	var scoped inventory.Permission
	for _, p := range permissions {
		if p.ExternalID == "role:app.read" {
			scoped = p
		}
	}
	accounts, err := store.ListAccounts(ctx, tx, conn.ID)
	if err != nil {
		t.Fatalf("list accounts: %v", err)
	}
	var observedAcct inventory.Account
	for _, a := range accounts {
		if a.EngineIdentity == "svc_observed" {
			observedAcct = a
		}
	}

	// Двойник усыновлён: desired_state задан.
	if _, err := tx.Exec(ctx, `
		update bindings set desired_state = 'present', source = 'service'
		where account_id = $1 and permission_definition_id = $2 and scope_resource_id is not null`,
		observedAcct.ID, scoped.ID); err != nil {
		t.Fatalf("adopt twin: %v", err)
	}
	legacyID := legacyManagedBinding(ctx, t, tx, observedAcct.ID, scoped.ID)

	runBackfill(ctx, t, tx, statements)

	rows := bindingsOf(ctx, t, tx, observedAcct.ID, scoped.ID)
	if len(rows) != 2 {
		t.Fatalf("rows after backfill = %d, want 2 (a conflicting pair is left to the operator): %+v", len(rows), rows)
	}
	for _, b := range rows {
		if b.ID == legacyID && b.ScopeResourceID != nil {
			t.Errorf("legacy row was moved into a scope already taken by an adopted twin: %+v", b)
		}
	}
}
