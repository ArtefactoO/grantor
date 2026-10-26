//go:build integration

// Чтение pg_hba_file_rules в Topology. Главный инвариант — недоступность
// правил НЕ валит discovery: view появилась в PostgreSQL 15 и требует
// superuser либо явного GRANT, а инвентаризация обязана работать и без неё.
package postgres_test

import (
	"context"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
)

func TestDiscoverHBARules(t *testing.T) {
	dsn := targetDSN(t)
	ctx := context.Background()
	ensureFixture(ctx, t, dsn)

	snap, err := postgres.New().Discover(ctx, targetConnection(t, dsn))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	raw, ok := snap.Topology["hba_rules"]
	if !ok {
		// PostgreSQL < 15 или admin без прав: ключа нет — это штатно.
		t.Skip("target does not expose pg_hba_file_rules to the admin role")
	}
	rules, ok := raw.([]map[string]any)
	if !ok {
		t.Fatalf("hba_rules has type %T, want []map[string]any", raw)
	}
	if len(rules) == 0 {
		t.Fatal("hba_rules is empty: a running server always has at least one rule")
	}
	for _, field := range []string{"number", "type", "databases", "users", "auth_method", "error"} {
		if _, ok := rules[0][field]; !ok {
			t.Errorf("rule is missing field %q: %+v", field, rules[0])
		}
	}

	// Повторный снимок обязан дать тот же порядок: contract-тест
	// DiscoveryIsRepeatable опирается на детерминированность.
	again, err := postgres.New().Discover(ctx, targetConnection(t, dsn))
	if err != nil {
		t.Fatalf("second Discover: %v", err)
	}
	second, _ := again.Topology["hba_rules"].([]map[string]any)
	if len(second) != len(rules) {
		t.Errorf("rule count changed between snapshots: %d -> %d", len(rules), len(second))
	}
	for i := range rules {
		if rules[i]["number"] != second[i]["number"] {
			t.Errorf("rule order changed at %d: %v -> %v", i, rules[i]["number"], second[i]["number"])
		}
	}
}

// Админ без прав на view: discovery обязан пройти успешно и просто не
// положить ключ. Это главный инвариант чтения pg_hba.
func TestDiscoverHBARulesWithoutAccess(t *testing.T) {
	dsn := targetDSN(t)
	ctx := context.Background()
	ensureFixture(ctx, t, dsn)

	limited := "gr_hba_limited"
	admin := connectTarget(ctx, t, dsn, "")
	defer closeTarget(ctx, admin)
	if _, err := admin.Exec(ctx,
		`do $$ begin create role `+limited+` login password 'hba-probe-secret' createrole;
		 exception when duplicate_object then null; end $$`); err != nil {
		t.Fatalf("create limited admin: %v", err)
	}
	t.Cleanup(func() {
		cctx := context.Background()
		cleanup := connectTarget(cctx, t, dsn, "")
		defer closeTarget(cctx, cleanup)
		if _, err := cleanup.Exec(cctx, `drop role if exists `+limited); err != nil {
			t.Logf("cleanup limited admin: %v", err)
		}
	})

	cfg := targetConnection(t, dsn)
	cfg.AdminCredential.Username = limited
	cfg.AdminCredential.Secret = []byte("hba-probe-secret")

	snap, err := postgres.New().Discover(ctx, cfg)
	if err != nil {
		t.Fatalf("Discover with a limited admin must succeed: %v", err)
	}
	if _, ok := snap.Topology["hba_rules"]; ok {
		t.Error("hba_rules is present for a role without access to pg_hba_file_rules")
	}
	if len(snap.Accounts) == 0 {
		t.Error("discovery returned no accounts: inventory must work without pg_hba access")
	}
}
