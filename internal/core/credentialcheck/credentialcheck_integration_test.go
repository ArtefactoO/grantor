//go:build integration

package credentialcheck

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

// fakeVault отдаёт заранее заданные текущие версии по путям. Реальный Vault
// здесь не нужен: сверка использует только номер версии из метаданных, а
// поведение самого Vault покрыто тестами его провайдера.
type fakeVault struct {
	versions map[string]int
	err      error
	// calls — обращения по каждому пути. Именно по пути, а не общим
	// счётчиком: прогон сверяет все анкерованные аккаунты базы, включая
	// оставленные соседними тестами, и общее число ничего не доказывало бы.
	calls map[string]int
}

func newFakeVault(versions map[string]int, err error) *fakeVault {
	return &fakeVault{versions: versions, err: err, calls: map[string]int{}}
}

func (f *fakeVault) Metadata(_ context.Context, path string) (*vault.Metadata, error) {
	f.calls[path]++
	if f.err != nil {
		return nil, f.err
	}
	v, ok := f.versions[path]
	if !ok {
		return nil, errors.New("no such secret")
	}
	return &vault.Metadata{CurrentVersion: v}, nil
}

// newAnchoredAccount создаёт managed-аккаунт с якорем версии. Прямой SQL:
// тест наполняет состояние, а не проверяет путь ротации.
func newAnchoredAccount(ctx context.Context, t *testing.T, pool *pgxpool.Pool,
	vaultPath string, anchor, observed int) (uuid.UUID, uuid.UUID) {
	t.Helper()
	conn, err := connections.NewStore().Create(ctx, pool, connections.CreateParams{
		DisplayName: "itest-credcheck-" + uuid.NewString(),
		Engine:      "postgres",
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	acct, err := inventory.NewStore().CreateManagedAccount(ctx, pool, inventory.CreateManagedAccountParams{
		ConnectionID:   conn.ID,
		EngineIdentity: "itest_" + uuid.NewString()[:8],
		CredentialMode: "generated",
		VaultPath:      vaultPath,
	})
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		update accounts set ownership = 'managed', vault_path = $2,
			credential_version = $3, credential_observed_version = $4
		where id = $1`, acct.ID, vaultPath, anchor, observed); err != nil {
		t.Fatalf("anchor account: %v", err)
	}
	return conn.ID, acct.ID
}

func accountVersions(ctx context.Context, t *testing.T, pool *pgxpool.Pool, id uuid.UUID) (int, int) {
	t.Helper()
	var anchor, observed int
	if err := pool.QueryRow(ctx,
		`select credential_version, credential_observed_version from accounts where id = $1`,
		id).Scan(&anchor, &observed); err != nil {
		t.Fatalf("read versions: %v", err)
	}
	return anchor, observed
}

func TestIntegrationRunOnceDetectsDivergence(t *testing.T) {
	ctx := t.Context()
	pool := pgtest.Pool(t)
	path := "principals/" + uuid.NewString() + "/environments/dev/credential"
	connID, acctID := newAnchoredAccount(ctx, t, pool, path, 3, 3)

	// В Vault версия ушла вперёд: секрет переписали мимо grantor.
	fv := newFakeVault(map[string]int{path: 5}, nil)
	runner := New(pool, fv, Config{Interval: time.Minute}).WithAudit(audit.NewWriter())

	stats, err := runner.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if stats.Diverged != 1 || stats.NewlyDiverged != 1 {
		t.Errorf("stats = %+v, want one divergence reported as new", stats)
	}

	anchor, observed := accountVersions(ctx, t, pool, acctID)
	if anchor != 3 || observed != 5 {
		t.Errorf("versions = %d/%d, want anchor 3 and observed 5", anchor, observed)
	}

	// Расхождение обязано быть видно оператору в разделе дрифта, иначе
	// обнаружение бессмысленно.
	findings, err := inventory.NewStore().DriftFindings(ctx, pool, &connID)
	if err != nil {
		t.Fatalf("drift findings: %v", err)
	}
	var found bool
	for _, f := range findings {
		if f.Kind == inventory.DriftKindCredentialDiverged && f.AccountID != nil && *f.AccountID == acctID {
			found = true
		}
	}
	if !found {
		t.Errorf("drift findings = %+v, want a credential_diverged finding", findings)
	}

	// Повторный прогон видит то же расхождение, но нового audit не пишет:
	// одна забытая правка не должна засыпать журнал.
	second, err := runner.RunOnce(ctx)
	if err != nil {
		t.Fatalf("second RunOnce: %v", err)
	}
	if second.Diverged != 1 || second.NewlyDiverged != 0 {
		t.Errorf("second run stats = %+v, want the divergence still seen but not new", second)
	}
}

func TestIntegrationRunOnceMatchingVersionIsQuiet(t *testing.T) {
	ctx := t.Context()
	pool := pgtest.Pool(t)
	path := "accounts/" + uuid.NewString() + "/credential"
	connID, acctID := newAnchoredAccount(ctx, t, pool, path, 7, 7)

	fv := newFakeVault(map[string]int{path: 7}, nil)
	stats, err := New(pool, fv, Config{Interval: time.Minute}).RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if stats.Diverged != 0 {
		t.Errorf("stats = %+v, want no divergence", stats)
	}
	findings, err := inventory.NewStore().DriftFindings(ctx, pool, &connID)
	if err != nil {
		t.Fatalf("drift findings: %v", err)
	}
	for _, f := range findings {
		if f.Kind == inventory.DriftKindCredentialDiverged && f.AccountID != nil && *f.AccountID == acctID {
			t.Errorf("unexpected credential_diverged finding: %+v", f)
		}
	}
}

// Недоступный Vault ничего не доказывает: наблюдаемая версия обязана
// остаться прежней, а расхождение — не появиться. Это прямое следствие
// правила «временная недоступность dependency не превращается в вывод».
func TestIntegrationRunOnceVaultUnavailable(t *testing.T) {
	ctx := t.Context()
	pool := pgtest.Pool(t)
	path := "accounts/" + uuid.NewString() + "/credential"
	_, acctID := newAnchoredAccount(ctx, t, pool, path, 4, 4)

	fv := newFakeVault(nil, errors.New("vault is down"))
	stats, err := New(pool, fv, Config{Interval: time.Minute}).RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if stats.PathsUnavailable == 0 {
		t.Errorf("stats = %+v, want the unavailable path reported", stats)
	}
	if _, observed := accountVersions(ctx, t, pool, acctID); observed != 4 {
		t.Errorf("observed version = %d, want it untouched at 4", observed)
	}
}

// Общий секрет принципала разделяют несколько аккаунтов: Vault обязан
// опрашиваться один раз на путь, а не на аккаунт.
func TestIntegrationRunOnceQueriesEachPathOnce(t *testing.T) {
	ctx := t.Context()
	pool := pgtest.Pool(t)
	path := "principals/" + uuid.NewString() + "/environments/dev/credential"
	_, first := newAnchoredAccount(ctx, t, pool, path, 2, 2)
	_, second := newAnchoredAccount(ctx, t, pool, path, 2, 2)

	fv := newFakeVault(map[string]int{path: 9}, nil)
	if _, err := New(pool, fv, Config{Interval: time.Minute}).RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if fv.calls[path] != 1 {
		t.Errorf("vault metadata calls for the shared path = %d, want 1", fv.calls[path])
	}
	for _, id := range []uuid.UUID{first, second} {
		if _, observed := accountVersions(ctx, t, pool, id); observed != 9 {
			t.Errorf("account %s observed version = %d, want 9", id, observed)
		}
	}
}

// Аккаунт без якоря в сверку не попадает: сравнивать не с чем, и ложный
// finding хуже отсутствующего.
func TestIntegrationRunOnceSkipsAccountsWithoutAnchor(t *testing.T) {
	ctx := t.Context()
	pool := pgtest.Pool(t)
	path := "accounts/" + uuid.NewString() + "/credential"
	_, acctID := newAnchoredAccount(ctx, t, pool, path, 0, 0)

	fv := newFakeVault(map[string]int{path: 12}, nil)
	if _, err := New(pool, fv, Config{Interval: time.Minute}).RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if fv.calls[path] != 0 {
		t.Errorf("vault metadata calls = %d, want none for an account without an anchor", fv.calls[path])
	}
	if _, observed := accountVersions(ctx, t, pool, acctID); observed != 0 {
		t.Errorf("observed version = %d, want it untouched", observed)
	}
}
