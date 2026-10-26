//go:build integration

package maintenance

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/principals"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

// stubPurgeEnqueuer записывает поставленные account.delete, не создавая
// операций: исполнение worker'а в этом тесте не нужно.
type stubPurgeEnqueuer struct{ enqueued []uuid.UUID }

func (s *stubPurgeEnqueuer) EnqueuePurgeDelete(_ context.Context, _ pgx.Tx, accountID uuid.UUID, _ string) (bool, error) {
	s.enqueued = append(s.enqueued, accountID)
	return true, nil
}

// stubCredentialPurger записывает зачищенные пары (principal, environment).
type stubCredentialPurger struct{ deleted []string }

func (s *stubCredentialPurger) DeletePrincipalCredential(_ context.Context, principalID uuid.UUID, environment string) error {
	s.deleted = append(s.deleted, principalID.String()+" "+environment)
	return nil
}

func insertPurgePrincipal(ctx context.Context, t *testing.T, pool *pgxpool.Pool, purgeAfter time.Time) principals.Principal {
	t.Helper()
	p, err := principals.NewStore().Create(ctx, pool, principals.CreateParams{
		Type: principals.TypeHuman, DisplayName: "itest purge " + uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create principal: %v", err)
	}
	if _, err := principals.NewStore().SetStatus(ctx, pool, p.ID, principals.StatusPendingPurge); err != nil {
		t.Fatalf("set pending_purge: %v", err)
	}
	if _, err := principals.NewStore().SetPurgeAfter(ctx, pool, p.ID, &purgeAfter); err != nil {
		t.Fatalf("set purge_after: %v", err)
	}
	return p
}

func insertPurgeAccount(ctx context.Context, t *testing.T, pool *pgxpool.Pool,
	connectionID, principalID uuid.UUID, kind, ownership, status string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(ctx, `
		insert into accounts (connection_id, principal_id, kind, engine_identity, status, ownership)
		values ($1, $2, $3, $4, $5, $6)
		returning id`,
		connectionID, principalID, kind, "itest_purge_"+uuid.NewString()[:8], status, ownership,
	).Scan(&id)
	if err != nil {
		t.Fatalf("insert account: %v", err)
	}
	return id
}

// Конвергентность фазы 2: первый прогон ставит удаления живых
// managed-логинов и не финализирует; после того как учётки удалены, второй
// прогон зачищает секреты всех окружений реестра, отвязывает остальных и
// переводит принципала в deleted с audit principal.purged. Принципал со
// сроком в будущем не затрагивается вовсе.
func TestIntegrationPurgeExpiredPrincipals(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	conn := newConn(ctx, t, pool)

	envName := "purge-" + uuid.NewString()[:8]
	if _, err := pool.Exec(ctx,
		`insert into environments (name) values ($1) on conflict do nothing`, envName); err != nil {
		t.Fatalf("insert environment: %v", err)
	}

	due := insertPurgePrincipal(ctx, t, pool, time.Now().Add(-time.Hour))
	managed := insertPurgeAccount(ctx, t, pool, conn.ID, due.ID, "login", "managed", "active")
	unmanaged := insertPurgeAccount(ctx, t, pool, conn.ID, due.ID, "login", "unmanaged", "active")
	notDue := insertPurgePrincipal(ctx, t, pool, time.Now().Add(24*time.Hour))

	enqueuer := &stubPurgeEnqueuer{}
	creds := &stubCredentialPurger{}
	runner := New(pool, Config{}).
		WithAudit(audit.NewWriter()).
		WithPurge(enqueuer, creds)

	stats, err := runner.RunOnce(ctx)
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	if len(enqueuer.enqueued) != 1 || enqueuer.enqueued[0] != managed {
		t.Fatalf("enqueued = %v, want exactly the managed login %s", enqueuer.enqueued, managed)
	}
	if stats.PurgeDeletesEnqueued < 1 {
		t.Errorf("stats.PurgeDeletesEnqueued = %d, want >= 1", stats.PurgeDeletesEnqueued)
	}
	stored, err := principals.NewStore().Get(ctx, pool, due.ID)
	if err != nil {
		t.Fatalf("get principal: %v", err)
	}
	if stored.Status != principals.StatusPendingPurge {
		t.Fatalf("status after first run = %q, want pending_purge (deletion still in flight)", stored.Status)
	}

	// Worker «удалил» учётку: помечаем tombstone напрямую.
	if _, err := pool.Exec(ctx,
		`update accounts set status = 'deleted', updated_at = now() where id = $1`, managed); err != nil {
		t.Fatalf("mark account deleted: %v", err)
	}

	enqueuer.enqueued = nil
	if _, err := runner.RunOnce(ctx); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if len(enqueuer.enqueued) != 0 {
		t.Errorf("second run enqueued %v, want nothing", enqueuer.enqueued)
	}
	stored, err = principals.NewStore().Get(ctx, pool, due.ID)
	if err != nil {
		t.Fatalf("get principal after finalize: %v", err)
	}
	if stored.Status != principals.StatusDeleted {
		t.Errorf("status after finalize = %q, want deleted", stored.Status)
	}
	found := false
	for _, entry := range creds.deleted {
		if entry == due.ID.String()+" "+envName {
			found = true
		}
	}
	if !found {
		t.Errorf("credential purge entries %v miss environment %s", creds.deleted, envName)
	}
	acct, err := inventory.NewStore().GetAccount(ctx, pool, unmanaged)
	if err != nil {
		t.Fatalf("get unmanaged account: %v", err)
	}
	if acct.PrincipalID != nil {
		t.Errorf("unmanaged account still linked to purged principal")
	}
	events, err := audit.NewWriter().List(ctx, pool, audit.Filter{Actions: []string{"principal.purged"}}, 100, 0)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	foundAudit := false
	for _, ev := range events {
		if ev.PrincipalID != nil && *ev.PrincipalID == due.ID {
			foundAudit = true
		}
	}
	if !foundAudit {
		t.Error("principal.purged audit event not found")
	}

	// Принципал с будущим сроком не тронут.
	stored, err = principals.NewStore().Get(ctx, pool, notDue.ID)
	if err != nil {
		t.Fatalf("get not-due principal: %v", err)
	}
	if stored.Status != principals.StatusPendingPurge {
		t.Errorf("not-due principal status = %q, want pending_purge", stored.Status)
	}
}
