//go:build integration

package maintenance

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	dto "github.com/prometheus/client_model/go"

	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/metrics"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

// activateWithAdminCredential переводит подключение в active и проставляет
// vault_admin_path + admin_credential_set_at с заданным возрастом. Так
// подключение становится кандидатом эвалуации старения.
func activateWithAdminCredential(ctx context.Context, t *testing.T, pool *pgxpool.Pool, id uuid.UUID, age time.Duration) {
	t.Helper()
	setAt := time.Now().Add(-age)
	_, err := pool.Exec(ctx, `
		update connections
		set status = 'active',
		    vault_admin_path = $2,
		    admin_credential_set_at = $3,
		    updated_at = now()
		where id = $1`,
		id, "connections/"+id.String()+"/admin", setAt)
	if err != nil {
		t.Fatalf("activate connection %s: %v", id, err)
	}
}

// agedAuditCount считает события security.admin_credential_aged по
// connection_id.
func agedAuditCount(ctx context.Context, t *testing.T, pool *pgxpool.Pool, connID uuid.UUID) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx, `
		select count(*) from audit_events
		where action = $1 and connection_id = $2
		  and metadata->>'reason' = 'admin_credential_aged'`,
		auditActionAdminCredentialAged, connID,
	).Scan(&n); err != nil {
		t.Fatalf("count aged audit for %s: %v", connID, err)
	}
	return n
}

// ageGaugeValue возвращает значение gauge возраста admin credential для
// connection_id и признак его наличия среди series.
func ageGaugeValue(t *testing.T, connID uuid.UUID) (float64, bool) {
	t.Helper()
	families, err := metrics.Gatherer().Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, f := range families {
		if f.GetName() != "grantor_connection_admin_credential_age_seconds" {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "connection_id" && l.GetValue() == connID.String() {
					return m.GetGauge().GetValue(), true
				}
			}
		}
	}
	return 0, false
}

func TestRunOnceAdminCredentialAging(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)

	// Устаревшее подключение: admin credential старше порога (90 суток).
	agedConn := newConn(ctx, t, pool)
	activateWithAdminCredential(ctx, t, pool, agedConn.ID, 120*24*time.Hour)

	// Свежее подключение: admin credential моложе порога.
	freshConn := newConn(ctx, t, pool)
	activateWithAdminCredential(ctx, t, pool, freshConn.ID, time.Hour)

	// Подключение без admin credential (draft, vault_admin_path пуст) не
	// эвалуируется вовсе.
	draftConn := newConn(ctx, t, pool)

	const maxAge = 90 * 24 * time.Hour
	runner := New(pool, Config{AdminCredentialMaxAge: maxAge}).WithAudit(audit.NewWriter())
	stats, err := runner.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	// RunOnce глобален — «не меньше» ожидаемого по этому прогону.
	if stats.AdminCredentialsAged < 1 {
		t.Errorf("AdminCredentialsAged = %d, want >= 1", stats.AdminCredentialsAged)
	}

	// audit: ровно одно событие для устаревшего, ни одного для свежего/draft.
	if got := agedAuditCount(ctx, t, pool, agedConn.ID); got != 1 {
		t.Errorf("aged connection audit events = %d, want 1", got)
	}
	if got := agedAuditCount(ctx, t, pool, freshConn.ID); got != 0 {
		t.Errorf("fresh connection audit events = %d, want 0", got)
	}
	if got := agedAuditCount(ctx, t, pool, draftConn.ID); got != 0 {
		t.Errorf("draft connection audit events = %d, want 0", got)
	}

	// метрики: gauge возраста выставлен и для устаревшего, и для свежего
	// (эвалуируются оба), draft — нет (нет admin credential).
	agedAge, ok := ageGaugeValue(t, agedConn.ID)
	if !ok {
		t.Fatal("aged connection has no age gauge series")
	}
	if agedAge < maxAge.Seconds() {
		t.Errorf("aged connection age gauge = %v, want >= %v (over threshold)", agedAge, maxAge.Seconds())
	}
	freshAge, ok := ageGaugeValue(t, freshConn.ID)
	if !ok {
		t.Fatal("fresh connection has no age gauge series")
	}
	if freshAge >= maxAge.Seconds() {
		t.Errorf("fresh connection age gauge = %v, want < %v", freshAge, maxAge.Seconds())
	}
	if _, ok := ageGaugeValue(t, draftConn.ID); ok {
		t.Error("draft connection (no admin credential) has an age gauge series, want none")
	}

	// grantor_connection_admin_credential_aged (скалярный gauge) выставлен.
	if !scalarGaugeSet(t, "grantor_connection_admin_credential_aged") {
		t.Error("grantor_connection_admin_credential_aged gauge not exported after run")
	}
}

// scalarGaugeSet сообщает, экспортирован ли скалярный gauge с непустым набором
// series (значение >= 0 достаточно как признак, что эвалуация его выставила).
func scalarGaugeSet(t *testing.T, name string) bool {
	t.Helper()
	families, err := metrics.Gatherer().Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, f := range families {
		if f.GetName() == name && f.GetType() == dto.MetricType_GAUGE && len(f.GetMetric()) > 0 {
			return true
		}
	}
	return false
}

func TestRunOnceAdminCredentialAgingDisabled(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)

	agedConn := newConn(ctx, t, pool)
	activateWithAdminCredential(ctx, t, pool, agedConn.ID, 120*24*time.Hour)

	// Порог не задан (0) — эвалуация выключена: ни findings, ни счётчика.
	runner := New(pool, Config{}).WithAudit(audit.NewWriter())
	stats, err := runner.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if stats.AdminCredentialsAged != 0 {
		t.Errorf("AdminCredentialsAged = %d, want 0 (disabled)", stats.AdminCredentialsAged)
	}
	if got := agedAuditCount(ctx, t, pool, agedConn.ID); got != 0 {
		t.Errorf("aged audit events with disabled aging = %d, want 0", got)
	}
}
