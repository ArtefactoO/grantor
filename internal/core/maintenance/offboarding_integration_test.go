//go:build integration

package maintenance

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/principals"
	"github.com/ArtefactoO/grantor/internal/directory"
	"github.com/ArtefactoO/grantor/internal/metrics"
	"github.com/ArtefactoO/grantor/internal/secret"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

type failingDirectoryProvider struct{}

func (failingDirectoryProvider) Statuses(context.Context, []string) (map[string]directory.Status, error) {
	return nil, errors.New("directory unavailable")
}

// ldapTestProvider собирает LDAP-провайдер из GRANTOR_TEST_LDAP_* (каталог
// scripts/test-integration.sh: alice активна, carol заблокирована по
// employeeType=disabled, bob отсутствует) или пропускает тест.
func ldapTestProvider(t *testing.T) directory.Provider {
	t.Helper()
	url := os.Getenv("GRANTOR_TEST_LDAP_URL")
	if url == "" {
		t.Skip("GRANTOR_TEST_LDAP_URL is not set; skipping ldap-backed maintenance test")
	}
	p, err := directory.NewLDAP(directory.LDAPConfig{
		URL:            url,
		BindDN:         os.Getenv("GRANTOR_TEST_LDAP_BIND_DN"),
		BindPassword:   secret.FromString(os.Getenv("GRANTOR_TEST_LDAP_BIND_PASSWORD")),
		BaseDN:         os.Getenv("GRANTOR_TEST_LDAP_BASE_DN"),
		DisabledFilter: "(employeeType=disabled)",
	})
	if err != nil {
		t.Fatalf("NewLDAP: %v", err)
	}
	return p
}

// newPrincipal создаёт принципала с указанными типом и внешней identity.
func newPrincipal(ctx context.Context, t *testing.T, pool *pgxpool.Pool,
	typ principals.Type, provider, subject string) principals.Principal {
	t.Helper()
	p, err := principals.NewStore().Create(ctx, pool, principals.CreateParams{
		Type:             typ,
		DisplayName:      "itest-offb-" + uuid.NewString(),
		ExternalProvider: provider,
		ExternalSubject:  subject,
	})
	if err != nil {
		t.Fatalf("create principal %s/%s: %v", provider, subject, err)
	}
	return p
}

// principalStatus возвращает текущий статус и disabled_at принципала.
func principalStatus(ctx context.Context, t *testing.T, pool *pgxpool.Pool, id uuid.UUID) principals.Principal {
	t.Helper()
	p, err := principals.NewStore().Get(ctx, pool, id)
	if err != nil {
		t.Fatalf("get principal %s: %v", id, err)
	}
	return p
}

// newAccountFor создаёт активный managed-аккаунт принципала на новом
// connection и возвращает аккаунт.
func newAccountFor(ctx context.Context, t *testing.T, pool *pgxpool.Pool, principalID uuid.UUID) inventory.Account {
	t.Helper()
	conn := newConn(ctx, t, pool)
	account, err := inventory.NewStore().CreateManagedAccount(ctx, pool, inventory.CreateManagedAccountParams{
		ConnectionID:   conn.ID,
		EngineIdentity: "offb-" + uuid.NewString(),
		PrincipalID:    &principalID,
	})
	if err != nil {
		t.Fatalf("create account for principal %s: %v", principalID, err)
	}
	return account
}

// auditCountByReason считает audit-события действия action по принципалу
// с указанным metadata reason.
func auditCountByReason(ctx context.Context, t *testing.T, pool *pgxpool.Pool,
	action string, principalID uuid.UUID, reason string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx, `
		select count(*) from audit_events
		where action = $1 and principal_id = $2 and metadata->>'reason' = $3`,
		action, principalID, reason,
	).Scan(&n); err != nil {
		t.Fatalf("count %s audit for %s: %v", action, principalID, err)
	}
	return n
}

// offboardingAuditCount считает findings security.offboarding_incomplete
// по принципалу.
func offboardingAuditCount(ctx context.Context, t *testing.T, pool *pgxpool.Pool, principalID uuid.UUID) int {
	t.Helper()
	return auditCountByReason(ctx, t, pool, auditActionOffboardingIncomplete, principalID, "offboarding_incomplete")
}

func externalIdentityStatusAuditCount(
	ctx context.Context,
	t *testing.T,
	pool *pgxpool.Pool,
	principalID uuid.UUID,
) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx, `
		select count(*) from audit_events
		where action = $1 and principal_id = $2`,
		auditActionExternalIdentityStatusChanged, principalID,
	).Scan(&n); err != nil {
		t.Fatalf("count external identity status audits for %s: %v", principalID, err)
	}
	return n
}

func latestExternalIdentityStatusAudit(
	ctx context.Context,
	t *testing.T,
	pool *pgxpool.Pool,
	principalID uuid.UUID,
) struct {
	Provider       string  `json:"provider"`
	Status         string  `json:"status"`
	PreviousStatus *string `json:"previous_status"`
	Reason         string  `json:"reason"`
} {
	t.Helper()
	var raw []byte
	if err := pool.QueryRow(ctx, `
		select metadata from audit_events
		where action = $1 and principal_id = $2
		order by id desc limit 1`,
		auditActionExternalIdentityStatusChanged, principalID,
	).Scan(&raw); err != nil {
		t.Fatalf("read external identity status audit for %s: %v", principalID, err)
	}
	var out struct {
		Provider       string  `json:"provider"`
		Status         string  `json:"status"`
		PreviousStatus *string `json:"previous_status"`
		Reason         string  `json:"reason"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal external identity status audit %s: %v", raw, err)
	}
	return out
}

// disabledCounterValue возвращает значение counter
// grantor_principals_disabled_total для reason (0, если series нет).
func disabledCounterValue(t *testing.T, reason string) float64 {
	t.Helper()
	families, err := metrics.Gatherer().Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, f := range families {
		if f.GetName() != "grantor_principals_disabled_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "reason" && l.GetValue() == reason {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

// TestRunOnceIdPPoll — сквозной сценарий поллинга против реального LDAP:
// исчезнувший из каталога принципал выключается (+audit principal.disabled,
// +counter), заблокированный в каталоге — тоже (reason disabled), активный
// и service-принципал не трогаются; выключенный этим же прогоном принципал
// с активным аккаунтом сразу получает finding offboarding_incomplete.
// Повторный прогон идемпотентен: повторного principal.disabled нет.
func TestRunOnceIdPPoll(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	provider := ldapTestProvider(t)

	// Уникальное имя провайдера скоупит поллинг принципалами этого теста:
	// общая база содержит принципалов других тестов и прогонов.
	providerName := "ldap-itest-" + uuid.NewString()

	alice := newPrincipal(ctx, t, pool, principals.TypeHuman, providerName, "alice@grantor.test")
	bob := newPrincipal(ctx, t, pool, principals.TypeHuman, providerName, "bob@grantor.test")
	carol := newPrincipal(ctx, t, pool, principals.TypeHuman, providerName, "carol@grantor.test")
	// Service-принципал с отсутствующим в каталоге субъектом: poll обязан
	// пропустить его (в каталоге людей сервисы не живут).
	svc := newPrincipal(ctx, t, pool, principals.TypeService, providerName, "bob-svc@grantor.test")

	// У bob остаётся активный аккаунт — после выключения поллом он должен
	// дать finding offboarding_incomplete в том же прогоне.
	newAccountFor(ctx, t, pool, bob.ID)

	missingBefore := disabledCounterValue(t, metrics.ReasonDirectoryMissing)
	disabledBefore := disabledCounterValue(t, metrics.ReasonDirectoryDisabled)

	runner := New(pool, Config{}).WithAudit(audit.NewWriter()).WithDirectoryPoll(DirectoryPoll{
		Provider:          provider,
		ProviderName:      providerName,
		MissingIsDisabled: true,
	})
	stats, err := runner.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if stats.PrincipalsDisabled < 2 {
		t.Errorf("PrincipalsDisabled = %d, want >= 2 (bob missing + carol disabled)", stats.PrincipalsDisabled)
	}
	if stats.OffboardingIncomplete < 1 {
		t.Errorf("OffboardingIncomplete = %d, want >= 1 (bob keeps an active account)", stats.OffboardingIncomplete)
	}

	// Локальные статусы: alice и service нетронуты, bob и carol выключены.
	// Зеркало обновляется для всех human: active/disabled/missing→deleted;
	// service-принципал poll не затрагивает.
	if got := principalStatus(ctx, t, pool, alice.ID); got.Status != principals.StatusActive {
		t.Errorf("alice status = %q, want active", got.Status)
	} else if got.ExternalIdentityStatus == nil || *got.ExternalIdentityStatus != principals.ExternalIdentityActive {
		t.Errorf("alice external identity status = %v, want active", got.ExternalIdentityStatus)
	} else if got.ExternalIdentityCheckedAt == nil || got.ExternalIdentityStatusChangedAt == nil {
		t.Error("alice external identity timestamps are nil after successful poll")
	}
	if got := principalStatus(ctx, t, pool, svc.ID); got.Status != principals.StatusActive {
		t.Errorf("service principal status = %q, want active (poll must skip services)", got.Status)
	} else if got.ExternalIdentityStatus != nil || got.ExternalIdentityCheckedAt != nil ||
		got.ExternalIdentityStatusChangedAt != nil {
		t.Error("service principal external identity mirror changed, want untouched")
	}
	gotBob := principalStatus(ctx, t, pool, bob.ID)
	if gotBob.Status != principals.StatusDisabled {
		t.Errorf("bob status = %q, want disabled (missing in directory)", gotBob.Status)
	}
	if gotBob.DisabledAt == nil {
		t.Error("bob DisabledAt is nil after idp poll disable")
	}
	if gotBob.ExternalIdentityStatus == nil || *gotBob.ExternalIdentityStatus != principals.ExternalIdentityDeleted {
		t.Errorf("bob external identity status = %v, want deleted", gotBob.ExternalIdentityStatus)
	}
	bobExternalAudit := latestExternalIdentityStatusAudit(ctx, t, pool, bob.ID)
	if bobExternalAudit.Provider != providerName || bobExternalAudit.Status != "deleted" ||
		bobExternalAudit.PreviousStatus != nil || bobExternalAudit.Reason != "missing" {
		t.Errorf("bob external identity audit = %+v, want provider/deleted/null/missing", bobExternalAudit)
	}
	if got := principalStatus(ctx, t, pool, carol.ID); got.Status != principals.StatusDisabled {
		t.Errorf("carol status = %q, want disabled (disabled filter matched)", got.Status)
	} else if got.ExternalIdentityStatus == nil || *got.ExternalIdentityStatus != principals.ExternalIdentityDisabled {
		t.Errorf("carol external identity status = %v, want disabled", got.ExternalIdentityStatus)
	}

	// Audit: по одному principal.disabled с точной причиной; alice/svc — ни
	// одного.
	if got := auditCountByReason(ctx, t, pool, auditActionPrincipalDisabled, bob.ID, "missing"); got != 1 {
		t.Errorf("bob principal.disabled(reason=missing) audit events = %d, want 1", got)
	}
	if got := auditCountByReason(ctx, t, pool, auditActionPrincipalDisabled, carol.ID, "disabled"); got != 1 {
		t.Errorf("carol principal.disabled(reason=disabled) audit events = %d, want 1", got)
	}
	for _, untouched := range []uuid.UUID{alice.ID, svc.ID} {
		for _, reason := range []string{"missing", "disabled"} {
			if got := auditCountByReason(ctx, t, pool, auditActionPrincipalDisabled, untouched, reason); got != 0 {
				t.Errorf("untouched principal %s has %d principal.disabled(%s) audit events, want 0",
					untouched, got, reason)
			}
		}
	}

	// Finding для bob — в том же прогоне, что и выключение.
	if got := offboardingAuditCount(ctx, t, pool, bob.ID); got != 1 {
		t.Errorf("bob offboarding_incomplete audit events = %d, want 1", got)
	}
	// carol без аккаунтов findings не получает.
	if got := offboardingAuditCount(ctx, t, pool, carol.ID); got != 0 {
		t.Errorf("carol offboarding_incomplete audit events = %d, want 0", got)
	}

	// Метрики: counter переходов вырос по обеим причинам, gauge выставлен.
	if got := disabledCounterValue(t, metrics.ReasonDirectoryMissing); got < missingBefore+1 {
		t.Errorf("principals_disabled_total{reason=missing} = %v, want >= %v", got, missingBefore+1)
	}
	if got := disabledCounterValue(t, metrics.ReasonDirectoryDisabled); got < disabledBefore+1 {
		t.Errorf("principals_disabled_total{reason=disabled} = %v, want >= %v", got, disabledBefore+1)
	}
	if !scalarGaugeSet(t, "grantor_offboarding_incomplete_principals") {
		t.Error("grantor_offboarding_incomplete_principals gauge not exported after run")
	}

	// Повторный прогон идемпотентен: статусы уже disabled, повторного
	// principal.disabled нет; finding по-прежнему эмитится (один на прогон —
	// период прогона и есть троттлинг).
	if _, err := runner.RunOnce(ctx); err != nil {
		t.Fatalf("second RunOnce: %v", err)
	}
	if got := auditCountByReason(ctx, t, pool, auditActionPrincipalDisabled, bob.ID, "missing"); got != 1 {
		t.Errorf("bob principal.disabled audit events after second run = %d, want 1 (idempotent)", got)
	}
	if got := externalIdentityStatusAuditCount(ctx, t, pool, bob.ID); got != 1 {
		t.Errorf("bob external identity status audits after repeated status = %d, want 1", got)
	}
	if got := offboardingAuditCount(ctx, t, pool, bob.ID); got != 2 {
		t.Errorf("bob offboarding_incomplete audit events after second run = %d, want 2 (one per run)", got)
	}
}

// TestRunOnceIdPPollMissingPolicy: при MissingIsDisabled=false отсутствие
// всё равно зеркалится как external deleted, но локальный active principal
// не выключается.
func TestRunOnceIdPPollMissingPolicy(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	providerName := "static-itest-" + uuid.NewString()
	p := newPrincipal(ctx, t, pool, principals.TypeHuman, providerName, "missing@grantor.test")

	runner := New(pool, Config{}).WithDirectoryPoll(DirectoryPoll{
		Provider:          directory.NewStatic(nil, []string{p.ExternalSubject}),
		ProviderName:      providerName,
		MissingIsDisabled: false,
	})
	if _, err := runner.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	got := principalStatus(ctx, t, pool, p.ID)
	if got.Status != principals.StatusActive {
		t.Errorf("local status = %q, want active (missing policy disabled)", got.Status)
	}
	if got.ExternalIdentityStatus == nil || *got.ExternalIdentityStatus != principals.ExternalIdentityDeleted {
		t.Errorf("external identity status = %v, want deleted", got.ExternalIdentityStatus)
	}
	if got.ExternalIdentityCheckedAt == nil || got.ExternalIdentityStatusChangedAt == nil {
		t.Error("external identity timestamps are nil after successful poll")
	}
}

// TestRunOnceIdPPollProviderErrorFailsClosed: недоступность provider не
// обновляет checked_at/зеркало и не меняет локальный lifecycle.
func TestRunOnceIdPPollProviderErrorFailsClosed(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	providerName := "failing-itest-" + uuid.NewString()
	p := newPrincipal(ctx, t, pool, principals.TypeHuman, providerName, "failure@grantor.test")
	store := principals.NewStore()
	initial, err := store.RecordExternalIdentityStatus(
		ctx, pool, p.ID, principals.ExternalIdentityActive, false)
	if err != nil {
		t.Fatalf("seed external identity mirror: %v", err)
	}

	runner := New(pool, Config{}).WithAudit(audit.NewWriter()).WithDirectoryPoll(DirectoryPoll{
		Provider:     failingDirectoryProvider{},
		ProviderName: providerName,
	})
	if _, err := runner.RunOnce(ctx); err == nil {
		t.Fatal("RunOnce error = nil, want provider error")
	}

	got := principalStatus(ctx, t, pool, p.ID)
	if got.Status != principals.StatusActive || got.ExternalIdentityStatus == nil ||
		*got.ExternalIdentityStatus != principals.ExternalIdentityActive {
		t.Errorf("provider error changed principal: %+v", got)
	}
	if initial.Principal.ExternalIdentityCheckedAt == nil || got.ExternalIdentityCheckedAt == nil ||
		!got.ExternalIdentityCheckedAt.Equal(*initial.Principal.ExternalIdentityCheckedAt) {
		t.Errorf("checked_at changed on provider error: before %v after %v",
			initial.Principal.ExternalIdentityCheckedAt, got.ExternalIdentityCheckedAt)
	}
	if got := externalIdentityStatusAuditCount(ctx, t, pool, p.ID); got != 0 {
		t.Errorf("provider error emitted external identity audit: count = %d, want 0", got)
	}
}

// TestRunOnceIdPPollRefreshesDisabledMirror: локально disabled principal
// остаётся disabled при внешнем active, но зеркало и checked_at продолжают
// обновляться. Это неявно запрещает auto-enable из IdP.
func TestRunOnceIdPPollRefreshesDisabledMirror(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	providerName := "static-itest-" + uuid.NewString()
	p := newPrincipal(ctx, t, pool, principals.TypeHuman, providerName, "disabled@grantor.test")
	store := principals.NewStore()
	if _, err := store.SetStatus(ctx, pool, p.ID, principals.StatusDisabled); err != nil {
		t.Fatalf("disable principal: %v", err)
	}

	runner := New(pool, Config{}).WithAudit(audit.NewWriter()).WithDirectoryPoll(DirectoryPoll{
		Provider:     directory.NewStatic([]string{p.ExternalSubject}, nil),
		ProviderName: providerName,
	})
	if _, err := runner.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	first := principalStatus(ctx, t, pool, p.ID)
	if first.ExternalIdentityStatus == nil ||
		*first.ExternalIdentityStatus != principals.ExternalIdentityDisabled {
		t.Fatalf("first external identity status = %v, want disabled", first.ExternalIdentityStatus)
	}

	runner = New(pool, Config{}).WithAudit(audit.NewWriter()).WithDirectoryPoll(DirectoryPoll{
		Provider:     directory.NewStatic(nil, nil),
		ProviderName: providerName,
	})
	if _, err := runner.RunOnce(ctx); err != nil {
		t.Fatalf("second RunOnce: %v", err)
	}

	got := principalStatus(ctx, t, pool, p.ID)
	if got.Status != principals.StatusDisabled {
		t.Errorf("local status = %q, want disabled (no automatic enable)", got.Status)
	}
	if got.ExternalIdentityStatus == nil || *got.ExternalIdentityStatus != principals.ExternalIdentityActive {
		t.Errorf("external identity status = %v, want active", got.ExternalIdentityStatus)
	}
	if got.ExternalIdentityCheckedAt == nil || got.ExternalIdentityStatusChangedAt == nil {
		t.Error("external identity timestamps are nil after successful poll")
	}
	meta := latestExternalIdentityStatusAudit(ctx, t, pool, p.ID)
	if meta.Provider != providerName || meta.Status != "active" || meta.PreviousStatus == nil ||
		*meta.PreviousStatus != "disabled" || meta.Reason != "active" {
		t.Errorf("reactivation audit = %+v, want provider/active/disabled/active", meta)
	}
	if got := externalIdentityStatusAuditCount(ctx, t, pool, p.ID); got != 2 {
		t.Errorf("external identity status audit count = %d, want 2", got)
	}
	if _, err := runner.RunOnce(ctx); err != nil {
		t.Fatalf("third RunOnce: %v", err)
	}
	if got := externalIdentityStatusAuditCount(ctx, t, pool, p.ID); got != 2 {
		t.Errorf("unchanged external status emitted audit: count = %d, want 2", got)
	}
}

// TestRunOnceOffboardingFindingWithoutPoll: finding offboarding_incomplete
// эвалуируется из локального статуса принципалов и без подключённого IdP
// (GRANTOR_IDP_MODE=""): выключенный админом принципал с активным
// аккаунтом и present-binding получает finding, выключенный «дочиста» и
// активный — нет.
func TestRunOnceOffboardingFindingWithoutPoll(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := principals.NewStore()

	// Выключенный принципал с активным аккаунтом и present-binding.
	lingering := newPrincipal(ctx, t, pool, principals.TypeHuman, "", "")
	account := newAccountFor(ctx, t, pool, lingering.ID)
	perm := insertPermission(ctx, t, pool, account.ConnectionID)
	insertBinding(ctx, t, pool, account.ID, perm, "present", nil)
	if _, err := store.SetStatus(ctx, pool, lingering.ID, principals.StatusDisabled); err != nil {
		t.Fatalf("disable lingering principal: %v", err)
	}

	// Выключенный принципал без какого-либо доступа.
	clean := newPrincipal(ctx, t, pool, principals.TypeHuman, "", "")
	if _, err := store.SetStatus(ctx, pool, clean.ID, principals.StatusDisabled); err != nil {
		t.Fatalf("disable clean principal: %v", err)
	}

	// Активный принципал с аккаунтом — findings не про него.
	active := newPrincipal(ctx, t, pool, principals.TypeHuman, "", "")
	newAccountFor(ctx, t, pool, active.ID)

	// Runner без WithDirectoryPoll — поллинг выключен (режим "").
	runner := New(pool, Config{}).WithAudit(audit.NewWriter())
	stats, err := runner.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if stats.PrincipalsDisabled != 0 {
		t.Errorf("PrincipalsDisabled = %d, want 0 (poll disabled)", stats.PrincipalsDisabled)
	}
	if stats.OffboardingIncomplete < 1 {
		t.Errorf("OffboardingIncomplete = %d, want >= 1", stats.OffboardingIncomplete)
	}

	if got := offboardingAuditCount(ctx, t, pool, lingering.ID); got != 1 {
		t.Errorf("lingering principal offboarding audit events = %d, want 1", got)
	}
	if got := offboardingAuditCount(ctx, t, pool, clean.ID); got != 0 {
		t.Errorf("clean disabled principal offboarding audit events = %d, want 0", got)
	}
	if got := offboardingAuditCount(ctx, t, pool, active.ID); got != 0 {
		t.Errorf("active principal offboarding audit events = %d, want 0", got)
	}

	// Metadata события: счётчики и момент выключения, без секретов
	// (jsonb нормализует JSON — сравниваем разобранные значения).
	var raw []byte
	if err := pool.QueryRow(ctx, `
		select metadata from audit_events
		where action = $1 and principal_id = $2
		order by id desc limit 1`,
		auditActionOffboardingIncomplete, lingering.ID,
	).Scan(&raw); err != nil {
		t.Fatalf("read offboarding audit metadata: %v", err)
	}
	var meta struct {
		PrincipalID   string `json:"principal_id"`
		AccountCount  int    `json:"account_count"`
		BindingCount  int    `json:"binding_count"`
		DisabledSince string `json:"disabled_since"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatalf("unmarshal offboarding metadata %s: %v", raw, err)
	}
	if meta.PrincipalID != lingering.ID.String() {
		t.Errorf("metadata principal_id = %q, want %q", meta.PrincipalID, lingering.ID)
	}
	if meta.AccountCount != 1 || meta.BindingCount != 1 {
		t.Errorf("metadata counts = %d/%d, want 1/1", meta.AccountCount, meta.BindingCount)
	}
	if meta.DisabledSince == "" {
		t.Error("metadata disabled_since is empty, want RFC3339 timestamp")
	}
}
