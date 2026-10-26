//go:build integration

// Integration-тесты разделов UI «Пользователи» (principals) и «Дрифт»
// поверх httptest-сервера API (см. api_integration_test.go): создание и
// привязка принципалов, отчёт о расхождениях и adopt unmanaged binding.
// Worker не запускается: эти endpoints меняют только metadata.
package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/principals"
)

// principalBody — подмножество principalJSON (плюс accounts из detail)
// для разбора ответов.
type principalBody struct {
	ID                              uuid.UUID  `json:"id"`
	Type                            string     `json:"type"`
	DisplayName                     string     `json:"display_name"`
	Status                          string     `json:"status"`
	ExternalIdentityStatus          *string    `json:"external_identity_status"`
	ExternalIdentityCheckedAt       *time.Time `json:"external_identity_checked_at"`
	ExternalIdentityStatusChangedAt *time.Time `json:"external_identity_status_changed_at"`
	AccountsCount                   *int       `json:"accounts_count"`
	Accounts                        []struct {
		ID           uuid.UUID  `json:"id"`
		ConnectionID uuid.UUID  `json:"connection_id"`
		PrincipalID  *uuid.UUID `json:"principal_id"`
	} `json:"accounts"`
}

// getPrincipalBody читает detail принципала через API.
func getPrincipalBody(t *testing.T, env *testEnv, sess *auth.Session, id uuid.UUID) principalBody {
	t.Helper()
	resp := env.do(t, http.MethodGet, "/api/v1/principals/"+id.String(), nil, sess, false)
	requireStatus(t, resp, http.StatusOK)
	var out principalBody
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode principal detail: %v", err)
	}
	return out
}

// findPrincipalInList находит принципала в списковом ответе API. Лимит
// большой: общая тестовая база может содержать чужих принципалов.
func findPrincipalInList(t *testing.T, env *testEnv, sess *auth.Session, id uuid.UUID) principalBody {
	t.Helper()
	resp := env.do(t, http.MethodGet, "/api/v1/principals?limit=100000", nil, sess, false)
	requireStatus(t, resp, http.StatusOK)
	var list struct {
		Principals []principalBody `json:"principals"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatalf("decode principals list: %v", err)
	}
	for _, p := range list.Principals {
		if p.ID == id {
			return p
		}
	}
	t.Fatalf("principal %s not found in list of %d", id, len(list.Principals))
	return principalBody{}
}

func TestIntegrationPrincipalsFlow(t *testing.T) {
	env := newTestEnv(t, nil)
	operator := session(auth.RoleOperator)
	viewer := session(auth.RoleViewer)

	body := map[string]any{
		"type":         "human",
		"display_name": "itest-principal-" + uuid.NewString(),
	}

	// RBAC: viewer не создаёт principals; невалидный type — 400.
	resp := env.do(t, http.MethodPost, "/api/v1/principals", body, &viewer, true)
	requireStatus(t, resp, http.StatusForbidden)
	resp = env.do(t, http.MethodPost, "/api/v1/principals",
		map[string]any{"type": "alien", "display_name": "x"}, &operator, true)
	requireStatus(t, resp, http.StatusBadRequest)

	resp = env.do(t, http.MethodPost, "/api/v1/principals", body, &operator, true)
	requireStatus(t, resp, http.StatusCreated)
	var created principalBody
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.Type != "human" || created.Status != "active" {
		t.Errorf("created type/status = %q/%q, want human/active", created.Type, created.Status)
	}
	if created.ExternalIdentityStatus != nil || created.ExternalIdentityCheckedAt != nil ||
		created.ExternalIdentityStatusChangedAt != nil {
		t.Error("local principal external identity fields must be null")
	}

	// Внешнее зеркало присутствует одинаково в list/detail и не смешивается
	// с локальным status.
	externalBody := map[string]any{
		"type":              "human",
		"display_name":      "itest-external-" + uuid.NewString(),
		"external_provider": "itest",
		"external_subject":  "sub-" + uuid.NewString(),
	}
	resp = env.do(t, http.MethodPost, "/api/v1/principals", externalBody, &operator, true)
	requireStatus(t, resp, http.StatusCreated)
	var external principalBody
	if err := json.NewDecoder(resp.Body).Decode(&external); err != nil {
		t.Fatalf("decode external principal: %v", err)
	}
	if _, err := principals.NewStore().RecordExternalIdentityStatus(
		t.Context(), env.pool, external.ID, principals.ExternalIdentityDisabled, false,
	); err != nil {
		t.Fatalf("record external identity status: %v", err)
	}
	for name, got := range map[string]principalBody{
		"list":   findPrincipalInList(t, env, &viewer, external.ID),
		"detail": getPrincipalBody(t, env, &viewer, external.ID),
	} {
		if got.Status != "active" {
			t.Errorf("%s local status = %q, want active", name, got.Status)
		}
		if got.ExternalIdentityStatus == nil || *got.ExternalIdentityStatus != "disabled" {
			t.Errorf("%s external identity status = %v, want disabled", name, got.ExternalIdentityStatus)
		}
		if got.ExternalIdentityCheckedAt == nil || got.ExternalIdentityStatusChangedAt == nil {
			t.Errorf("%s external identity timestamps are nil", name)
		}
	}

	// Audit principal.created записан с id принципала и actor из сессии.
	events, err := audit.NewWriter().List(t.Context(), env.pool,
		audit.Filter{Actions: []string{"principal.created"}, ActorID: operator.Email}, 100, 0)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	foundEvent := false
	for _, e := range events {
		if e.PrincipalID != nil && *e.PrincipalID == created.ID {
			foundEvent = true
		}
	}
	if !foundEvent {
		t.Error("no principal.created audit event for created principal")
	}

	// Список: accounts_count присутствует и равен 0.
	item := findPrincipalInList(t, env, &viewer, created.ID)
	if item.AccountsCount == nil || *item.AccountsCount != 0 {
		t.Errorf("accounts_count = %v, want 0", item.AccountsCount)
	}

	// Managed account и link.
	conn := createDraft(t, env.pool)
	acct := managedAccount(t, env.pool, conn.ID, "")
	linkPath := "/api/v1/accounts/" + acct.ID.String() + "/link"

	resp = env.do(t, http.MethodPost, linkPath, map[string]any{"principal_id": created.ID}, &viewer, true)
	requireStatus(t, resp, http.StatusForbidden)
	resp = env.do(t, http.MethodPost, linkPath, map[string]any{}, &operator, true)
	requireStatus(t, resp, http.StatusBadRequest)
	resp = env.do(t, http.MethodPost, linkPath, map[string]any{"principal_id": uuid.New()}, &operator, true)
	requireStatus(t, resp, http.StatusNotFound)

	resp = env.do(t, http.MethodPost, linkPath, map[string]any{"principal_id": created.ID}, &operator, true)
	requireStatus(t, resp, http.StatusOK)
	var linked struct {
		ID          uuid.UUID  `json:"id"`
		PrincipalID *uuid.UUID `json:"principal_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&linked); err != nil {
		t.Fatalf("decode link response: %v", err)
	}
	if linked.PrincipalID == nil || *linked.PrincipalID != created.ID {
		t.Errorf("linked principal_id = %v, want %s", linked.PrincipalID, created.ID)
	}

	// Detail видит аккаунт с connection_id; счётчик в списке — 1.
	detail := getPrincipalBody(t, env, &viewer, created.ID)
	if len(detail.Accounts) != 1 {
		t.Fatalf("detail accounts = %d, want 1", len(detail.Accounts))
	}
	if detail.Accounts[0].ID != acct.ID || detail.Accounts[0].ConnectionID != conn.ID {
		t.Errorf("detail account = %s/%s, want %s/%s",
			detail.Accounts[0].ID, detail.Accounts[0].ConnectionID, acct.ID, conn.ID)
	}
	item = findPrincipalInList(t, env, &viewer, created.ID)
	if item.AccountsCount == nil || *item.AccountsCount != 1 {
		t.Errorf("accounts_count after link = %v, want 1", item.AccountsCount)
	}

	// Audit account.linked несёт principal_id в metadata.
	acctID := acct.ID
	events, err = audit.NewWriter().List(t.Context(), env.pool,
		audit.Filter{AccountID: &acctID, Actions: []string{"account.linked"}}, 10, 0)
	if err != nil {
		t.Fatalf("list account.linked events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("account.linked events = %d, want 1", len(events))
	}
	var meta struct {
		PrincipalID uuid.UUID `json:"principal_id"`
	}
	if err := json.Unmarshal(events[0].Metadata, &meta); err != nil || meta.PrincipalID != created.ID {
		t.Errorf("account.linked metadata %s misses principal_id (err=%v)", events[0].Metadata, err)
	}

	// Unlink: привязка снята, detail пуст, audit записан.
	resp = env.do(t, http.MethodPost, "/api/v1/accounts/"+acct.ID.String()+"/unlink", nil, &operator, true)
	requireStatus(t, resp, http.StatusOK)
	if err := json.NewDecoder(resp.Body).Decode(&linked); err != nil {
		t.Fatalf("decode unlink response: %v", err)
	}
	if linked.PrincipalID != nil {
		t.Errorf("unlinked principal_id = %v, want null", linked.PrincipalID)
	}
	detail = getPrincipalBody(t, env, &viewer, created.ID)
	if len(detail.Accounts) != 0 {
		t.Errorf("detail accounts after unlink = %d, want 0", len(detail.Accounts))
	}
	events, err = audit.NewWriter().List(t.Context(), env.pool,
		audit.Filter{AccountID: &acctID, Actions: []string{"account.unlinked"}}, 10, 0)
	if err != nil {
		t.Fatalf("list account.unlinked events: %v", err)
	}
	if len(events) != 1 {
		t.Errorf("account.unlinked events = %d, want 1", len(events))
	}

	// Disable / enable.
	base := "/api/v1/principals/" + created.ID.String()
	resp = env.do(t, http.MethodPost, base+"/disable", nil, &operator, true)
	requireStatus(t, resp, http.StatusOK)
	var updated principalBody
	if err := json.NewDecoder(resp.Body).Decode(&updated); err != nil {
		t.Fatalf("decode disable response: %v", err)
	}
	if updated.Status != "disabled" {
		t.Errorf("status after disable = %q, want disabled", updated.Status)
	}
	resp = env.do(t, http.MethodPost, base+"/enable", nil, &operator, true)
	requireStatus(t, resp, http.StatusOK)
	if err := json.NewDecoder(resp.Body).Decode(&updated); err != nil {
		t.Fatalf("decode enable response: %v", err)
	}
	if updated.Status != "active" {
		t.Errorf("status after enable = %q, want active", updated.Status)
	}

	// Несуществующий principal — 404 на detail и disable.
	resp = env.do(t, http.MethodGet, "/api/v1/principals/"+uuid.NewString(), nil, &viewer, false)
	requireStatus(t, resp, http.StatusNotFound)
	resp = env.do(t, http.MethodPost, "/api/v1/principals/"+uuid.NewString()+"/disable", nil, &operator, true)
	requireStatus(t, resp, http.StatusNotFound)
}

// driftSnapshot — фикстура дрифта: ресурсы db+schema, аккаунты
// svc/readers, permission role:readers и bindings обоих аккаунтов.
// full=false убирает схему и binding readers — второе сведение
// переводит managed-схему в missing, а binding readers в drift.
func driftSnapshot(full bool) *adapter.Snapshot {
	snap := &adapter.Snapshot{
		ServerVersion: "16.4",
		Resources: []adapter.ObservedResource{
			{
				Kind:          "database",
				ExternalID:    "db:app",
				Name:          "app",
				CanonicalPath: "app",
				Fingerprint:   "fp-db",
			},
			{
				Kind:             "schema",
				ExternalID:       "schema:app.public",
				ParentExternalID: "db:app",
				Name:             "public",
				CanonicalPath:    "app.public",
				Fingerprint:      "fp-schema",
			},
		},
		Accounts: []adapter.ObservedAccount{
			{Kind: "login", EngineIdentity: "svc"},
			{Kind: "group", EngineIdentity: "readers"},
		},
		Permissions: []adapter.ObservedPermission{
			{ExternalID: "role:readers", Name: "readers", Assignable: true},
		},
		Bindings: []adapter.ObservedBinding{
			{AccountEngineIdentity: "svc", PermissionExternalID: "role:readers"},
			{AccountEngineIdentity: "readers", PermissionExternalID: "role:readers"},
		},
		ObservedAt: time.Now(),
	}
	if !full {
		snap.Resources = snap.Resources[:1]
		snap.Bindings = snap.Bindings[:1]
	}
	return snap
}

// upsertDriftSnapshot сводит снапшот фикстуры в инвентарь connection.
func upsertDriftSnapshot(t *testing.T, pool *pgxpool.Pool, connID uuid.UUID, snap *adapter.Snapshot, at time.Time) {
	t.Helper()
	if _, err := inventory.NewStore().UpsertSnapshot(context.Background(), pool, connID, snap, at); err != nil {
		t.Fatalf("upsert drift snapshot: %v", err)
	}
}

// driftReport — тело ответа GET /api/v1/drift.
type driftReport struct {
	Findings []struct {
		Kind            string     `json:"kind"`
		ConnectionID    uuid.UUID  `json:"connection_id"`
		BindingID       *uuid.UUID `json:"binding_id"`
		ResourceID      *uuid.UUID `json:"resource_id"`
		AccountIdentity string     `json:"account_identity"`
		PermissionName  string     `json:"permission_name"`
		Detail          string     `json:"detail"`
	} `json:"findings"`
	Counts map[string]int `json:"counts"`
}

// getDriftReport читает отчёт дрифта через API.
func getDriftReport(t *testing.T, env *testEnv, sess *auth.Session, query string) driftReport {
	t.Helper()
	resp := env.do(t, http.MethodGet, "/api/v1/drift"+query, nil, sess, false)
	requireStatus(t, resp, http.StatusOK)
	var out driftReport
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode drift report: %v", err)
	}
	return out
}

func TestIntegrationDriftAndAdopt(t *testing.T) {
	env := newTestEnv(t, nil)
	operator := session(auth.RoleOperator)
	viewer := session(auth.RoleViewer)
	ctx := context.Background()
	inv := inventory.NewStore()

	conn := createDraft(t, env.pool)
	upsertDriftSnapshot(t, env.pool, conn.ID, driftSnapshot(true), time.Now())

	// readers-binding берётся под управление (desired present), схема
	// становится managed: их исчезновение из второго снапшота даст
	// binding_drift и missing_resource; svc-binding остаётся unmanaged.
	readers := findAccount(t, env.pool, conn.ID, "readers")
	readersBindings, err := inv.ListBindingsByAccount(ctx, env.pool, readers.ID)
	if err != nil {
		t.Fatalf("list readers bindings: %v", err)
	}
	if len(readersBindings) != 1 {
		t.Fatalf("readers bindings = %d, want 1", len(readersBindings))
	}
	if _, err := inv.SetBindingDesired(ctx, env.pool, readersBindings[0].ID, inventory.BindingPresent); err != nil {
		t.Fatalf("set readers binding desired: %v", err)
	}
	if _, err := env.pool.Exec(ctx,
		`update resources set ownership = 'managed'
		 where connection_id = $1 and external_id = 'schema:app.public'`, conn.ID); err != nil {
		t.Fatalf("mark schema managed: %v", err)
	}
	upsertDriftSnapshot(t, env.pool, conn.ID, driftSnapshot(false), time.Now().Add(time.Minute))

	// Отдельное degraded-подключение для connection_degraded finding.
	degraded := createDraft(t, env.pool)
	activateConnection(t, env.pool, degraded.ID)
	if _, err := connections.NewStore().Transition(ctx, env.pool, degraded.ID,
		connections.StatusActive, connections.StatusDegraded); err != nil {
		t.Fatalf("degrade connection: %v", err)
	}

	// Отчёт по conn: ровно по одному finding каждого инвентарного вида,
	// degraded-подключений в фильтре нет.
	report := getDriftReport(t, env, &viewer, "?connection_id="+conn.ID.String())
	wantCounts := map[string]int{
		"binding_drift":        1,
		"unmanaged_binding":    1,
		"missing_resource":     1,
		"degraded_connections": 0,
	}
	for kind, want := range wantCounts {
		if got := report.Counts[kind]; got != want {
			t.Errorf("counts[%s] = %d, want %d", kind, got, want)
		}
	}
	if len(report.Findings) != 3 {
		t.Fatalf("findings = %d, want 3; report: %+v", len(report.Findings), report)
	}

	var unmanagedBindingID uuid.UUID
	for _, f := range report.Findings {
		if f.ConnectionID != conn.ID {
			t.Errorf("finding %s connection = %s, want %s", f.Kind, f.ConnectionID, conn.ID)
		}
		switch f.Kind {
		case "binding_drift":
			if f.AccountIdentity != "readers" || f.PermissionName != "readers" {
				t.Errorf("binding_drift identity/permission = %q/%q, want readers/readers",
					f.AccountIdentity, f.PermissionName)
			}
			if !strings.Contains(f.Detail, "желаемое состояние present, наблюдаемое absent") {
				t.Errorf("binding_drift detail = %q, want желаемое состояние present, наблюдаемое absent", f.Detail)
			}
		case "unmanaged_binding":
			if f.AccountIdentity != "svc" {
				t.Errorf("unmanaged_binding identity = %q, want svc", f.AccountIdentity)
			}
			if f.BindingID == nil {
				t.Error("unmanaged_binding has no binding_id")
			} else {
				unmanagedBindingID = *f.BindingID
			}
		case "missing_resource":
			if f.ResourceID == nil {
				t.Error("missing_resource has no resource_id")
			}
		default:
			t.Errorf("unexpected finding kind %q", f.Kind)
		}
	}
	if unmanagedBindingID == uuid.Nil {
		t.Fatal("no unmanaged binding finding in report")
	}

	// Отчёт по degraded connection: только connection_degraded.
	report = getDriftReport(t, env, &viewer, "?connection_id="+degraded.ID.String())
	if report.Counts["degraded_connections"] != 1 || len(report.Findings) != 1 ||
		report.Findings[0].Kind != "connection_degraded" {
		t.Errorf("degraded connection report = %+v, want single connection_degraded", report)
	}

	// Отчёт без фильтра видит degraded наравне с инвентарными findings.
	report = getDriftReport(t, env, &viewer, "")
	foundDegraded := false
	for _, f := range report.Findings {
		if f.Kind == "connection_degraded" && f.ConnectionID == degraded.ID {
			foundDegraded = true
		}
	}
	if !foundDegraded {
		t.Error("unfiltered report misses connection_degraded finding")
	}
	if report.Counts["degraded_connections"] < 1 {
		t.Errorf("unfiltered degraded_connections = %d, want >= 1", report.Counts["degraded_connections"])
	}

	// Несуществующий connection_id — 404, невалидный — 400.
	resp := env.do(t, http.MethodGet, "/api/v1/drift?connection_id="+uuid.NewString(), nil, &viewer, false)
	requireStatus(t, resp, http.StatusNotFound)
	resp = env.do(t, http.MethodGet, "/api/v1/drift?connection_id=zzz", nil, &viewer, false)
	requireStatus(t, resp, http.StatusBadRequest)

	// Adopt: viewer — 403; operator — 200, binding становится
	// desired=present/synced (observed present).
	adoptPath := "/api/v1/bindings/" + unmanagedBindingID.String() + "/adopt"
	resp = env.do(t, http.MethodPost, adoptPath, nil, &viewer, true)
	requireStatus(t, resp, http.StatusForbidden)
	resp = env.do(t, http.MethodPost, adoptPath, nil, &operator, true)
	requireStatus(t, resp, http.StatusOK)
	var adopted struct {
		ID           uuid.UUID `json:"id"`
		DesiredState *string   `json:"desired_state"`
		Status       string    `json:"status"`
		Source       string    `json:"source"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&adopted); err != nil {
		t.Fatalf("decode adopt response: %v", err)
	}
	if adopted.DesiredState == nil || *adopted.DesiredState != "present" || adopted.Status != "synced" {
		t.Errorf("adopted desired/status = %v/%q, want present/synced", adopted.DesiredState, adopted.Status)
	}
	stored, err := inv.GetBinding(t.Context(), env.pool, unmanagedBindingID)
	if err != nil {
		t.Fatalf("get adopted binding: %v", err)
	}
	if stored.DesiredState == nil || *stored.DesiredState != inventory.BindingPresent ||
		stored.Status != inventory.BindingStatusSynced || stored.Source != "external" {
		t.Errorf("stored binding = %+v, want desired present, synced, source external", stored)
	}

	// Audit binding.adopted записан.
	svc := findAccount(t, env.pool, conn.ID, "svc")
	svcID := svc.ID
	events, err := audit.NewWriter().List(t.Context(), env.pool,
		audit.Filter{AccountID: &svcID, Actions: []string{"binding.adopted"}}, 10, 0)
	if err != nil {
		t.Fatalf("list binding.adopted events: %v", err)
	}
	if len(events) != 1 {
		t.Errorf("binding.adopted events = %d, want 1", len(events))
	}

	// Повторный adopt — 409; managed binding — 409; несуществующий — 404.
	resp = env.do(t, http.MethodPost, adoptPath, nil, &operator, true)
	requireStatus(t, resp, http.StatusConflict)
	resp = env.do(t, http.MethodPost,
		"/api/v1/bindings/"+readersBindings[0].ID.String()+"/adopt", nil, &operator, true)
	requireStatus(t, resp, http.StatusConflict)
	resp = env.do(t, http.MethodPost, "/api/v1/bindings/"+uuid.NewString()+"/adopt", nil, &operator, true)
	requireStatus(t, resp, http.StatusNotFound)

	// После adopt в отчёте conn не остаётся unmanaged findings.
	report = getDriftReport(t, env, &viewer, "?connection_id="+conn.ID.String())
	if report.Counts["unmanaged_binding"] != 0 || report.Counts["binding_drift"] != 1 {
		t.Errorf("counts after adopt = %+v, want unmanaged 0, drift 1", report.Counts)
	}
}

// TestIntegrationInheritedBindingIsNotManageable: право, полученное через
// цепочку ролей, нельзя ни принять под управление, ни отозвать напрямую.
//
// Аудит показал, к чему приводило отсутствие этих границ: adopt делал кнопку
// отзыва видимой, отзыв не находил прямого ребра в целевой системе, шаг
// помечался skipped, а Verify — той же проверкой — подтверждал «снято».
// Оператор получал success при живом доступе.
func TestIntegrationInheritedBindingIsNotManageable(t *testing.T) {
	env := newTestEnv(t, nil)
	operator := session(auth.RoleOperator)
	conn := activeFakeConnection(t, env.pool)

	// Унаследованный binding заводится прямым SQL: воспроизводить полную
	// цепочку ролей движка здесь незачем — проверяются границы API, а не
	// discovery.
	acct := findAccount(t, env.pool, conn.ID, "svc-a")
	var permID uuid.UUID
	if err := env.pool.QueryRow(t.Context(),
		`select id from permission_definitions where connection_id = $1 limit 1`,
		conn.ID).Scan(&permID); err != nil {
		t.Fatalf("load permission: %v", err)
	}
	var bindingID uuid.UUID
	if err := env.pool.QueryRow(t.Context(), `
		insert into bindings (account_id, permission_definition_id, source,
		                      desired_state, observed_state, status)
		values ($1, $2, 'inherited', null, 'present', 'pending')
		on conflict (account_id, permission_definition_id, scope_resource_id)
		do update set source = 'inherited', desired_state = null
		returning id`, acct.ID, permID).Scan(&bindingID); err != nil {
		t.Fatalf("seed inherited binding: %v", err)
	}

	// Принять под управление нельзя: grantor взял бы обязательство, которое
	// не может исполнить.
	resp := env.do(t, http.MethodPost,
		"/api/v1/bindings/"+bindingID.String()+"/adopt", nil, &operator, true)
	requireStatus(t, resp, http.StatusConflict)
	if body := string(readBody(t, resp)); !strings.Contains(body, "inherited") {
		t.Errorf("adopt conflict body = %s, want it to name inheritance", body)
	}
	// Отказ обязан быть без побочного эффекта: desired_state остался NULL.
	var desired *string
	if err := env.pool.QueryRow(t.Context(),
		`select desired_state from bindings where id = $1`, bindingID).Scan(&desired); err != nil {
		t.Fatalf("read binding after refused adopt: %v", err)
	}
	if desired != nil {
		t.Errorf("desired_state after refused adopt = %q, want NULL", *desired)
	}

	// Отозвать напрямую тоже нельзя — даже если binding уже помечен желаемым
	// (наследие прежнего поведения, когда adopt его пропускал).
	if _, err := env.pool.Exec(t.Context(),
		`update bindings set desired_state = 'present' where id = $1`, bindingID); err != nil {
		t.Fatalf("mark inherited binding desired: %v", err)
	}
	resp = env.do(t, http.MethodDelete, "/api/v1/bindings/"+bindingID.String(), nil, &operator, true)
	requireStatus(t, resp, http.StatusConflict)
	if body := string(readBody(t, resp)); !strings.Contains(body, "revoke the role") {
		t.Errorf("delete conflict body = %s, want it to point at the granting role", body)
	}
}
