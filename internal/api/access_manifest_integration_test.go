//go:build integration

// Integration-тесты декларативного access manifest (ADR-0009) на fake
// adapter. Проверяется API-слой (worker не запускается): plan (dry-run diff
// без применения), apply (создание managed-аккаунта + binding, идемпотентность
// повторного apply, отзыв через absent), export применённого состояния, RBAC
// и dangerous-контроль. Резолв принципала — по external_subject, подключения —
// по display_name; окружение уникально на тест (общая тестовая БД).
package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"gopkg.in/yaml.v3"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/accessmanifest"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/principals"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

// uniqueSuffix — короткий уникальный хвост для окружений/субъектов на общей
// тестовой БД.
func uniqueSuffix() string {
	return strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
}

// createPrincipalWithSubject создаёт service-принципала с уникальным
// external_subject (по нему манифест его резолвит).
func createPrincipalWithSubject(t *testing.T, pool *pgxpool.Pool, subject string) principals.Principal {
	t.Helper()
	p, err := principals.NewStore().Create(context.Background(), pool, principals.CreateParams{
		Type:             principals.TypeService,
		DisplayName:      "Manifest " + subject,
		ExternalProvider: "itest",
		ExternalSubject:  subject,
	})
	if err != nil {
		t.Fatalf("create principal: %v", err)
	}
	return p
}

func TestIntegrationAccessManifestPlan(t *testing.T) {
	env := newTestEnv(t, nil)
	operator := session(auth.RoleOperator)
	viewer := session(auth.RoleViewer)

	sfx := uniqueSuffix()
	mfEnv := "mfenv-" + sfx
	conn := activeFakeConnectionEnv(t, env.pool, mfEnv)
	principal := createPrincipalWithSubject(t, env.pool, "mfsub-"+sfx)

	manifest := map[string]any{
		"version":     "v1",
		"environment": mfEnv,
		"entries": []map[string]any{
			{"principal": principal.ExternalSubject, "connection": conn.DisplayName, "role": "role:app-readonly"},
			{"principal": principal.ExternalSubject, "connection": conn.DisplayName, "role": "role:does-not-exist"},
		},
	}

	// RBAC: viewer не может строить план; без CSRF мутирующий POST отклоняется.
	resp := env.do(t, http.MethodPost, "/api/v1/access/plan", manifest, &viewer, true)
	requireStatus(t, resp, http.StatusForbidden)
	resp = env.do(t, http.MethodPost, "/api/v1/access/plan", manifest, &operator, false)
	requireStatus(t, resp, http.StatusForbidden)

	resp = env.do(t, http.MethodPost, "/api/v1/access/plan", manifest, &operator, true)
	requireStatus(t, resp, http.StatusOK)
	var out struct {
		Plan struct {
			Actions []struct {
				Kind                  string `json:"kind"`
				Principal             string `json:"principal"`
				Role                  string `json:"role"`
				AccountEngineIdentity string `json:"account_engine_identity"`
			} `json:"actions"`
			Unresolved []struct {
				Role   string `json:"role"`
				Reason string `json:"reason"`
			} `json:"unresolved"`
		} `json:"plan"`
		Summary struct {
			Grants    int `json:"grants"`
			Revokes   int `json:"revokes"`
			Creates   int `json:"creates"`
			Dangerous int `json:"dangerous"`
		} `json:"summary"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode plan response: %v", err)
	}
	if out.Summary.Creates != 1 || out.Summary.Grants != 1 || out.Summary.Revokes != 0 {
		t.Errorf("summary = %+v, want creates=1 grants=1 revokes=0", out.Summary)
	}
	if len(out.Plan.Actions) != 2 {
		t.Errorf("actions = %d, want 2 (create_account + grant)", len(out.Plan.Actions))
	}
	if len(out.Plan.Unresolved) != 1 || out.Plan.Unresolved[0].Role != "role:does-not-exist" || out.Plan.Unresolved[0].Reason == "" {
		t.Errorf("unresolved = %+v, want one role:does-not-exist with reason", out.Plan.Unresolved)
	}

	// Plan ничего не применяет: managed-аккаунта у принципала нет.
	accounts, err := inventory.NewStore().ListAccountsByPrincipal(t.Context(), env.pool, principal.ID)
	if err != nil {
		t.Fatalf("list accounts by principal: %v", err)
	}
	if len(accounts) != 0 {
		t.Errorf("plan created %d accounts, want 0", len(accounts))
	}
}

func TestIntegrationAccessManifestConnectionScope(t *testing.T) {
	env := newTestEnv(t, nil)
	operator := session(auth.RoleOperator)

	sfx := uniqueSuffix()
	mfEnv := "mfenv-" + sfx
	connA := activeFakeConnectionEnv(t, env.pool, mfEnv)
	connB := activeFakeConnectionEnv(t, env.pool, mfEnv)
	principal := createPrincipalWithSubject(t, env.pool, "mfsub-"+sfx)
	entry := func(connection string) map[string]any {
		return map[string]any{
			"principal":  principal.ExternalSubject,
			"connection": connection,
			"role":       "role:app-readonly",
		}
	}
	manifest := func(entries ...map[string]any) map[string]any {
		return map[string]any{"version": "v1", "environment": mfEnv, "entries": entries}
	}

	// Query scope и manifest entry независимо принимают UUID/display_name.
	resp := env.do(t, http.MethodPost,
		"/api/v1/access/plan?connection="+connA.ID.String(),
		manifest(entry(connA.DisplayName)), &operator, true)
	requireStatus(t, resp, http.StatusOK)
	resp = env.do(t, http.MethodPost,
		"/api/v1/access/plan?connection="+url.QueryEscape(connA.DisplayName),
		manifest(entry(connA.ID.String())), &operator, true)
	requireStatus(t, resp, http.StatusOK)

	// Любая foreign entry отвергает весь scoped запрос до применения.
	resp = env.do(t, http.MethodPost,
		"/api/v1/access/plan?connection="+connA.ID.String(),
		manifest(entry(connA.DisplayName), entry(connB.DisplayName)), &operator, true)
	requireStatus(t, resp, http.StatusBadRequest)
	resp = env.do(t, http.MethodPost,
		"/api/v1/access/apply?connection="+connA.ID.String(),
		manifest(entry(connB.DisplayName)), &operator, true)
	requireStatus(t, resp, http.StatusBadRequest)

	// Клиенты без optional query-параметра сохраняют прежнюю семантику.
	resp = env.do(t, http.MethodPost, "/api/v1/access/plan",
		manifest(entry(connA.DisplayName), entry(connB.DisplayName)), &operator, true)
	requireStatus(t, resp, http.StatusOK)
}

func TestIntegrationAccessManifestApplyExport(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	operator := session(auth.RoleOperator)
	viewer := session(auth.RoleViewer)

	sfx := uniqueSuffix()
	mfEnv := "mfenv-" + sfx
	conn := activeFakeConnectionEnv(t, env.pool, mfEnv)
	principal := createPrincipalWithSubject(t, env.pool, "mfsub-"+sfx)
	subject := principal.ExternalSubject

	present := map[string]any{
		"version":     "v1",
		"environment": mfEnv,
		"entries": []map[string]any{
			{"principal": subject, "connection": conn.DisplayName, "role": "role:app-readonly"},
		},
	}

	// Первый apply создаёт managed-аккаунт и binding.
	resp := env.do(t, http.MethodPost, "/api/v1/access/apply", present, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var applied struct {
		OperationID  uuid.UUID `json:"operation_id"`
		ActionsCount int       `json:"actions_count"`
		Children     []struct {
			Kind                     string     `json:"kind"`
			AccountID                uuid.UUID  `json:"account_id"`
			AccountCreateOperationID *uuid.UUID `json:"account_create_operation_id"`
			GrantOperationID         *uuid.UUID `json:"grant_operation_id"`
			BindingID                *uuid.UUID `json:"binding_id"`
		} `json:"children"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&applied); err != nil {
		t.Fatalf("decode apply response: %v", err)
	}
	if applied.ActionsCount != 2 {
		t.Errorf("actions_count = %d, want 2 (create_account + grant)", applied.ActionsCount)
	}
	if len(applied.Children) != 1 {
		t.Fatalf("children = %d, want 1", len(applied.Children))
	}
	child := applied.Children[0]
	if child.AccountCreateOperationID == nil || child.GrantOperationID == nil || child.BindingID == nil {
		t.Fatalf("child missing ops: create=%v grant=%v binding=%v",
			child.AccountCreateOperationID, child.GrantOperationID, child.BindingID)
	}

	parent, err := operations.NewStore().Get(t.Context(), env.pool, applied.OperationID)
	if err != nil {
		t.Fatalf("get parent operation: %v", err)
	}
	if parent.Kind != jobs.KindBulkManifestApply || parent.Status != operations.StatusRunning {
		t.Errorf("parent kind/status = %q/%q, want bulk.manifest_apply/running", parent.Kind, parent.Status)
	}

	acct, err := inventory.NewStore().GetAccount(t.Context(), env.pool, child.AccountID)
	if err != nil {
		t.Fatalf("get account: %v", err)
	}
	if acct.PrincipalID == nil || *acct.PrincipalID != principal.ID {
		t.Errorf("account principal_id = %v, want %s", acct.PrincipalID, principal.ID)
	}
	if acct.EngineIdentity != subject || acct.Ownership != inventory.OwnershipManaged {
		t.Errorf("account identity/ownership = %q/%q, want %q/managed", acct.EngineIdentity, acct.Ownership, subject)
	}
	binding, err := inventory.NewStore().GetBinding(t.Context(), env.pool, *child.BindingID)
	if err != nil {
		t.Fatalf("get binding: %v", err)
	}
	if binding.DesiredState == nil || *binding.DesiredState != inventory.BindingPresent {
		t.Errorf("binding desired = %v, want present", binding.DesiredState)
	}
	if _, err := operations.NewStore().Transition(t.Context(), env.pool, *child.AccountCreateOperationID,
		operations.StatusPending, operations.StatusRunning, operations.TransitionOpts{}); err != nil {
		t.Fatalf("start manifest account.create: %v", err)
	}
	if _, err := operations.NewStore().Transition(t.Context(), env.pool, *child.AccountCreateOperationID,
		operations.StatusRunning, operations.StatusSuccess, operations.TransitionOpts{}); err != nil {
		t.Fatalf("finish manifest account.create: %v", err)
	}

	// Идемпотентность: повторный apply того же манифеста — 0 действий.
	resp = env.do(t, http.MethodPost, "/api/v1/access/apply", present, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var again struct {
		ActionsCount int               `json:"actions_count"`
		Children     []json.RawMessage `json:"children"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&again); err != nil {
		t.Fatalf("decode re-apply response: %v", err)
	}
	if again.ActionsCount != 0 || len(again.Children) != 0 {
		t.Errorf("re-apply actions_count=%d children=%d, want 0/0 (idempotent)", again.ActionsCount, len(again.Children))
	}

	// Export отражает применённый доступ.
	exportPath := "/api/v1/access/export?environment=" + mfEnv
	resp = env.do(t, http.MethodGet, exportPath, nil, &viewer, false)
	requireStatus(t, resp, http.StatusOK)
	var exported struct {
		Version string `json:"version"`
		Entries []struct {
			Principal  string `json:"principal"`
			Connection string `json:"connection"`
			Role       string `json:"role"`
			State      string `json:"state"`
		} `json:"entries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&exported); err != nil {
		t.Fatalf("decode export response: %v", err)
	}
	if exported.Version != "v1" || len(exported.Entries) != 1 {
		t.Fatalf("export version/entries = %q/%d, want v1/1", exported.Version, len(exported.Entries))
	}
	e := exported.Entries[0]
	if e.Principal != subject || e.Connection != conn.DisplayName || e.Role != "role:app-readonly" || e.State != "present" {
		t.Errorf("exported entry = %+v, want subject/conn/role:app-readonly/present", e)
	}

	// Absent-манифест отзывает доступ.
	absent := map[string]any{
		"version":     "v1",
		"environment": mfEnv,
		"entries": []map[string]any{
			{"principal": subject, "connection": conn.DisplayName, "role": "role:app-readonly", "state": "absent"},
		},
	}
	resp = env.do(t, http.MethodPost, "/api/v1/access/apply", absent, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var revoked struct {
		ActionsCount int `json:"actions_count"`
		Children     []struct {
			Kind              string     `json:"kind"`
			RevokeOperationID *uuid.UUID `json:"revoke_operation_id"`
		} `json:"children"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&revoked); err != nil {
		t.Fatalf("decode revoke response: %v", err)
	}
	if revoked.ActionsCount != 1 || len(revoked.Children) != 1 || revoked.Children[0].Kind != "revoke" {
		t.Errorf("revoke actions_count=%d children=%+v, want 1 revoke", revoked.ActionsCount, revoked.Children)
	}
	if revoked.Children[0].RevokeOperationID == nil {
		t.Error("revoke child missing operation id")
	}
	binding, err = inventory.NewStore().GetBinding(t.Context(), env.pool, *child.BindingID)
	if err != nil {
		t.Fatalf("get binding after revoke: %v", err)
	}
	if binding.DesiredState == nil || *binding.DesiredState != inventory.BindingAbsent {
		t.Errorf("binding desired = %v, want absent", binding.DesiredState)
	}

	// После отзыва export по этому окружению пуст.
	resp = env.do(t, http.MethodGet, exportPath, nil, &viewer, false)
	requireStatus(t, resp, http.StatusOK)
	var afterRevoke struct {
		Entries []json.RawMessage `json:"entries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&afterRevoke); err != nil {
		t.Fatalf("decode export after revoke: %v", err)
	}
	if len(afterRevoke.Entries) != 0 {
		t.Errorf("export after revoke = %d entries, want 0", len(afterRevoke.Entries))
	}
}

// TestIntegrationAccessManifestExportByConnection проверяет scope экспорта по
// подключению: два managed-подключения одного окружения, export?connection=A
// возвращает только записи A (json и yaml round-trip), неизвестное подключение
// — 404. Общий окружение-фильтр их не разделил бы — сужает именно connection.
func TestIntegrationAccessManifestExportByConnection(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	operator := session(auth.RoleOperator)
	viewer := session(auth.RoleViewer)

	sfx := uniqueSuffix()
	mfEnv := "mfenv-" + sfx
	connA := activeFakeConnectionEnv(t, env.pool, mfEnv)
	connB := activeFakeConnectionEnv(t, env.pool, mfEnv)
	principal := createPrincipalWithSubject(t, env.pool, "mfsub-"+sfx)
	subject := principal.ExternalSubject

	// Managed-доступ в обоих подключениях одного окружения.
	present := map[string]any{
		"version":     "v1",
		"environment": mfEnv,
		"entries": []map[string]any{
			{"principal": subject, "connection": connA.DisplayName, "role": "role:app-readonly"},
			{"principal": subject, "connection": connB.DisplayName, "role": "role:app-readonly"},
		},
	}
	resp := env.do(t, http.MethodPost, "/api/v1/access/apply", present, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)

	type exportBody struct {
		Version string `json:"version"`
		Entries []struct {
			Principal  string `json:"principal"`
			Connection string `json:"connection"`
			Role       string `json:"role"`
			State      string `json:"state"`
		} `json:"entries"`
	}

	// Без connection-фильтра (только окружение) видны оба подключения.
	resp = env.do(t, http.MethodGet, "/api/v1/access/export?environment="+mfEnv, nil, &viewer, false)
	requireStatus(t, resp, http.StatusOK)
	var all exportBody
	if err := json.NewDecoder(resp.Body).Decode(&all); err != nil {
		t.Fatalf("decode export all: %v", err)
	}
	if len(all.Entries) != 2 {
		t.Fatalf("export environment-only entries = %d, want 2 (both connections)", len(all.Entries))
	}

	// connection=A по display_name (json): только записи A.
	resp = env.do(t, http.MethodGet,
		"/api/v1/access/export?connection="+url.QueryEscape(connA.DisplayName), nil, &viewer, false)
	requireStatus(t, resp, http.StatusOK)
	var onlyA exportBody
	if err := json.NewDecoder(resp.Body).Decode(&onlyA); err != nil {
		t.Fatalf("decode export connection=A: %v", err)
	}
	if len(onlyA.Entries) != 1 {
		t.Fatalf("export connection=A entries = %d, want 1", len(onlyA.Entries))
	}
	if e := onlyA.Entries[0]; e.Connection != connA.DisplayName || e.Principal != subject ||
		e.Role != "role:app-readonly" || e.State != "present" {
		t.Errorf("export connection=A entry = %+v, want A/subject/role:app-readonly/present", e)
	}

	// connection=A по id + format=yaml: round-trip в тот же Manifest, одна запись A.
	resp = env.do(t, http.MethodGet,
		"/api/v1/access/export?connection="+connA.ID.String()+"&format=yaml", nil, &viewer, false)
	requireStatus(t, resp, http.StatusOK)
	if ct := resp.Header.Get("Content-Type"); ct != "application/yaml" {
		t.Errorf("export yaml Content-Type = %q, want application/yaml", ct)
	}
	var exportedYAML accessmanifest.Manifest
	if err := yaml.Unmarshal(readBody(t, resp), &exportedYAML); err != nil {
		t.Fatalf("unmarshal exported yaml: %v", err)
	}
	if len(exportedYAML.Entries) != 1 || exportedYAML.Entries[0].Connection != connA.DisplayName {
		t.Fatalf("export connection=A yaml entries = %+v, want one A entry", exportedYAML.Entries)
	}

	// Неизвестное подключение (несуществующий id и имя) — 404.
	resp = env.do(t, http.MethodGet, "/api/v1/access/export?connection="+uuid.NewString(), nil, &viewer, false)
	requireStatus(t, resp, http.StatusNotFound)
	resp = env.do(t, http.MethodGet, "/api/v1/access/export?connection=no-such-connection-"+sfx, nil, &viewer, false)
	requireStatus(t, resp, http.StatusNotFound)
}

func TestIntegrationAccessManifestDangerous(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	operator := session(auth.RoleOperator)
	admin := session(auth.RoleAdmin)

	sfx := uniqueSuffix()
	mfEnv := "mfenv-" + sfx
	conn := activeFakeConnectionEnv(t, env.pool, mfEnv)
	principal := createPrincipalWithSubject(t, env.pool, "mfsub-"+sfx)

	manifest := func(confirm bool) map[string]any {
		m := map[string]any{
			"version":     "v1",
			"environment": mfEnv,
			"entries": []map[string]any{
				{"principal": principal.ExternalSubject, "connection": conn.DisplayName, "role": "role:superuser"},
			},
		}
		if confirm {
			m["confirm"] = true
		}
		return m
	}

	// Plan помечает dangerous, но не гейтит (dry-run).
	resp := env.do(t, http.MethodPost, "/api/v1/access/plan", manifest(false), &operator, true)
	requireStatus(t, resp, http.StatusOK)
	var out struct {
		Summary struct {
			Dangerous int `json:"dangerous"`
		} `json:"summary"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode plan response: %v", err)
	}
	if out.Summary.Dangerous < 1 {
		t.Errorf("summary dangerous = %d, want >= 1", out.Summary.Dangerous)
	}

	// operator даже с confirm не может применить dangerous — 403.
	resp = env.do(t, http.MethodPost, "/api/v1/access/apply", manifest(true), &operator, true)
	requireStatus(t, resp, http.StatusForbidden)
	// admin без confirm — 400.
	resp = env.do(t, http.MethodPost, "/api/v1/access/apply", manifest(false), &admin, true)
	requireStatus(t, resp, http.StatusBadRequest)
	// admin с confirm — 202.
	resp = env.do(t, http.MethodPost, "/api/v1/access/apply", manifest(true), &admin, true)
	requireStatus(t, resp, http.StatusAccepted)
}

// doRaw выполняет запрос с сырым телом и явным Content-Type (YAML-манифесты).
// Сессия обязательна; CSRF-заголовок ставится всегда (helper используется
// мутирующими POST).
func doRaw(t *testing.T, env *testEnv, method, path, contentType, body string, sess auth.Session) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, env.srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", contentType)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: env.codec.Encode(sess)})
	req.Header.Set(auth.CSRFHeader, env.codec.CSRFToken(sess))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	t.Cleanup(func() { resp.Body.Close() }) //nolint:errcheck
	return resp
}

func TestIntegrationAccessManifestYAML(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	operator := session(auth.RoleOperator)
	viewer := session(auth.RoleViewer)

	sfx := uniqueSuffix()
	mfEnv := "mfenv-" + sfx
	conn := activeFakeConnectionEnv(t, env.pool, mfEnv)
	principal := createPrincipalWithSubject(t, env.pool, "mfsub-"+sfx)

	yamlManifest := fmt.Sprintf(`version: v1
environment: %s
entries:
  - principal: %s
    connection: %s
    role: role:app-readonly
`, mfEnv, principal.ExternalSubject, conn.DisplayName)

	// Неподдерживаемый Content-Type — 415; битый YAML — 400.
	resp := doRaw(t, env, http.MethodPost, "/api/v1/access/plan", "text/plain", yamlManifest, operator)
	requireStatus(t, resp, http.StatusUnsupportedMediaType)
	resp = doRaw(t, env, http.MethodPost, "/api/v1/access/plan", "application/yaml", "entries: [::broken", operator)
	requireStatus(t, resp, http.StatusBadRequest)

	// Plan принимает YAML и строит тот же план, что и для JSON.
	resp = doRaw(t, env, http.MethodPost, "/api/v1/access/plan", "application/yaml", yamlManifest, operator)
	requireStatus(t, resp, http.StatusOK)
	var planned struct {
		Summary struct {
			Grants  int `json:"grants"`
			Creates int `json:"creates"`
			Revokes int `json:"revokes"`
		} `json:"summary"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&planned); err != nil {
		t.Fatalf("decode plan response: %v", err)
	}
	if planned.Summary.Creates != 1 || planned.Summary.Grants != 1 || planned.Summary.Revokes != 0 {
		t.Errorf("summary = %+v, want creates=1 grants=1 revokes=0", planned.Summary)
	}

	// Apply тем же YAML-телом создаёт managed-аккаунт и binding.
	resp = doRaw(t, env, http.MethodPost, "/api/v1/access/apply", "text/yaml", yamlManifest, operator)
	requireStatus(t, resp, http.StatusAccepted)
	var applied struct {
		ActionsCount int `json:"actions_count"`
		Children     []struct {
			BindingID *uuid.UUID `json:"binding_id"`
		} `json:"children"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&applied); err != nil {
		t.Fatalf("decode apply response: %v", err)
	}
	if applied.ActionsCount != 2 || len(applied.Children) != 1 {
		t.Fatalf("apply actions_count=%d children=%d, want 2/1", applied.ActionsCount, len(applied.Children))
	}

	// Export в YAML: правильный Content-Type, декодируется в тот же Manifest.
	exportPath := "/api/v1/access/export?environment=" + mfEnv + "&format=yaml"
	resp = env.do(t, http.MethodGet, exportPath, nil, &viewer, false)
	requireStatus(t, resp, http.StatusOK)
	if ct := resp.Header.Get("Content-Type"); ct != "application/yaml" {
		t.Errorf("export Content-Type = %q, want application/yaml", ct)
	}
	exportedYAML := readBody(t, resp)
	var exported accessmanifest.Manifest
	if err := yaml.Unmarshal(exportedYAML, &exported); err != nil {
		t.Fatalf("unmarshal exported yaml: %v\nyaml:\n%s", err, exportedYAML)
	}
	if exported.Version != "v1" || len(exported.Entries) != 1 {
		t.Fatalf("export version/entries = %q/%d, want v1/1; yaml:\n%s", exported.Version, len(exported.Entries), exportedYAML)
	}
	e := exported.Entries[0]
	if e.Principal != principal.ExternalSubject || e.Connection != conn.DisplayName || e.Role != "role:app-readonly" {
		t.Errorf("exported entry = %+v, want subject/conn/role:app-readonly", e)
	}

	// Round-trip: экспортированный YAML снова проходит plan и даёт пустой
	// план (состояние уже применено).
	resp = doRaw(t, env, http.MethodPost, "/api/v1/access/plan", "application/yaml", string(exportedYAML), operator)
	requireStatus(t, resp, http.StatusOK)
	var roundTrip struct {
		Plan struct {
			Actions    []json.RawMessage `json:"actions"`
			Unresolved []json.RawMessage `json:"unresolved"`
		} `json:"plan"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&roundTrip); err != nil {
		t.Fatalf("decode round-trip plan: %v", err)
	}
	if len(roundTrip.Plan.Actions) != 0 || len(roundTrip.Plan.Unresolved) != 0 {
		t.Errorf("round-trip plan actions=%d unresolved=%d, want 0/0; exported yaml:\n%s",
			len(roundTrip.Plan.Actions), len(roundTrip.Plan.Unresolved), exportedYAML)
	}

	// Неизвестный format — 400.
	resp = env.do(t, http.MethodGet, "/api/v1/access/export?format=xml", nil, &viewer, false)
	requireStatus(t, resp, http.StatusBadRequest)
}

// TestIntegrationAccessManifestYAMLDangerousConfirmQuery проверяет
// dangerous-контроль для YAML-манифеста: confirm передаётся query-параметром
// (?confirm=true), не переписывая сам документ манифеста.
func TestIntegrationAccessManifestYAMLDangerousConfirmQuery(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	operator := session(auth.RoleOperator)
	admin := session(auth.RoleAdmin)

	sfx := uniqueSuffix()
	mfEnv := "mfenv-" + sfx
	conn := activeFakeConnectionEnv(t, env.pool, mfEnv)
	principal := createPrincipalWithSubject(t, env.pool, "mfsub-"+sfx)

	yamlManifest := fmt.Sprintf(`version: v1
environment: %s
entries:
  - principal: %s
    connection: %s
    role: role:superuser
`, mfEnv, principal.ExternalSubject, conn.DisplayName)

	// operator — 403 даже с confirm; admin без confirm — 400.
	resp := doRaw(t, env, http.MethodPost, "/api/v1/access/apply?confirm=true", "application/yaml", yamlManifest, operator)
	requireStatus(t, resp, http.StatusForbidden)
	resp = doRaw(t, env, http.MethodPost, "/api/v1/access/apply", "application/yaml", yamlManifest, admin)
	requireStatus(t, resp, http.StatusBadRequest)
	// admin с ?confirm=true — 202: YAML-документ не переписывался.
	resp = doRaw(t, env, http.MethodPost, "/api/v1/access/apply?confirm=true", "application/yaml", yamlManifest, admin)
	requireStatus(t, resp, http.StatusAccepted)
}

// TestIntegrationAccessManifestIdentityOverride: аккаунт, созданный с явным
// engine_identity, план обязан узнать по принадлежности принципалу.
//
// Identity в манифесте не хранится и выводится из имени принципала, поэтому
// поиск строго по ней не находил такой аккаунт: export отдавал выданное
// право, а следующий plan того же манифеста предлагал завести второй аккаунт
// и выдать право ему — export→apply переставал быть идемпотентным.
func TestIntegrationAccessManifestIdentityOverride(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	operator := session(auth.RoleOperator)

	sfx := uniqueSuffix()
	mfEnv := "idov-" + sfx
	conn := activeFakeConnectionEnv(t, env.pool, mfEnv)
	principal := createPrincipalWithSubject(t, env.pool, "idov-"+sfx)
	perm := findPermission(t, env.pool, conn.ID, "role:app-readonly")

	// Выдача с явной identity: она заведомо не совпадает с выведенной из
	// имени принципала.
	identity := "custom_" + sfx[:8]
	access := grantPrincipalAccessItems(t, env, &operator, principal.ID, identity, []map[string]any{
		{"connection_id": conn.ID, "permission_id": perm.ID},
	})
	finishProvisionChildren(t, env, access.Children)

	manifest := map[string]any{
		"version": "v1", "environment": mfEnv,
		"entries": []map[string]any{
			{"principal": principal.ExternalSubject, "connection": conn.DisplayName,
				"role": "role:app-readonly", "state": "present"},
		},
	}
	resp := env.do(t, http.MethodPost, "/api/v1/access/plan", manifest, &operator, true)
	requireStatus(t, resp, http.StatusOK)
	var out struct {
		Plan struct {
			Actions    []map[string]any `json:"actions"`
			Unresolved []map[string]any `json:"unresolved"`
		} `json:"plan"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode plan: %v", err)
	}
	if len(out.Plan.Actions) != 0 {
		t.Fatalf("plan for an already granted access = %v, want no actions", out.Plan.Actions)
	}
	if len(out.Plan.Unresolved) != 0 {
		t.Fatalf("plan unresolved = %v, want none", out.Plan.Unresolved)
	}
}
