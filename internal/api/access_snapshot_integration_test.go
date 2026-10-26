//go:build integration

// Integration-тесты снапшота доступов (GET /api/v1/access/export?sections=)
// на fake adapter: инвентарь fake содержит unmanaged-аккаунты svc-a/readers
// и unmanaged binding readers -> role:app-readonly. Проверяется: снапшот со
// всеми секциями поверх managed + unmanaged данных, байт-совместимость
// sections=managed с export без sections, YAML-формат, 400 на неизвестную
// секцию и на снапшот без connection, отказ apply принимать снапшот.
package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/ArtefactoO/grantor/internal/auth"
)

// snapshotBody — разбор JSON-снапшота в тестах. Указатели на срезы
// отличают отсутствующую секцию (nil) от запрошенной пустой ([]).
type snapshotBody struct {
	Kind       string `json:"kind"`
	Connection struct {
		ID          string `json:"id"`
		DisplayName string `json:"display_name"`
		Engine      string `json:"engine"`
		Environment string `json:"environment"`
	} `json:"connection"`
	GeneratedAt string `json:"generated_at"`
	Managed     *[]struct {
		Principal string `json:"principal"`
		Account   string `json:"account"`
		Role      string `json:"role"`
		Scope     string `json:"scope"`
		State     string `json:"state"`
	} `json:"managed"`
	Unmanaged *[]struct {
		Account       string `json:"account"`
		Role          string `json:"role"`
		Scope         string `json:"scope"`
		ObservedState string `json:"observed_state"`
	} `json:"unmanaged"`
	Roles *[]struct {
		Name       string `json:"name"`
		ExternalID string `json:"external_id"`
		Assignable bool   `json:"assignable"`
		Dangerous  bool   `json:"dangerous"`
		Scope      string `json:"scope"`
	} `json:"roles"`
	Accounts *[]struct {
		EngineIdentity string `json:"engine_identity"`
		Kind           string `json:"kind"`
		Ownership      string `json:"ownership"`
		Status         string `json:"status"`
		Principal      string `json:"principal"`
	} `json:"accounts"`
}

func TestIntegrationAccessSnapshotExport(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	operator := session(auth.RoleOperator)
	viewer := session(auth.RoleViewer)

	sfx := uniqueSuffix()
	mfEnv := "snapenv-" + sfx
	conn := activeFakeConnectionEnv(t, env.pool, mfEnv)
	principal := createPrincipalWithSubject(t, env.pool, "snapsub-"+sfx)
	subject := principal.ExternalSubject

	// Managed-грант через manifest apply: рядом с unmanaged-данными fake
	// discovery (readers -> role:app-readonly) появляется managed binding.
	present := map[string]any{
		"version":     "v1",
		"environment": mfEnv,
		"entries": []map[string]any{
			{"principal": subject, "connection": conn.DisplayName, "role": "role:app-readonly"},
		},
	}
	resp := env.do(t, http.MethodPost, "/api/v1/access/apply", present, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)

	base := "/api/v1/access/export?connection=" + conn.ID.String()

	// Байт-совместимость: sections=managed отвечает теми же байтами, что и
	// export без sections (оба идут прежним manifest-путём).
	resp = env.do(t, http.MethodGet, base, nil, &viewer, false)
	requireStatus(t, resp, http.StatusOK)
	plain := readBody(t, resp)
	resp = env.do(t, http.MethodGet, base+"&sections=managed", nil, &viewer, false)
	requireStatus(t, resp, http.StatusOK)
	managedOnly := readBody(t, resp)
	if string(plain) != string(managedOnly) {
		t.Errorf("sections=managed export differs from plain export:\nplain:   %s\nmanaged: %s", plain, managedOnly)
	}
	if !strings.Contains(string(plain), `"version":"v1"`) {
		t.Errorf("plain export is not a manifest: %s", plain)
	}

	// Снапшот со всеми секциями; viewer достаточно (RBAC не менялся).
	resp = env.do(t, http.MethodGet, base+"&sections=managed,unmanaged,roles,accounts", nil, &viewer, false)
	requireStatus(t, resp, http.StatusOK)
	raw := readBody(t, resp)
	if strings.Contains(string(raw), "vault_path") || strings.Contains(string(raw), "principals/") {
		t.Errorf("snapshot leaks vault paths: %s", raw)
	}
	var snap snapshotBody
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatalf("unmarshal snapshot: %v\nbody: %s", err, raw)
	}
	if snap.Kind != "access_snapshot" {
		t.Errorf("kind = %q, want access_snapshot", snap.Kind)
	}
	if snap.Connection.ID != conn.ID.String() || snap.Connection.DisplayName != conn.DisplayName ||
		snap.Connection.Engine != "fake" || snap.Connection.Environment != mfEnv {
		t.Errorf("connection block = %+v", snap.Connection)
	}
	if snap.GeneratedAt == "" {
		t.Error("generated_at is empty")
	}

	if snap.Managed == nil || len(*snap.Managed) != 1 {
		t.Fatalf("managed = %+v, want exactly the applied grant", snap.Managed)
	}
	if m := (*snap.Managed)[0]; m.Principal != subject || m.Account == "" ||
		m.Role != "role:app-readonly" || m.State != "present" {
		t.Errorf("managed[0] = %+v, want %s/<account>/role:app-readonly/present", m, subject)
	}

	// Unmanaged: ровно один binding readers -> app-readonly (managed binding
	// принципала в секцию не попадает).
	if snap.Unmanaged == nil || len(*snap.Unmanaged) != 1 {
		t.Fatalf("unmanaged = %+v, want exactly one readers binding", snap.Unmanaged)
	}
	if u := (*snap.Unmanaged)[0]; u.Account != "readers" || u.Role != "app-readonly" ||
		u.Scope != "" || u.ObservedState != "present" {
		t.Errorf("unmanaged[0] = %+v, want readers/app-readonly/present without scope", u)
	}

	// Roles: три permission definitions fake, superuser — dangerous.
	if snap.Roles == nil || len(*snap.Roles) != 3 {
		t.Fatalf("roles = %+v, want 3 fake permissions", snap.Roles)
	}
	dangerous := 0
	for _, role := range *snap.Roles {
		if role.Dangerous {
			dangerous++
			if role.Name != "superuser" {
				t.Errorf("dangerous role = %+v, want superuser", role)
			}
		}
	}
	if dangerous != 1 {
		t.Errorf("dangerous roles = %d, want 1", dangerous)
	}

	// Accounts: svc-a и readers (unmanaged из discovery) плюс managed-аккаунт
	// принципала со ссылкой на его external subject.
	if snap.Accounts == nil || len(*snap.Accounts) != 3 {
		t.Fatalf("accounts = %+v, want svc-a, readers and managed account", snap.Accounts)
	}
	foundManaged := false
	for _, acct := range *snap.Accounts {
		if acct.EngineIdentity == subject {
			foundManaged = true
			// Статус provisioning, а не active: worker в этом тесте не
			// запущен, поэтому account.create ещё не подтвердил учётку в
			// целевой системе. Аккаунт становится active только после
			// успешного create (см. миграцию 00013).
			if acct.Ownership != "managed" || acct.Principal != subject || acct.Status != "provisioning" {
				t.Errorf("managed account = %+v, want managed/provisioning linked to %s", acct, subject)
			}
		}
		if acct.EngineIdentity == "readers" && (acct.Ownership != "unmanaged" || acct.Principal != "") {
			t.Errorf("readers account = %+v, want unmanaged without principal", acct)
		}
	}
	if !foundManaged {
		t.Errorf("managed account %s not found in accounts section: %+v", subject, *snap.Accounts)
	}

	// Частичный снапшот: только запрошенные секции присутствуют.
	resp = env.do(t, http.MethodGet, base+"&sections=unmanaged", nil, &viewer, false)
	requireStatus(t, resp, http.StatusOK)
	var partial snapshotBody
	if err := json.NewDecoder(resp.Body).Decode(&partial); err != nil {
		t.Fatalf("decode partial snapshot: %v", err)
	}
	if partial.Managed != nil || partial.Roles != nil || partial.Accounts != nil {
		t.Errorf("partial snapshot has unrequested sections: %+v", partial)
	}
	if partial.Unmanaged == nil {
		t.Error("partial snapshot misses requested unmanaged section")
	}

	// YAML-формат снапшота: правильный Content-Type, декодируется в тот же
	// документ (сравниваются разобранные значения, не байты — jsonb здесь ни
	// при чём, но правило то же).
	resp = env.do(t, http.MethodGet, base+"&sections=unmanaged,roles&format=yaml", nil, &viewer, false)
	requireStatus(t, resp, http.StatusOK)
	if ct := resp.Header.Get("Content-Type"); ct != "application/yaml" {
		t.Errorf("snapshot yaml Content-Type = %q, want application/yaml", ct)
	}
	var fromYAML struct {
		Kind      string `yaml:"kind"`
		Unmanaged []struct {
			Account string `yaml:"account"`
			Role    string `yaml:"role"`
		} `yaml:"unmanaged"`
		Roles []struct {
			ExternalID string `yaml:"external_id"`
		} `yaml:"roles"`
	}
	if err := yaml.Unmarshal(readBody(t, resp), &fromYAML); err != nil {
		t.Fatalf("unmarshal yaml snapshot: %v", err)
	}
	if fromYAML.Kind != "access_snapshot" || len(fromYAML.Unmanaged) != 1 || len(fromYAML.Roles) != 3 {
		t.Errorf("yaml snapshot = %+v, want kind/1 unmanaged/3 roles", fromYAML)
	}

	// Ошибки: неизвестная секция и снапшот без connection — 400.
	resp = env.do(t, http.MethodGet, base+"&sections=bogus", nil, &viewer, false)
	requireStatus(t, resp, http.StatusBadRequest)
	resp = env.do(t, http.MethodGet, "/api/v1/access/export?sections=unmanaged", nil, &viewer, false)
	requireStatus(t, resp, http.StatusBadRequest)

	// Снапшот не применяется: apply отвергает его валидацией манифеста.
	resp = env.do(t, http.MethodPost, "/api/v1/access/apply",
		json.RawMessage(raw), &operator, true)
	requireStatus(t, resp, http.StatusBadRequest)
}
