//go:build integration

// Integration-тесты обогащения списка accounts connection их bindings
// (GET /api/v1/connections/{id}/accounts?include=bindings) на fake
// adapter. Проверяется: дефолт лёгкий (без bindings), include=bindings
// добавляет к каждому аккаунту его гранты, и они совпадают с
// GET /accounts/{id}/bindings того же аккаунта. Покрыт unmanaged/observed
// аккаунт (реальный кейс: обнаруженные discovery пользователи).
package api_test

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/ArtefactoO/grantor/internal/auth"
)

// acctItemRaw — аккаунт в ответе списка с bindings как сырым JSON (для
// точного сравнения с single-account endpoint).
type acctItemRaw struct {
	ID             string          `json:"id"`
	EngineIdentity string          `json:"engine_identity"`
	Ownership      string          `json:"ownership"`
	Bindings       json.RawMessage `json:"bindings"`
}

type acctListRaw struct {
	Accounts []acctItemRaw `json:"accounts"`
}

// acctBinding — подмножество bindingJSON для проверки «уровень + где».
type acctBinding struct {
	AccountID                      string         `json:"account_id"`
	PermissionDefinitionID         string         `json:"permission_definition_id"`
	ScopeResourceID                *string        `json:"scope_resource_id"`
	AssignmentKey                  string         `json:"assignment_key"`
	ObservedPermissionDefinitionID *string        `json:"observed_permission_definition_id"`
	ObservedAttributes             map[string]any `json:"observed_attributes"`
	Source                         string         `json:"source"`
	DesiredState                   *string        `json:"desired_state"`
	ObservedState                  string         `json:"observed_state"`
	Status                         string         `json:"status"`
	BindingVersion                 int64          `json:"binding_version"`
	TransitionOperationID          *string        `json:"transition_operation_id"`
}

func findAcct(t *testing.T, accts []acctItemRaw, identity string) acctItemRaw {
	t.Helper()
	for _, a := range accts {
		if a.EngineIdentity == identity {
			return a
		}
	}
	t.Fatalf("account %q not found among %d", identity, len(accts))
	return acctItemRaw{}
}

func TestIntegrationConnectionAccountsIncludeBindings(t *testing.T) {
	env := newTestEnv(t, nil)
	viewer := session(auth.RoleViewer)

	// Fake-инвентарь: accounts svc-a (login, unmanaged, без bindings) и
	// readers (group, unmanaged, 1 unmanaged binding role:app-readonly,
	// connection-wide). Оба — обнаруженные discovery unmanaged-аккаунты.
	conn := activeFakeConnection(t, env.pool)
	base := "/api/v1/connections/" + conn.ID.String() + "/accounts"

	// Дефолт: список лёгкий — поля bindings нет вовсе.
	resp := env.do(t, http.MethodGet, base, nil, &viewer, false)
	requireStatus(t, resp, http.StatusOK)
	lightBody := readBody(t, resp)
	if strings.Contains(string(lightBody), "\"bindings\"") {
		t.Errorf("default accounts list unexpectedly contains bindings: %s", lightBody)
	}
	var light acctListRaw
	if err := json.Unmarshal(lightBody, &light); err != nil {
		t.Fatalf("unmarshal light list: %v", err)
	}
	for _, a := range light.Accounts {
		if a.Bindings != nil {
			t.Errorf("account %q has bindings without include param", a.EngineIdentity)
		}
	}

	// include=bindings: у каждого аккаунта есть массив bindings.
	resp = env.do(t, http.MethodGet, base+"?include=bindings", nil, &viewer, false)
	requireStatus(t, resp, http.StatusOK)
	var enriched acctListRaw
	if err := json.NewDecoder(resp.Body).Decode(&enriched); err != nil {
		t.Fatalf("decode enriched list: %v", err)
	}

	// svc-a: bindings присутствует как пустой массив (запросили, но грантов
	// нет) — не отсутствует и не null.
	svcA := findAcct(t, enriched.Accounts, "svc-a")
	if string(svcA.Bindings) != "[]" {
		t.Errorf("svc-a bindings = %s, want []", svcA.Bindings)
	}

	// readers: один unmanaged binding на role:app-readonly, connection-wide.
	readers := findAcct(t, enriched.Accounts, "readers")
	if readers.Ownership != "unmanaged" {
		t.Errorf("readers ownership = %q, want unmanaged", readers.Ownership)
	}
	var readerBindings []acctBinding
	if err := json.Unmarshal(readers.Bindings, &readerBindings); err != nil {
		t.Fatalf("unmarshal readers bindings: %v", err)
	}
	if len(readerBindings) != 1 {
		t.Fatalf("readers bindings = %d, want 1", len(readerBindings))
	}
	rb := readerBindings[0]
	perm := findPermission(t, env.pool, conn.ID, "role:app-readonly")
	if rb.PermissionDefinitionID != perm.ID.String() {
		t.Errorf("binding permission = %q, want %q", rb.PermissionDefinitionID, perm.ID)
	}
	if rb.ScopeResourceID != nil {
		t.Errorf("binding scope_resource_id = %v, want null (connection-wide)", *rb.ScopeResourceID)
	}
	if rb.AssignmentKey != "" {
		t.Errorf("binding assignment_key = %q, want empty for non-exclusive permission", rb.AssignmentKey)
	}
	if rb.ObservedPermissionDefinitionID == nil || *rb.ObservedPermissionDefinitionID != perm.ID.String() {
		t.Errorf("binding observed permission = %v, want %q", rb.ObservedPermissionDefinitionID, perm.ID)
	}
	if rb.ObservedAttributes == nil {
		t.Error("binding observed_attributes = nil, want JSON object")
	}
	if rb.BindingVersion != 0 || rb.TransitionOperationID != nil {
		t.Errorf("binding transition fields = version %d operation %v, want 0/nil",
			rb.BindingVersion, rb.TransitionOperationID)
	}
	if rb.Source != "external" {
		t.Errorf("binding source = %q, want external", rb.Source)
	}
	if rb.DesiredState != nil {
		t.Errorf("binding desired_state = %v, want null (unmanaged)", *rb.DesiredState)
	}
	if rb.ObservedState != "present" {
		t.Errorf("binding observed_state = %q, want present", rb.ObservedState)
	}
	if rb.AccountID != readers.ID {
		t.Errorf("binding account_id = %q, want readers %q", rb.AccountID, readers.ID)
	}

	// Обогащённые bindings readers БАЙТ-В-БАЙТ совпадают с ответом
	// GET /accounts/{id}/bindings того же аккаунта (один тип binding).
	resp = env.do(t, http.MethodGet, "/api/v1/accounts/"+readers.ID+"/bindings", nil, &viewer, false)
	requireStatus(t, resp, http.StatusOK)
	var single struct {
		Bindings json.RawMessage `json:"bindings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&single); err != nil {
		t.Fatalf("decode single-account bindings: %v", err)
	}
	var fromList, fromSingle []map[string]any
	if err := json.Unmarshal(readers.Bindings, &fromList); err != nil {
		t.Fatalf("unmarshal enriched readers bindings: %v", err)
	}
	if err := json.Unmarshal(single.Bindings, &fromSingle); err != nil {
		t.Fatalf("unmarshal single-account bindings: %v", err)
	}
	if !reflect.DeepEqual(fromList, fromSingle) {
		t.Errorf("enriched bindings differ from /accounts/{id}/bindings:\n list:   %s\n single: %s",
			readers.Bindings, single.Bindings)
	}
}
