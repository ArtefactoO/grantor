//go:build integration

// Integration-тесты каскада принципала на fake adapter (worker не
// запускается): обратимый disable/enable (bulk parent + account.disable/
// account.enable children, скип аккаунтов в целевом статусе, metadata-only
// без целей), обратимый offboard (children revoke + credential.rotate,
// новая версия секрета в Vault, pending_purge со сроком хранения,
// unmanaged-аккаунты в ответе, guard'ы 400/403/409) и mass-revoke gate.
// Сквозной цикл с реальным целевым PostgreSQL и worker — в
// principal_cascade_e2e_integration_test.go.
package api_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/principals"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

// cascadeStatusResponse — 202-ответ каскадного disable/enable: прежние
// поля принципала плюс operation_id и children.
type cascadeStatusResponse struct {
	ID          uuid.UUID `json:"id"`
	Status      string    `json:"status"`
	OperationID uuid.UUID `json:"operation_id"`
	Children    []struct {
		ConnectionID uuid.UUID `json:"connection_id"`
		AccountID    uuid.UUID `json:"account_id"`
		OperationID  uuid.UUID `json:"operation_id"`
	} `json:"children"`
}

// offboardResponse — 202-ответ offboard.
type offboardResponse struct {
	OperationID uuid.UUID `json:"operation_id"`
	Children    []struct {
		Kind         string            `json:"kind"`
		ConnectionID uuid.UUID         `json:"connection_id"`
		AccountID    uuid.UUID         `json:"account_id"`
		BindingID    *uuid.UUID        `json:"binding_id"`
		OperationID  uuid.UUID         `json:"operation_id"`
		Status       operations.Status `json:"status"`
	} `json:"children"`
	UnmanagedAccounts []struct {
		ConnectionID   uuid.UUID `json:"connection_id"`
		EngineIdentity string    `json:"engine_identity"`
	} `json:"unmanaged_accounts"`
	// CredentialTakeoverRequired — аккаунты, чей пароль offboard не менял:
	// grantor им не владеет, а ротация присвоила бы чужой.
	CredentialTakeoverRequired []struct {
		ConnectionID   uuid.UUID `json:"connection_id"`
		EngineIdentity string    `json:"engine_identity"`
	} `json:"credential_takeover_required"`
}

// grantPrincipalAccessItems выдаёт принципалу роли через
// POST /principals/{id}/access и возвращает распарсенный ответ.
func grantPrincipalAccessItems(t *testing.T, env *testEnv, sess *auth.Session,
	principalID uuid.UUID, identity string, items []map[string]any) struct {
	OperationID uuid.UUID                  `json:"operation_id"`
	Children    []principalAccessChildBody `json:"children"`
} {
	t.Helper()
	resp := env.do(t, http.MethodPost, "/api/v1/principals/"+principalID.String()+"/access",
		map[string]any{"engine_identity": identity, "items": items}, sess, true)
	requireStatus(t, resp, http.StatusAccepted)
	var out struct {
		OperationID uuid.UUID                  `json:"operation_id"`
		Children    []principalAccessChildBody `json:"children"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode access response: %v", err)
	}
	return out
}

// requireOperation проверяет kind/status/parent операции в базе.
func requireOperation(t *testing.T, env *testEnv, id uuid.UUID, kind string, status operations.Status, parentID *uuid.UUID) operations.Operation {
	t.Helper()
	op, err := operations.NewStore().Get(t.Context(), env.pool, id)
	if err != nil {
		t.Fatalf("get operation %s: %v", id, err)
	}
	if op.Kind != kind || op.Status != status {
		t.Errorf("operation %s kind/status = %q/%q, want %q/%q", id, op.Kind, op.Status, kind, status)
	}
	if parentID != nil && (op.ParentID == nil || *op.ParentID != *parentID) {
		t.Errorf("operation %s parent = %v, want %s", id, op.ParentID, *parentID)
	}
	return op
}

// finishProvisionChildren моделирует завершившийся worker account.create в
// API-only тестах. Lifecycle reservation запрещает новый cascade поверх
// реально pending create; прежняя фикстура оставляла такие операции pending,
// хотя сценарий описывал уже созданные target accounts.
//
// Кроме статуса операции переводится и сам аккаунт: API создаёт его в
// provisioning, а живым (active) он становится только после подтверждённого
// адаптером create — ровно это и делает здесь executor-заглушка.
func finishProvisionChildren(t *testing.T, env *testEnv, children []principalAccessChildBody) {
	t.Helper()
	store := operations.NewStore()
	invStore := inventory.NewStore()
	for i := range children {
		id := children[i].AccountCreateOperationID
		if id == nil {
			continue
		}
		current, err := store.Get(t.Context(), env.pool, *id)
		if err != nil {
			t.Fatalf("load account.create %s: %v", *id, err)
		}
		if current.Status == operations.StatusSuccess {
			continue
		}
		if _, err := store.Transition(t.Context(), env.pool, *id,
			operations.StatusPending, operations.StatusRunning, operations.TransitionOpts{}); err != nil {
			t.Fatalf("start account.create %s: %v", *id, err)
		}
		if _, err := store.Transition(t.Context(), env.pool, *id,
			operations.StatusRunning, operations.StatusSuccess, operations.TransitionOpts{}); err != nil {
			t.Fatalf("finish account.create %s: %v", *id, err)
		}
		if err := invStore.SetAccountStatus(t.Context(), env.pool,
			children[i].AccountID, inventory.AccountActive); err != nil {
			t.Fatalf("activate account %s: %v", children[i].AccountID, err)
		}
	}
}

func TestIntegrationPrincipalDisableEnableCascade(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	operator := session(auth.RoleOperator)

	principal := createPrincipalRow(t, env.pool, "Cascade Service")
	connA := activeFakeConnectionEnv(t, env.pool, "test")
	connB := activeFakeConnectionEnv(t, env.pool, "test")
	permA := findPermission(t, env.pool, connA.ID, "role:app-readonly")
	permB := findPermission(t, env.pool, connB.ID, "role:app-readonly")

	identity := "itest_csc_" + uniqueSuffix()[:8]
	access := grantPrincipalAccessItems(t, env, &operator, principal.ID, identity, []map[string]any{
		{"connection_id": connA.ID, "permission_id": permA.ID},
		{"connection_id": connB.ID, "permission_id": permB.ID},
	})
	if len(access.Children) != 2 {
		t.Fatalf("access children = %d, want 2", len(access.Children))
	}
	finishProvisionChildren(t, env, access.Children)
	invStore := inventory.NewStore()
	// Аккаунт в connB заранее переводится в disabled: каскад disable обязан
	// его пропустить (он уже в целевом статусе).
	var acctA, acctB uuid.UUID
	for _, child := range access.Children {
		switch child.ConnectionID {
		case connA.ID:
			acctA = child.AccountID
		case connB.ID:
			acctB = child.AccountID
		}
	}
	if err := invStore.SetAccountStatus(t.Context(), env.pool, acctB, inventory.AccountDisabled); err != nil {
		t.Fatalf("preset account B disabled: %v", err)
	}

	// Disable: 202 с прежними полями принципала + operation_id/children;
	// ребёнок один — account.disable для аккаунта connA.
	resp := env.do(t, http.MethodPost, "/api/v1/principals/"+principal.ID.String()+"/disable", nil, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var disabled cascadeStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&disabled); err != nil {
		t.Fatalf("decode disable response: %v", err)
	}
	if disabled.ID != principal.ID || disabled.Status != string(principals.StatusDisabled) {
		t.Errorf("disable response id/status = %s/%q, want %s/disabled", disabled.ID, disabled.Status, principal.ID)
	}
	if len(disabled.Children) != 1 || disabled.Children[0].AccountID != acctA {
		t.Fatalf("disable children = %+v, want single child for account %s", disabled.Children, acctA)
	}
	parent := requireOperation(t, env, disabled.OperationID, jobs.KindBulkPrincipalDisable, operations.StatusRunning, nil)
	if parent.PrincipalID == nil || *parent.PrincipalID != principal.ID {
		t.Errorf("parent principal_id = %v, want %s", parent.PrincipalID, principal.ID)
	}
	requireOperation(t, env, disabled.Children[0].OperationID, jobs.KindAccountDisable, operations.StatusPending, &disabled.OperationID)

	stored, err := principals.NewStore().Get(t.Context(), env.pool, principal.ID)
	if err != nil {
		t.Fatalf("get principal: %v", err)
	}
	if stored.Status != principals.StatusDisabled {
		t.Errorf("principal status = %q, want disabled", stored.Status)
	}

	// Enable симметричен: ребёнок account.enable только для disabled
	// аккаунта (acctB; acctA в metadata остался active — worker не бежит).
	resp = env.do(t, http.MethodPost, "/api/v1/principals/"+principal.ID.String()+"/enable", nil, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var enabled cascadeStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&enabled); err != nil {
		t.Fatalf("decode enable response: %v", err)
	}
	if enabled.Status != string(principals.StatusActive) {
		t.Errorf("enable response status = %q, want active", enabled.Status)
	}
	if len(enabled.Children) != 1 || enabled.Children[0].AccountID != acctB {
		t.Fatalf("enable children = %+v, want single child for account %s", enabled.Children, acctB)
	}
	requireOperation(t, env, enabled.OperationID, jobs.KindBulkPrincipalEnable, operations.StatusRunning, nil)
	requireOperation(t, env, enabled.Children[0].OperationID, jobs.KindAccountEnable, operations.StatusPending, &enabled.OperationID)
}

func TestIntegrationPrincipalStatusMetadataOnlyWithoutAccounts(t *testing.T) {
	env := newTestEnv(t, nil)
	operator := session(auth.RoleOperator)
	principal := createPrincipalRow(t, env.pool, "No Accounts Service")

	// Без managed-аккаунтов каскадных целей нет: прежнее metadata-only
	// поведение — 200 без operation_id/children.
	resp := env.do(t, http.MethodPost, "/api/v1/principals/"+principal.ID.String()+"/disable", nil, &operator, true)
	requireStatus(t, resp, http.StatusOK)
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode disable response: %v", err)
	}
	if _, has := out["operation_id"]; has {
		t.Errorf("metadata-only disable response has operation_id: %v", out)
	}
	if out["status"] != string(principals.StatusDisabled) {
		t.Errorf("status = %v, want disabled", out["status"])
	}

	// Share/rotate выключенного принципала — 409 «principal is disabled».
	resp = env.do(t, http.MethodPost, "/api/v1/principals/"+principal.ID.String()+"/rotate", nil, &operator, true)
	requireStatus(t, resp, http.StatusConflict)
	resp = env.do(t, http.MethodPost, "/api/v1/principals/"+principal.ID.String()+"/share?environment=test", nil, &operator, true)
	requireStatus(t, resp, http.StatusConflict)
}

func TestIntegrationPrincipalOffboard(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	operator := session(auth.RoleOperator)
	admin := session(auth.RoleAdmin)

	principal := createPrincipalRow(t, env.pool, "Offboard Service")
	connA := activeFakeConnectionEnv(t, env.pool, "test")
	connB := activeFakeConnectionEnv(t, env.pool, "test")
	permRO := findPermission(t, env.pool, connA.ID, "role:app-readonly")
	permRW := findPermission(t, env.pool, connA.ID, "role:app-readwrite")
	permB := findPermission(t, env.pool, connB.ID, "role:app-readonly")

	identity := "itest_offb_" + uniqueSuffix()[:8]
	access := grantPrincipalAccessItems(t, env, &operator, principal.ID, identity, []map[string]any{
		{"connection_id": connA.ID, "permission_id": permRO.ID},
		{"connection_id": connA.ID, "permission_id": permRW.ID},
		{"connection_id": connB.ID, "permission_id": permB.ID},
	})
	finishProvisionChildren(t, env, access.Children)
	// Привязанный unmanaged-аккаунт (svc-a из discovery fake) не должен
	// быть затронут offboard и обязан попасть в ответ.
	unmanagedAcct := findAccount(t, env.pool, connA.ID, "svc-a")
	resp := env.do(t, http.MethodPost, "/api/v1/accounts/"+unmanagedAcct.ID.String()+"/link",
		map[string]any{"principal_id": principal.ID}, &operator, true)
	requireStatus(t, resp, http.StatusOK)

	path := "/api/v1/principals/" + principal.ID.String() + "/offboard"
	// Без confirm — 400; operator — 403 (endpoint admin-only).
	resp = env.do(t, http.MethodPost, path, nil, &admin, true)
	requireStatus(t, resp, http.StatusBadRequest)
	resp = env.do(t, http.MethodPost, path+"?confirm=true", nil, &operator, true)
	requireStatus(t, resp, http.StatusForbidden)

	sharedPath := "principals/" + principal.ID.String() + "/environments/test/credential"
	_, versionBefore, err := vaultClient.Get(t.Context(), sharedPath)
	if err != nil {
		t.Fatalf("shared secret must exist before offboard: %v", err)
	}

	resp = env.do(t, http.MethodPost, path, map[string]any{"confirm": true}, &admin, true)
	requireStatus(t, resp, http.StatusAccepted)
	var out offboardResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode offboard response: %v", err)
	}
	// Два managed-аккаунта, три binding: 3 revoke + 2 credential.rotate = 5
	// детей. Аккаунты не удаляются — offboard обратим до истечения срока
	// хранения.
	if len(out.Children) != 5 {
		t.Fatalf("offboard children = %d, want 5: %+v", len(out.Children), out.Children)
	}
	parent := requireOperation(t, env, out.OperationID, jobs.KindBulkPrincipalOffboard, operations.StatusRunning, nil)
	var parentPayload map[string]any
	if err := json.Unmarshal(parent.Payload, &parentPayload); err != nil {
		t.Fatalf("decode offboard parent payload: %v", err)
	}
	if _, staleCount := parentPayload["revokes"]; staleCount {
		t.Errorf("offboard parent payload carries pre-lock revoke count: %v", parentPayload)
	}
	if parentPayload["selection"] != "managed_accounts_request_snapshot" {
		t.Errorf("offboard parent payload selection = %v", parentPayload["selection"])
	}
	revokes, rotates := 0, 0
	rotatedAccounts := map[uuid.UUID]bool{}
	for _, child := range out.Children {
		switch child.Kind {
		case jobs.KindAccessRevoke:
			revokes++
			if child.BindingID == nil {
				t.Errorf("revoke child without binding_id: %+v", child)
			}
			requireOperation(t, env, child.OperationID, jobs.KindAccessRevoke, operations.StatusPending, &out.OperationID)
		case jobs.KindCredentialRotate:
			rotates++
			// Ровно одна ротация на аккаунт: вторая означала бы второй
			// резерв lifecycle, от которого упали бы revoke-дети.
			if rotatedAccounts[child.AccountID] {
				t.Errorf("account %s rotated twice by one offboard", child.AccountID)
			}
			rotatedAccounts[child.AccountID] = true
			requireOperation(t, env, child.OperationID, jobs.KindCredentialRotate, operations.StatusPending, &out.OperationID)
		default:
			t.Errorf("unexpected child kind %q", child.Kind)
		}
	}
	if revokes != 3 || rotates != 2 {
		t.Errorf("children mix = %d revokes / %d rotates, want 3/2", revokes, rotates)
	}
	requireOperation(t, env, out.OperationID, jobs.KindBulkPrincipalOffboard, operations.StatusRunning, nil)
	if len(out.UnmanagedAccounts) != 1 || out.UnmanagedAccounts[0].EngineIdentity != "svc-a" {
		t.Errorf("unmanaged_accounts = %+v, want [svc-a]", out.UnmanagedAccounts)
	}

	// Обратимость: принципал в pending_purge со сроком хранения, общий
	// секрет НЕ уничтожен, а перезаписан новой версией (дети
	// credential.rotate читают именно её), unmanaged-аккаунт не тронут.
	stored, err := principals.NewStore().Get(t.Context(), env.pool, principal.ID)
	if err != nil {
		t.Fatalf("get principal: %v", err)
	}
	if stored.Status != principals.StatusPendingPurge {
		t.Errorf("principal status = %q, want pending_purge", stored.Status)
	}
	if stored.PurgeAfter == nil || !stored.PurgeAfter.After(time.Now()) {
		t.Errorf("purge_after = %v, want a future deadline", stored.PurgeAfter)
	}
	_, versionAfter, err := vaultClient.Get(t.Context(), sharedPath)
	if err != nil {
		t.Fatalf("shared secret after offboard: %v", err)
	}
	if versionAfter <= versionBefore {
		t.Errorf("shared secret version = %d, want greater than %d (rotation writes a new version)",
			versionAfter, versionBefore)
	}
	untouched, err := inventory.NewStore().GetAccount(t.Context(), env.pool, unmanagedAcct.ID)
	if err != nil {
		t.Fatalf("get unmanaged account: %v", err)
	}
	if untouched.Ownership != inventory.OwnershipUnmanaged || untouched.Status != inventory.AccountActive {
		t.Errorf("unmanaged account changed: ownership=%q status=%q", untouched.Ownership, untouched.Status)
	}

	// Audit principal.offboarded с каунтерами (фильтр по действию; событие
	// нашего принципала отбирается по PrincipalID события).
	all, err := audit.NewWriter().List(t.Context(), env.pool, audit.Filter{
		Actions: []string{"principal.offboarded"},
	}, 100, 0)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	events := all[:0:0]
	for _, ev := range all {
		if ev.PrincipalID != nil && *ev.PrincipalID == principal.ID {
			events = append(events, ev)
		}
	}
	if len(events) != 1 {
		t.Fatalf("principal.offboarded events = %d, want 1", len(events))
	}
	var meta struct {
		ManagedAccounts  int         `json:"managed_accounts"`
		RevokedBindings  int         `json:"revoked_bindings"`
		Connections      []uuid.UUID `json:"connections"`
		UnmanagedLinked  int         `json:"unmanaged_linked"`
		RotatedAccounts  int         `json:"rotated_accounts"`
		TakeoverCreds    bool        `json:"takeover_credentials"`
		TakeoverRequired int         `json:"credential_takeover_required"`
		PurgeAfter       string      `json:"purge_after"`
	}
	if err := json.Unmarshal(events[0].Metadata, &meta); err != nil {
		t.Fatalf("unmarshal audit metadata: %v", err)
	}
	if meta.ManagedAccounts != 2 || meta.RevokedBindings != 3 || meta.UnmanagedLinked != 1 || len(meta.Connections) != 2 {
		t.Errorf("audit metadata = %+v, want {2, 3, 2 connections, 1}", meta)
	}
	// Audit обязан фиксировать и закрытие входа, и срок обратимости: без них
	// по журналу не отличить «вывели» от «сняли права».
	if meta.RotatedAccounts != 2 || meta.TakeoverCreds || meta.TakeoverRequired != 0 {
		t.Errorf("audit rotation metadata = %+v, want 2 rotated without takeover", meta)
	}
	if meta.PurgeAfter == "" {
		t.Error("audit metadata has no purge_after")
	}

	// Повторный offboard — 409; заблокированные действия над принципалом в
	// pending_purge — 409 (access/rotate/share/link/disable).
	resp = env.do(t, http.MethodPost, path+"?confirm=true", nil, &admin, true)
	requireStatus(t, resp, http.StatusConflict)
	resp = env.do(t, http.MethodPost, "/api/v1/principals/"+principal.ID.String()+"/access",
		map[string]any{"items": []map[string]any{{"connection_id": connA.ID, "permission_id": permRO.ID}}},
		&operator, true)
	requireStatus(t, resp, http.StatusConflict)
	resp = env.do(t, http.MethodPost, "/api/v1/principals/"+principal.ID.String()+"/rotate", nil, &operator, true)
	requireStatus(t, resp, http.StatusConflict)
	resp = env.do(t, http.MethodPost, "/api/v1/principals/"+principal.ID.String()+"/share?environment=test", nil, &operator, true)
	requireStatus(t, resp, http.StatusConflict)
	resp = env.do(t, http.MethodPost, "/api/v1/accounts/"+unmanagedAcct.ID.String()+"/link",
		map[string]any{"principal_id": principal.ID}, &operator, true)
	requireStatus(t, resp, http.StatusConflict)
	resp = env.do(t, http.MethodPost, "/api/v1/principals/"+principal.ID.String()+"/disable", nil, &operator, true)
	requireStatus(t, resp, http.StatusConflict)
	resp = env.do(t, http.MethodPost, "/api/v1/principals/"+principal.ID.String()+"/enable", nil, &operator, true)
	requireStatus(t, resp, http.StatusConflict)
}

func TestIntegrationPrincipalOffboardWithoutManagedAccounts(t *testing.T) {
	// Vault не сконфигурирован: без managed-аккаунтов offboard — чистый
	// metadata-only переход в pending_purge (200, без bulk parent),
	// ротировать и отзывать нечего.
	env := newTestEnv(t, nil)
	admin := session(auth.RoleAdmin)
	principal := createPrincipalRow(t, env.pool, "Empty Offboard")

	resp := env.do(t, http.MethodPost,
		"/api/v1/principals/"+principal.ID.String()+"/offboard?confirm=true", nil, &admin, true)
	requireStatus(t, resp, http.StatusOK)
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode offboard response: %v", err)
	}
	if _, has := out["operation_id"]; has {
		t.Errorf("metadata-only offboard has operation_id: %v", out)
	}
	if out["status"] != string(principals.StatusPendingPurge) {
		t.Errorf("status = %v, want pending_purge", out["status"])
	}
	if _, has := out["unmanaged_accounts"]; !has {
		t.Errorf("metadata-only offboard has no unmanaged_accounts field: %v", out)
	}
}

func TestIntegrationPrincipalOffboardMassRevokeGate(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newMassRevokeTestEnv(t, vaultClient, 1)
	operator := session(auth.RoleOperator)
	admin := session(auth.RoleAdmin)

	principal := createPrincipalRow(t, env.pool, "Gated Offboard")
	conn := activeFakeConnectionEnv(t, env.pool, "test")
	permRO := findPermission(t, env.pool, conn.ID, "role:app-readonly")
	permRW := findPermission(t, env.pool, conn.ID, "role:app-readwrite")
	access := grantPrincipalAccessItems(t, env, &operator, principal.ID, "itest_gate_"+uniqueSuffix()[:8],
		[]map[string]any{
			{"connection_id": conn.ID, "permission_id": permRO.ID},
			{"connection_id": conn.ID, "permission_id": permRW.ID},
		})
	finishProvisionChildren(t, env, access.Children)

	// 2 отзыва > порога 1: отзывы создаются в pending_approval и ждут
	// approve-children — существующая семантика mass-revoke gate,
	// переиспользованная offboard'ом.
	//
	// Ротация пароля через этот гейт НЕ проходит сознательно: гейт защищает
	// от массового снятия ПРАВ вторым человеком, а смена пароля прав не
	// снимает — она закрывает вход. Ждать второго админа, оставив человеку
	// рабочий пароль и все его роли, было бы ровно тем, от чего offboard
	// защищает.
	resp := env.do(t, http.MethodPost,
		"/api/v1/principals/"+principal.ID.String()+"/offboard?confirm=true", nil, &admin, true)
	requireStatus(t, resp, http.StatusAccepted)
	var out offboardResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode offboard response: %v", err)
	}
	if len(out.Children) != 3 {
		t.Fatalf("children = %d, want 3 (2 revokes + rotate)", len(out.Children))
	}
	gated, immediate := 0, 0
	for _, child := range out.Children {
		want := operations.StatusPendingApproval
		if child.Kind == jobs.KindCredentialRotate {
			want = operations.StatusPending
			immediate++
		} else {
			gated++
		}
		if child.Status != want {
			t.Errorf("child %s (%s) status = %q, want %q", child.OperationID, child.Kind, child.Status, want)
		}
		requireOperation(t, env, child.OperationID, child.Kind, want, &out.OperationID)
	}
	if gated != 2 || immediate != 1 {
		t.Errorf("children mix = %d gated / %d immediate, want 2/1", gated, immediate)
	}

	// Пока ротация пароля в полёте, restore честно отказывает 409: отменять
	// её нельзя (новая версия уже в Vault, цель обязана до неё доехать), а
	// выдавать права поверх незавершённой смены пароля запрещает lifecycle
	// guard. Здесь worker не запущен — доводим ротацию руками, как это
	// сделал бы он.
	resp = env.do(t, http.MethodPost,
		"/api/v1/principals/"+principal.ID.String()+"/restore", nil, &admin, true)
	requireStatus(t, resp, http.StatusConflict)
	opStore := operations.NewStore()
	for _, child := range out.Children {
		if child.Kind != jobs.KindCredentialRotate {
			continue
		}
		if _, err := opStore.Transition(t.Context(), env.pool, child.OperationID,
			operations.StatusPending, operations.StatusRunning, operations.TransitionOpts{}); err != nil {
			t.Fatalf("start rotate child: %v", err)
		}
		if _, err := opStore.Transition(t.Context(), env.pool, child.OperationID,
			operations.StatusRunning, operations.StatusSuccess, operations.TransitionOpts{}); err != nil {
			t.Fatalf("finish rotate child: %v", err)
		}
	}

	// Отмена вывода обязана отклонить зависшие отзывы: без этого
	// approve-children по старому parent снял бы права уже у активного,
	// восстановленного человека — мина в очереди подтверждений.
	resp = env.do(t, http.MethodPost,
		"/api/v1/principals/"+principal.ID.String()+"/restore", nil, &admin, true)
	requireStatus(t, resp, http.StatusAccepted)
	_ = readBody(t, resp)
	for _, child := range out.Children {
		if child.Kind != jobs.KindAccessRevoke {
			continue
		}
		requireOperation(t, env, child.OperationID, jobs.KindAccessRevoke, operations.StatusCancelled, &out.OperationID)
	}
	// Запоздалый клик по очереди подтверждений теперь идемпотентно пуст:
	// решать нечего, права остаются выданными.
	resp = env.do(t, http.MethodPost,
		"/api/v1/operations/"+out.OperationID.String()+"/approve-children", nil, &admin, true)
	requireStatus(t, resp, http.StatusOK)
	var decided struct {
		Approved []uuid.UUID `json:"approved"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decided); err != nil {
		t.Fatalf("decode approve-children: %v", err)
	}
	if len(decided.Approved) != 0 {
		t.Errorf("late approve-children approved %d children, want 0", len(decided.Approved))
	}
	stored, err := principals.NewStore().Get(t.Context(), env.pool, principal.ID)
	if err != nil {
		t.Fatalf("get principal: %v", err)
	}
	if stored.Status != principals.StatusActive {
		t.Errorf("principal status = %q, want active after restore", stored.Status)
	}
}

// TestIntegrationPrincipalOffboardChildlessParentFinalized: offboard
// принципала, чей единственный managed-аккаунт принят через adopt
// mode=metadata (takeover не разрешён, binding нет), создаёт bulk parent
// без детей — parent обязан финализироваться в success в той же
// транзакции, иначе он остаётся running навсегда: финализацию выполняет
// завершение последнего ребёнка, которого здесь не существует.
func TestIntegrationPrincipalOffboardChildlessParentFinalized(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	operator := session(auth.RoleOperator)
	admin := session(auth.RoleAdmin)

	principal := createPrincipalRow(t, env.pool, "Childless Offboard")
	conn := activeFakeConnectionEnv(t, env.pool, "test")
	acct := findAccount(t, env.pool, conn.ID, "svc-a")

	resp := env.do(t, http.MethodPost, "/api/v1/accounts/"+acct.ID.String()+"/adopt",
		map[string]any{"mode": "metadata"}, &operator, true)
	requireStatus(t, resp, http.StatusOK)
	resp = env.do(t, http.MethodPost, "/api/v1/accounts/"+acct.ID.String()+"/link",
		map[string]any{"principal_id": principal.ID}, &operator, true)
	requireStatus(t, resp, http.StatusOK)

	resp = env.do(t, http.MethodPost,
		"/api/v1/principals/"+principal.ID.String()+"/offboard",
		map[string]any{"confirm": true}, &admin, true)
	requireStatus(t, resp, http.StatusAccepted)
	var out offboardResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode offboard response: %v", err)
	}
	if len(out.Children) != 0 {
		t.Fatalf("offboard children = %d, want 0: %+v", len(out.Children), out.Children)
	}
	if len(out.CredentialTakeoverRequired) != 1 {
		t.Fatalf("credential_takeover_required = %+v, want the adopted account",
			out.CredentialTakeoverRequired)
	}
	requireOperation(t, env, out.OperationID, jobs.KindBulkPrincipalOffboard,
		operations.StatusSuccess, nil)
}
