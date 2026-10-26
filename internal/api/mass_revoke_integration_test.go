//go:build integration

// Integration-тесты mass-revoke gate (расширение ADR-0010,
// GRANTOR_APPROVAL_MASS_REVOKE_THRESHOLD): применение манифеста, отзывающее
// БОЛЬШЕ threshold bindings, создаёт все свои revoke-операции в
// pending_approval — массовый offboarding не выполняется без явного approve.
// Порог работает НЕЗАВИСИМО от GRANTOR_APPROVAL_REQUIRED (в этих тестах
// основной флаг выключен). Worker не запускается (insert-only dispatcher):
// «не выполняется до approve» проверяется как статус pending_approval (worker
// снузит такой job — internal/jobs/river_integration_test.go), «диспатч» —
// как pending.
package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
)

// massRevokeManifest собирает манифест с двумя безопасными ролями fake
// adapter в заданном состоянии (present/absent).
func massRevokeManifest(mfEnv, subject, connection, state string) map[string]any {
	entries := []map[string]any{}
	for _, role := range []string{"role:app-readonly", "role:app-readwrite"} {
		entries = append(entries, map[string]any{
			"principal": subject, "connection": connection, "role": role, "state": state,
		})
	}
	return map[string]any{"version": "v1", "environment": mfEnv, "entries": entries}
}

// manifestApplyOut — распарсенный ответ POST /api/v1/access/apply.
type manifestApplyOut struct {
	OperationID uuid.UUID `json:"operation_id"`
	Children    []struct {
		Kind                     string            `json:"kind"`
		AccountCreateOperationID *uuid.UUID        `json:"account_create_operation_id"`
		RevokeOperationID        *uuid.UUID        `json:"revoke_operation_id"`
		BindingID                *uuid.UUID        `json:"binding_id"`
		Status                   operations.Status `json:"status"`
	} `json:"children"`
}

// applyManifest применяет манифест и возвращает распарсенный ответ.
func applyManifest(t *testing.T, env *testEnv, sess *auth.Session, manifest map[string]any) manifestApplyOut {
	t.Helper()
	resp := env.do(t, http.MethodPost, "/api/v1/access/apply", manifest, sess, true)
	requireStatus(t, resp, http.StatusAccepted)
	var out manifestApplyOut
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode apply response: %v", err)
	}
	return out
}

// seedManifestGrants применяет present-манифест с двумя ролями и возвращает
// subject и display_name подключения для последующего absent-применения.
func seedManifestGrants(t *testing.T, env *testEnv, operator *auth.Session) (mfEnv, subject, connection string) {
	t.Helper()
	sfx := uniqueSuffix()
	mfEnv = "mrenv-" + sfx
	conn := activeFakeConnectionEnv(t, env.pool, mfEnv)
	principal := createPrincipalWithSubject(t, env.pool, "mrsub-"+sfx)

	out := applyManifest(t, env, operator, massRevokeManifest(mfEnv, principal.ExternalSubject, conn.DisplayName, "present"))
	if len(out.Children) != 2 {
		t.Fatalf("present apply children = %d, want 2", len(out.Children))
	}
	// GRANTOR_APPROVAL_REQUIRED в этих окружениях выключен: гранты (безопасные
	// роли) диспатчатся сразу — mass-revoke порог грантов не касается.
	for _, c := range out.Children {
		if c.Status != operations.StatusPending {
			t.Fatalf("grant child status = %q, want pending", c.Status)
		}
		if c.AccountCreateOperationID != nil {
			store := operations.NewStore()
			if _, err := store.Transition(t.Context(), env.pool, *c.AccountCreateOperationID,
				operations.StatusPending, operations.StatusRunning, operations.TransitionOpts{}); err != nil {
				t.Fatalf("start manifest account.create: %v", err)
			}
			if _, err := store.Transition(t.Context(), env.pool, *c.AccountCreateOperationID,
				operations.StatusRunning, operations.StatusSuccess, operations.TransitionOpts{}); err != nil {
				t.Fatalf("finish manifest account.create: %v", err)
			}
		}
	}
	return mfEnv, principal.ExternalSubject, conn.DisplayName
}

// requireRevokeStatuses проверяет, что все revoke-children применения имеют
// ожидаемые статусы в ответе и в базе, и возвращает их id.
func requireRevokeStatuses(t *testing.T, env *testEnv, out manifestApplyOut, want operations.Status) []uuid.UUID {
	t.Helper()
	if len(out.Children) != 2 {
		t.Fatalf("revoke apply children = %d, want 2", len(out.Children))
	}
	opStore := operations.NewStore()
	ids := make([]uuid.UUID, 0, len(out.Children))
	for _, c := range out.Children {
		if c.Kind != "revoke" || c.RevokeOperationID == nil {
			t.Fatalf("child = %+v, want revoke with operation id", c)
		}
		if c.Status != want {
			t.Errorf("revoke child %s response status = %q, want %q", *c.RevokeOperationID, c.Status, want)
		}
		op, err := opStore.Get(t.Context(), env.pool, *c.RevokeOperationID)
		if err != nil {
			t.Fatalf("get revoke operation: %v", err)
		}
		if op.Status != want {
			t.Errorf("revoke operation %s status = %q, want %q", op.ID, op.Status, want)
		}
		ids = append(ids, *c.RevokeOperationID)
	}
	return ids
}

// TestIntegrationMassRevokeOverThresholdGated — применение, отзывающее больше
// порога bindings (2 > 1), создаёт revoke-операции в pending_approval; они не
// выполняются, пока admin не подтвердит пачку approve-children.
func TestIntegrationMassRevokeOverThresholdGated(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newMassRevokeTestEnv(t, vaultClient, 1)
	operator := session(auth.RoleOperator)
	admin := adminSession("admin-a@grantor.dev")

	mfEnv, subject, connection := seedManifestGrants(t, env, &operator)

	out := applyManifest(t, env, &operator, massRevokeManifest(mfEnv, subject, connection, "absent"))
	revokeIDs := requireRevokeStatuses(t, env, out, operations.StatusPendingApproval)

	// Ожидающие ревоки видны в списке подтверждений.
	resp := env.do(t, http.MethodGet, "/api/v1/approvals", nil, &admin, false)
	requireStatus(t, resp, http.StatusOK)
	var list struct {
		Operations []struct {
			ID     uuid.UUID `json:"id"`
			Status string    `json:"status"`
		} `json:"operations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatalf("decode approvals list: %v", err)
	}
	for _, id := range revokeIDs {
		if !containsOp(list.Operations, id) {
			t.Errorf("gated revoke %s not present in approvals list", id)
		}
	}

	// Approve всей пачки одним действием: ревоки переходят в pending и будут
	// подхвачены уже поставленными jobs. Audit каждого ребёнка несёт
	// self_approved=false (запрашивал operator, подтверждает admin).
	decided := decideChildren(t, env, out.OperationID, "approve-children", "offboarding reviewed", &admin)
	if len(decided.Approved) != 2 {
		t.Fatalf("approved = %d, want 2", len(decided.Approved))
	}
	opStore := operations.NewStore()
	for _, id := range revokeIDs {
		op, err := opStore.Get(t.Context(), env.pool, id)
		if err != nil {
			t.Fatalf("get revoke operation after approve: %v", err)
		}
		if op.Status != operations.StatusPending {
			t.Errorf("revoke %s status after approve = %q, want pending (dispatched)", id, op.Status)
		}
		requireApprovalAudit(t, env, id, "operation.approved", "admin-a@grantor.dev", false)
	}
}

// TestIntegrationMassRevokeRejectRestoresDesired — reject пачки гейтованных
// ревоков возвращает их bindings в desired present: постановка отзыва
// переводит binding в absent ещё до approve, и без отката отказ admin
// оставлял binding в вечном drift, а повторное применение того же манифеста
// видело «уже отозвано» и mass-revoke gate больше не срабатывал.
func TestIntegrationMassRevokeRejectRestoresDesired(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newMassRevokeTestEnv(t, vaultClient, 1)
	operator := session(auth.RoleOperator)
	admin := adminSession("admin-a@grantor.dev")

	mfEnv, subject, connection := seedManifestGrants(t, env, &operator)
	out := applyManifest(t, env, &operator, massRevokeManifest(mfEnv, subject, connection, "absent"))
	requireRevokeStatuses(t, env, out, operations.StatusPendingApproval)

	decided := decideChildren(t, env, out.OperationID, "reject-children", "not today", &admin)
	if len(decided.Rejected) != 2 {
		t.Fatalf("rejected = %d, want 2", len(decided.Rejected))
	}

	invStore := inventory.NewStore()
	for _, c := range out.Children {
		if c.BindingID == nil {
			t.Fatalf("revoke child without binding_id: %+v", c)
		}
		b, err := invStore.GetBinding(t.Context(), env.pool, *c.BindingID)
		if err != nil {
			t.Fatalf("get binding after reject: %v", err)
		}
		if b.DesiredState == nil || *b.DesiredState != inventory.BindingPresent {
			t.Errorf("binding %s desired after reject = %v, want present", b.ID, b.DesiredState)
		}
	}

	// Повторное применение того же манифеста снова гейтуется целиком.
	again := applyManifest(t, env, &operator, massRevokeManifest(mfEnv, subject, connection, "absent"))
	requireRevokeStatuses(t, env, again, operations.StatusPendingApproval)
}

// TestIntegrationMassRevokeUnderThresholdDispatches — применение, отзывающее
// не больше порога bindings (2 <= 2), под gate не попадает: ревоки
// диспатчатся сразу, как раньше (малый отзыв — безопасное направление).
func TestIntegrationMassRevokeUnderThresholdDispatches(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newMassRevokeTestEnv(t, vaultClient, 2)
	operator := session(auth.RoleOperator)

	mfEnv, subject, connection := seedManifestGrants(t, env, &operator)
	out := applyManifest(t, env, &operator, massRevokeManifest(mfEnv, subject, connection, "absent"))
	requireRevokeStatuses(t, env, out, operations.StatusPending)
}

// TestIntegrationMassRevokeThresholdDisabled — дефолтный порог 0 полностью
// выключает gate: любые массовые ревоки диспатчатся сразу
// (обратная совместимость, как и другие approval-флаги).
func TestIntegrationMassRevokeThresholdDisabled(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	operator := session(auth.RoleOperator)

	mfEnv, subject, connection := seedManifestGrants(t, env, &operator)
	out := applyManifest(t, env, &operator, massRevokeManifest(mfEnv, subject, connection, "absent"))
	requireRevokeStatuses(t, env, out, operations.StatusPending)
}
