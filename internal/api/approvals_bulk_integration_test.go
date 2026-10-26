//go:build integration

// Integration-тесты batch-решений approval workflow (расширение ADR-0010):
// POST /api/v1/operations/{id}/approve-children и /reject-children решают все
// pending_approval дочерние операции parent одним действием. Семантика по
// каждому ребёнку — ровно как у одиночного approve/reject: тот же guarded
// UPDATE, то же audit-событие с self_approved по requester каждого ребёнка;
// self-approval разрешён (confirmation gate, не four-eyes). Worker здесь не
// запускается (insert-only dispatcher): «dispatch» проверяется как переход
// ребёнка в pending; полный цикл «approve → выполнение» — на уровне
// диспетчера (internal/jobs/river_integration_test.go).
package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/operations"
)

// childrenDecisionOut — распарсенный ответ approve-children/reject-children.
type childrenDecisionOut struct {
	OperationID uuid.UUID   `json:"operation_id"`
	Approved    []uuid.UUID `json:"approved"`
	Rejected    []uuid.UUID `json:"rejected"`
	Skipped     []struct {
		ID     uuid.UUID `json:"id"`
		Status string    `json:"status"`
	} `json:"skipped"`
}

// requestDangerousBulkGrant ставит bulk из двух опасных грантов (svc-a и
// readers × superuser) от имени requester и возвращает id parent и детей.
func requestDangerousBulkGrant(t *testing.T, env *testEnv, requester auth.Session) (uuid.UUID, []uuid.UUID) {
	t.Helper()
	conn := activeFakeConnection(t, env.pool)
	dangerous := findPermission(t, env.pool, conn.ID, "role:superuser")
	svcA := findAccount(t, env.pool, conn.ID, "svc-a")
	readers := findAccount(t, env.pool, conn.ID, "readers")

	body := map[string]any{
		"items": []map[string]any{
			{"account_id": svcA.ID, "permission_id": dangerous.ID},
			{"account_id": readers.ID, "permission_id": dangerous.ID},
		},
		"confirm": true,
	}
	resp := env.do(t, http.MethodPost, "/api/v1/bindings/bulk", body, &requester, true)
	requireStatus(t, resp, http.StatusAccepted)
	var out struct {
		OperationID uuid.UUID `json:"operation_id"`
		Children    []struct {
			OperationID uuid.UUID         `json:"operation_id"`
			Status      operations.Status `json:"status"`
		} `json:"children"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode bulk grant response: %v", err)
	}
	if len(out.Children) != 2 {
		t.Fatalf("bulk children = %d, want 2", len(out.Children))
	}
	childIDs := make([]uuid.UUID, 0, len(out.Children))
	for _, c := range out.Children {
		if c.Status != operations.StatusPendingApproval {
			t.Fatalf("bulk child status = %q, want pending_approval", c.Status)
		}
		childIDs = append(childIDs, c.OperationID)
	}
	return out.OperationID, childIDs
}

// decideChildren вызывает approve-children/reject-children и возвращает
// распарсенный ответ.
func decideChildren(t *testing.T, env *testEnv, parentID uuid.UUID, action string, reason string, sess *auth.Session) childrenDecisionOut {
	t.Helper()
	var body map[string]any
	if reason != "" {
		body = map[string]any{"reason": reason}
	}
	resp := env.do(t, http.MethodPost, "/api/v1/operations/"+parentID.String()+"/"+action, body, sess, true)
	requireStatus(t, resp, http.StatusOK)
	var out childrenDecisionOut
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode %s response: %v", action, err)
	}
	return out
}

// containsID сообщает, есть ли id среди элементов списка.
func containsID(ids []uuid.UUID, id uuid.UUID) bool {
	for i := range ids {
		if ids[i] == id {
			return true
		}
	}
	return false
}

// TestIntegrationApproveChildrenSelfApprove — штатный путь: admin ставит bulk
// опасных грантов и сам же подтверждает всю пачку одним действием.
// Self-approval разрешён; audit каждого ребёнка помечен self_approved=true.
func TestIntegrationApproveChildrenSelfApprove(t *testing.T) {
	env := newApprovalTestEnv(t)
	admin := adminSession("admin-a@grantor.dev")
	operator := session(auth.RoleOperator)

	parentID, childIDs := requestDangerousBulkGrant(t, env, admin)

	// RBAC: batch-решение — только admin.
	resp := env.do(t, http.MethodPost, "/api/v1/operations/"+parentID.String()+"/approve-children", nil, &operator, true)
	requireStatus(t, resp, http.StatusForbidden)

	out := decideChildren(t, env, parentID, "approve-children", "batch confirmed", &admin)
	if out.OperationID != parentID {
		t.Errorf("operation_id = %s, want parent %s", out.OperationID, parentID)
	}
	if len(out.Approved) != 2 || len(out.Skipped) != 0 {
		t.Fatalf("approved/skipped = %d/%d, want 2/0", len(out.Approved), len(out.Skipped))
	}

	opStore := operations.NewStore()
	for _, childID := range childIDs {
		if !containsID(out.Approved, childID) {
			t.Errorf("child %s not in approved list", childID)
		}
		child, err := opStore.Get(t.Context(), env.pool, childID)
		if err != nil {
			t.Fatalf("get child %s: %v", childID, err)
		}
		if child.Status != operations.StatusPending {
			t.Errorf("child %s status = %q, want pending (dispatched)", childID, child.Status)
		}
		if child.ApprovedBy == nil || *child.ApprovedBy != "admin-a@grantor.dev" {
			t.Errorf("child %s approved_by = %v, want admin-a@grantor.dev", childID, child.ApprovedBy)
		}
		if child.DecisionReason != "batch confirmed" {
			t.Errorf("child %s decision_reason = %q", childID, child.DecisionReason)
		}
		// Audit по каждому ребёнку — как у одиночного approve; requester и
		// approver совпадают → self_approved=true.
		requireApprovalAudit(t, env, childID, "operation.approved", "admin-a@grantor.dev", true)
	}

	// Идемпотентность: повторный batch по уже решённому parent — 200 с пустым
	// approved, дети отражены в skipped со статусом pending (диспатчены).
	again := decideChildren(t, env, parentID, "approve-children", "", &admin)
	if len(again.Approved) != 0 || len(again.Skipped) != 2 {
		t.Fatalf("repeat approved/skipped = %d/%d, want 0/2", len(again.Approved), len(again.Skipped))
	}
	for _, sk := range again.Skipped {
		if sk.Status != string(operations.StatusPending) {
			t.Errorf("skipped %s status = %q, want pending", sk.ID, sk.Status)
		}
	}

	// reject-children по уже диспатченным детям — не ошибка (в отличие от
	// одиночного reject c 409): batch отражает их в skipped и ничего не меняет.
	rej := decideChildren(t, env, parentID, "reject-children", "", &admin)
	if len(rej.Rejected) != 0 || len(rej.Skipped) != 2 {
		t.Errorf("reject after approve: rejected/skipped = %d/%d, want 0/2", len(rej.Rejected), len(rej.Skipped))
	}
}

// TestIntegrationApproveChildrenByDifferentAdmin — пачку подтверждает не тот
// admin, что запросил: audit каждого ребёнка несёт self_approved=false.
func TestIntegrationApproveChildrenByDifferentAdmin(t *testing.T) {
	env := newApprovalTestEnv(t)
	requester := adminSession("admin-a@grantor.dev")
	approver := adminSession("admin-b@grantor.dev")

	parentID, childIDs := requestDangerousBulkGrant(t, env, requester)

	out := decideChildren(t, env, parentID, "approve-children", "reviewed by another admin", &approver)
	if len(out.Approved) != 2 {
		t.Fatalf("approved = %d, want 2", len(out.Approved))
	}
	opStore := operations.NewStore()
	for _, childID := range childIDs {
		child, err := opStore.Get(t.Context(), env.pool, childID)
		if err != nil {
			t.Fatalf("get child %s: %v", childID, err)
		}
		if child.ApprovedBy == nil || *child.ApprovedBy != "admin-b@grantor.dev" {
			t.Errorf("child %s approved_by = %v, want admin-b@grantor.dev", childID, child.ApprovedBy)
		}
		requireApprovalAudit(t, env, childID, "operation.approved", "admin-b@grantor.dev", false)
	}
}

// TestIntegrationApproveChildrenMixedStatuses — parent со смешанными детьми:
// опасный грант ждёт approve, безопасный уже диспатчен. Batch подтверждает
// только ожидающих, диспатченный отражается в skipped, а не в ошибке.
func TestIntegrationApproveChildrenMixedStatuses(t *testing.T) {
	env := newApprovalTestEnv(t)
	admin := adminSession("admin-a@grantor.dev")

	conn := activeFakeConnection(t, env.pool)
	svcA := findAccount(t, env.pool, conn.ID, "svc-a")
	dangerous := findPermission(t, env.pool, conn.ID, "role:superuser")
	safe := findPermission(t, env.pool, conn.ID, "role:app-readonly")

	body := map[string]any{
		"items": []map[string]any{
			{"account_id": svcA.ID, "permission_id": dangerous.ID},
			{"account_id": svcA.ID, "permission_id": safe.ID},
		},
		"confirm": true,
	}
	resp := env.do(t, http.MethodPost, "/api/v1/bindings/bulk", body, &admin, true)
	requireStatus(t, resp, http.StatusAccepted)
	var bulk struct {
		OperationID uuid.UUID `json:"operation_id"`
		Children    []struct {
			OperationID  uuid.UUID         `json:"operation_id"`
			PermissionID uuid.UUID         `json:"permission_id"`
			Status       operations.Status `json:"status"`
		} `json:"children"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&bulk); err != nil {
		t.Fatalf("decode bulk response: %v", err)
	}
	var gatedID, dispatchedID uuid.UUID
	for _, c := range bulk.Children {
		switch c.Status {
		case operations.StatusPendingApproval:
			gatedID = c.OperationID
		case operations.StatusPending:
			dispatchedID = c.OperationID
		default:
			t.Fatalf("unexpected child status %q", c.Status)
		}
	}
	if gatedID == uuid.Nil || dispatchedID == uuid.Nil {
		t.Fatalf("want one pending_approval and one pending child, got %+v", bulk.Children)
	}

	out := decideChildren(t, env, bulk.OperationID, "approve-children", "", &admin)
	if len(out.Approved) != 1 || out.Approved[0] != gatedID {
		t.Errorf("approved = %v, want [%s]", out.Approved, gatedID)
	}
	if len(out.Skipped) != 1 || out.Skipped[0].ID != dispatchedID ||
		out.Skipped[0].Status != string(operations.StatusPending) {
		t.Errorf("skipped = %+v, want [{%s pending}]", out.Skipped, dispatchedID)
	}
}

// TestIntegrationRejectChildrenTerminal — reject-children переводит всех
// ожидающих детей в терминальный cancelled: они никогда не выполнятся.
func TestIntegrationRejectChildrenTerminal(t *testing.T) {
	env := newApprovalTestEnv(t)
	requester := adminSession("admin-a@grantor.dev")
	approver := adminSession("admin-b@grantor.dev")

	parentID, childIDs := requestDangerousBulkGrant(t, env, requester)

	out := decideChildren(t, env, parentID, "reject-children", "mass request denied", &approver)
	if len(out.Rejected) != 2 || len(out.Skipped) != 0 {
		t.Fatalf("rejected/skipped = %d/%d, want 2/0", len(out.Rejected), len(out.Skipped))
	}

	opStore := operations.NewStore()
	for _, childID := range childIDs {
		child, err := opStore.Get(t.Context(), env.pool, childID)
		if err != nil {
			t.Fatalf("get child %s: %v", childID, err)
		}
		if child.Status != operations.StatusCancelled || !child.Status.IsTerminal() {
			t.Errorf("child %s status = %q, want terminal cancelled", childID, child.Status)
		}
		if child.FinishedAt == nil {
			t.Errorf("child %s finished_at nil after reject", childID)
		}
		if child.DecisionReason != "mass request denied" {
			t.Errorf("child %s decision_reason = %q", childID, child.DecisionReason)
		}
		requireApprovalAudit(t, env, childID, "operation.rejected", "admin-b@grantor.dev", false)
	}

	// Идемпотентность повторного reject-children и approve-children по уже
	// отклонённым детям: пустой результат, дети в skipped со статусом cancelled.
	again := decideChildren(t, env, parentID, "reject-children", "", &approver)
	if len(again.Rejected) != 0 || len(again.Skipped) != 2 {
		t.Errorf("repeat rejected/skipped = %d/%d, want 0/2", len(again.Rejected), len(again.Skipped))
	}
	appr := decideChildren(t, env, parentID, "approve-children", "", &approver)
	if len(appr.Approved) != 0 || len(appr.Skipped) != 2 {
		t.Errorf("approve after reject: approved/skipped = %d/%d, want 0/2", len(appr.Approved), len(appr.Skipped))
	}
	for _, sk := range appr.Skipped {
		if sk.Status != string(operations.StatusCancelled) {
			t.Errorf("skipped %s status = %q, want cancelled", sk.ID, sk.Status)
		}
	}
}

// TestIntegrationDecideChildrenNoPending — операция без ожидающих детей:
// batch отвечает 200 с пустым результатом (идемпотентно), несуществующий
// parent — 404.
func TestIntegrationDecideChildrenNoPending(t *testing.T) {
	env := newApprovalTestEnv(t)
	admin := adminSession("admin-a@grantor.dev")

	// Одиночный опасный грант — операция без детей.
	conn := activeFakeConnection(t, env.pool)
	acct := findAccount(t, env.pool, conn.ID, "svc-a")
	dangerous := findPermission(t, env.pool, conn.ID, "role:superuser")
	opID := requestDangerousGrant(t, env, admin, acct.ID, dangerous.ID)

	out := decideChildren(t, env, opID, "approve-children", "", &admin)
	if len(out.Approved) != 0 || len(out.Skipped) != 0 {
		t.Errorf("no-children batch approved/skipped = %d/%d, want 0/0", len(out.Approved), len(out.Skipped))
	}
	// Сама операция batch'ем по детям не решается: она осталась ожидающей.
	op, err := operations.NewStore().Get(t.Context(), env.pool, opID)
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if op.Status != operations.StatusPendingApproval {
		t.Errorf("operation status = %q, want pending_approval (untouched)", op.Status)
	}

	resp := env.do(t, http.MethodPost, "/api/v1/operations/"+uuid.NewString()+"/approve-children", nil, &admin, true)
	requireStatus(t, resp, http.StatusNotFound)
}
