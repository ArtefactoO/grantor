//go:build integration

// Integration-тесты approval workflow (ADR-0010): опасный грант при включённом
// gate создаётся в pending_approval и не диспатчится, пока admin явно его не
// подтвердит. Это confirmation gate, а НЕ four-eyes: тот же admin, что запросил,
// может подтвердить свой запрос (self-approval — штатный случай, фиксируется в
// audit флагом self_approved). Полный loop «approve → выполнение» проверяется на
// уровне диспетчера (internal/jobs/river_integration_test.go); здесь API-сервер
// собран с insert-only dispatcher (без worker), поэтому «dispatch» проверяется
// как переход операции в pending.
package api_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
)

// adminSession возвращает admin-сессию с заданным email (для сценариев с
// несколькими admin).
func adminSession(email string) auth.Session {
	return auth.Session{
		Subject:   "sub-" + email,
		Email:     email,
		Role:      auth.RoleAdmin,
		ExpiresAt: time.Now().Add(time.Hour),
	}
}

// requestDangerousGrant запрашивает опасный грант от имени requester и
// возвращает id созданной операции. Ожидается 202.
func requestDangerousGrant(t *testing.T, env *testEnv, requester auth.Session, acctID, permID uuid.UUID) uuid.UUID {
	t.Helper()
	body := map[string]any{"account_id": acctID, "permission_id": permID, "confirm": true}
	resp := env.do(t, http.MethodPost, "/api/v1/bindings", body, &requester, true)
	requireStatus(t, resp, http.StatusAccepted)
	var out struct {
		OperationID uuid.UUID `json:"operation_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode grant response: %v", err)
	}
	return out.OperationID
}

// TestIntegrationApprovalSelfApprove проверяет штатный путь: admin запрашивает
// опасный грант и сам же его подтверждает (self-approval разрешён), а audit
// явно помечает self_approved=true.
func TestIntegrationApprovalSelfApprove(t *testing.T) {
	env := newApprovalTestEnv(t)
	admin := adminSession("admin-a@grantor.dev")
	operator := session(auth.RoleOperator)

	conn := activeFakeConnection(t, env.pool)
	acct := findAccount(t, env.pool, conn.ID, "svc-a")
	dangerous := findPermission(t, env.pool, conn.ID, "role:superuser")

	opID := requestDangerousGrant(t, env, admin, acct.ID, dangerous.ID)

	// Операция ждёт подтверждения, не диспатчится.
	opStore := operations.NewStore()
	op, err := opStore.Get(t.Context(), env.pool, opID)
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if op.Status != operations.StatusPendingApproval {
		t.Fatalf("status = %q, want pending_approval", op.Status)
	}

	// Список ожидающих: admin видит операцию, operator — 403.
	resp := env.do(t, http.MethodGet, "/api/v1/approvals", nil, &operator, false)
	requireStatus(t, resp, http.StatusForbidden)
	resp = env.do(t, http.MethodGet, "/api/v1/approvals", nil, &admin, false)
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
	if !containsOp(list.Operations, opID) {
		t.Error("pending operation not present in approvals list")
	}

	// Self-approval РАЗРЕШЁН: запросивший admin подтверждает свою же операцию.
	resp = env.do(t, http.MethodPost, "/api/v1/operations/"+opID.String()+"/approve",
		map[string]any{"reason": "confirmed by requester"}, &admin, true)
	requireStatus(t, resp, http.StatusOK)
	op, err = opStore.Get(t.Context(), env.pool, opID)
	if err != nil {
		t.Fatalf("get operation after approve: %v", err)
	}
	if op.Status != operations.StatusPending {
		t.Errorf("status after approve = %q, want pending (dispatched)", op.Status)
	}
	if op.ApprovedBy == nil || *op.ApprovedBy != "admin-a@grantor.dev" {
		t.Errorf("approved_by = %v, want admin-a@grantor.dev", op.ApprovedBy)
	}
	if op.DecisionReason != "confirmed by requester" {
		t.Errorf("decision_reason = %q", op.DecisionReason)
	}

	// Audit operation.approved помечен self_approved=true и несёт актора.
	requireApprovalAudit(t, env, opID, "operation.approved", "admin-a@grantor.dev", true)

	// Идемпотентность: повторный approve уже подтверждённой (ещё не
	// выполненной) операции — no-op 200.
	resp = env.do(t, http.MethodPost, "/api/v1/operations/"+opID.String()+"/approve", nil, &admin, true)
	requireStatus(t, resp, http.StatusOK)

	// Reject уже подтверждённой операции — 409 conflict.
	resp = env.do(t, http.MethodPost, "/api/v1/operations/"+opID.String()+"/reject", nil, &admin, true)
	requireStatus(t, resp, http.StatusConflict)
}

// TestIntegrationApprovalByDifferentAdmin проверяет допустимый (но не
// обязательный) случай: подтверждает не тот admin, что запросил, — audit несёт
// self_approved=false.
func TestIntegrationApprovalByDifferentAdmin(t *testing.T) {
	env := newApprovalTestEnv(t)
	requester := adminSession("admin-a@grantor.dev")
	approver := adminSession("admin-b@grantor.dev")

	conn := activeFakeConnection(t, env.pool)
	acct := findAccount(t, env.pool, conn.ID, "svc-a")
	dangerous := findPermission(t, env.pool, conn.ID, "role:superuser")

	opID := requestDangerousGrant(t, env, requester, acct.ID, dangerous.ID)

	resp := env.do(t, http.MethodPost, "/api/v1/operations/"+opID.String()+"/approve",
		map[string]any{"reason": "reviewed by another admin"}, &approver, true)
	requireStatus(t, resp, http.StatusOK)

	op, err := operations.NewStore().Get(t.Context(), env.pool, opID)
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if op.Status != operations.StatusPending {
		t.Errorf("status = %q, want pending", op.Status)
	}
	if op.ApprovedBy == nil || *op.ApprovedBy != "admin-b@grantor.dev" {
		t.Errorf("approved_by = %v, want admin-b@grantor.dev", op.ApprovedBy)
	}
	requireApprovalAudit(t, env, opID, "operation.approved", "admin-b@grantor.dev", false)
}

func TestIntegrationApprovalReject(t *testing.T) {
	env := newApprovalTestEnv(t)
	requester := adminSession("admin-a@grantor.dev")

	conn := activeFakeConnection(t, env.pool)
	acct := findAccount(t, env.pool, conn.ID, "svc-a")
	dangerous := findPermission(t, env.pool, conn.ID, "role:superuser")

	opID := requestDangerousGrant(t, env, requester, acct.ID, dangerous.ID)

	// Reject: операция терминально cancelled.
	resp := env.do(t, http.MethodPost, "/api/v1/operations/"+opID.String()+"/reject",
		map[string]any{"reason": "not permitted"}, &requester, true)
	requireStatus(t, resp, http.StatusOK)

	op, err := operations.NewStore().Get(t.Context(), env.pool, opID)
	if err != nil {
		t.Fatalf("get operation after reject: %v", err)
	}
	if op.Status != operations.StatusCancelled {
		t.Errorf("status = %q, want cancelled", op.Status)
	}
	if !op.Status.IsTerminal() {
		t.Error("rejected operation must be terminal")
	}
	if op.DecisionReason != "not permitted" {
		t.Errorf("decision_reason = %q, want %q", op.DecisionReason, "not permitted")
	}
	if op.FinishedAt == nil {
		t.Error("finished_at nil after reject")
	}

	// Audit operation.rejected записан.
	requireApprovalAudit(t, env, opID, "operation.rejected", "admin-a@grantor.dev", true)

	// Approve уже отклонённой операции — 409 conflict.
	resp = env.do(t, http.MethodPost, "/api/v1/operations/"+opID.String()+"/approve", nil, &requester, true)
	requireStatus(t, resp, http.StatusConflict)

	// Повторный reject — идемпотентный no-op 200.
	resp = env.do(t, http.MethodPost, "/api/v1/operations/"+opID.String()+"/reject", nil, &requester, true)
	requireStatus(t, resp, http.StatusOK)
}

func TestIntegrationApprovalDisabledDispatchesDirectly(t *testing.T) {
	// Без gate (дефолт) опасный грант ставится сразу в pending, как раньше.
	env := newTestEnv(t, nil)
	admin := session(auth.RoleAdmin)
	conn := activeFakeConnection(t, env.pool)
	acct := findAccount(t, env.pool, conn.ID, "svc-a")
	dangerous := findPermission(t, env.pool, conn.ID, "role:superuser")

	opID := requestDangerousGrant(t, env, admin, acct.ID, dangerous.ID)
	op, err := operations.NewStore().Get(t.Context(), env.pool, opID)
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if op.Status != operations.StatusPending {
		t.Errorf("status = %q, want pending (approval gate disabled)", op.Status)
	}
}

// containsOp сообщает, есть ли операция с id среди элементов списка approvals.
func containsOp(ops []struct {
	ID     uuid.UUID `json:"id"`
	Status string    `json:"status"`
}, id uuid.UUID) bool {
	for i := range ops {
		if ops[i].ID == id {
			return true
		}
	}
	return false
}

// requireApprovalAudit проверяет, что записано audit-событие action по операции
// opID с актором actorID и корректной отметкой self_approved.
func requireApprovalAudit(t *testing.T, env *testEnv, opID uuid.UUID, action, actorID string, wantSelf bool) {
	t.Helper()
	events, err := audit.NewWriter().List(t.Context(), env.pool, audit.Filter{
		OperationID: &opID,
		Actions:      []string{action},
	}, 10, 0)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	for i := range events {
		if events[i].ActorID != actorID {
			continue
		}
		var meta struct {
			SelfApproved bool `json:"self_approved"`
		}
		if err := json.Unmarshal(events[i].Metadata, &meta); err != nil {
			t.Fatalf("unmarshal audit metadata: %v", err)
		}
		if meta.SelfApproved != wantSelf {
			t.Errorf("%s self_approved = %v, want %v", action, meta.SelfApproved, wantSelf)
		}
		return
	}
	t.Errorf("no %s audit event for operation %s by %s (got %d events)", action, opID, actorID, len(events))
}

// TestIntegrationApprovalRejectRestoresBinding: отказ по опасной выдаче
// возвращает binding туда, где он был.
//
// Постановка выдачи переводит binding в desired present ещё до approve,
// поэтому без отката отклонённое право продолжало числиться желаемым и
// показывалось вечным drift'ом. Строку, которую создала сама выдача и до
// которой на цели ничего не дошло, откат удаляет: несуществующее право не
// должно висеть в инвентаре ни в каком виде.
func TestIntegrationApprovalRejectRestoresBinding(t *testing.T) {
	env := newApprovalTestEnv(t)
	admin := adminSession("admin-a@grantor.dev")
	invStore := inventory.NewStore()

	conn := activeFakeConnection(t, env.pool)
	acct := findAccount(t, env.pool, conn.ID, "svc-a")
	dangerous := findPermission(t, env.pool, conn.ID, "role:superuser")

	// Свежая выдача: строки binding до неё не было.
	opID := requestDangerousGrant(t, env, admin, acct.ID, dangerous.ID)
	op, err := operations.NewStore().Get(t.Context(), env.pool, opID)
	if err != nil {
		t.Fatalf("get grant operation: %v", err)
	}
	if op.BindingID == nil {
		t.Fatal("grant operation has no binding")
	}
	bindingID := *op.BindingID

	resp := env.do(t, http.MethodPost, "/api/v1/operations/"+opID.String()+"/reject", nil, &admin, true)
	requireStatus(t, resp, http.StatusOK)

	if _, err := invStore.GetBinding(t.Context(), env.pool, bindingID); !errors.Is(err, inventory.ErrNotFound) {
		t.Fatalf("binding after rejecting its own grant: err = %v, want ErrNotFound", err)
	}

	// Повторная выдача того же права и повторный отказ: gate снова
	// срабатывает, значит состояние действительно вернулось.
	secondID := requestDangerousGrant(t, env, admin, acct.ID, dangerous.ID)
	second, err := operations.NewStore().Get(t.Context(), env.pool, secondID)
	if err != nil {
		t.Fatalf("get second grant operation: %v", err)
	}
	if second.Status != operations.StatusPendingApproval {
		t.Fatalf("second grant status = %q, want pending_approval", second.Status)
	}
}
