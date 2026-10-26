package api

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/core/approval"
	"github.com/ArtefactoO/grantor/internal/core/operations"
)

// TestPartitionApprovalChildren проверяет формирование batch-решения: в
// pending попадают только дети в pending_approval, остальные — в skipped с
// текущим статусом (уже решённые/диспатченные — не ошибка).
func TestPartitionApprovalChildren(t *testing.T) {
	mk := func(st operations.Status) operations.Operation {
		return operations.Operation{ID: uuid.New(), Status: st}
	}
	waiting1 := mk(operations.StatusPendingApproval)
	waiting2 := mk(operations.StatusPendingApproval)
	dispatched := mk(operations.StatusPending)
	done := mk(operations.StatusSuccess)
	rejected := mk(operations.StatusCancelled)

	pending, skipped := partitionApprovalChildren([]operations.Operation{
		waiting1, dispatched, waiting2, done, rejected,
	})

	if len(pending) != 2 || pending[0].ID != waiting1.ID || pending[1].ID != waiting2.ID {
		t.Errorf("pending = %v, want [%s %s] in creation order", pending, waiting1.ID, waiting2.ID)
	}
	wantSkipped := []childDecisionSkip{
		{ID: dispatched.ID, Status: operations.StatusPending},
		{ID: done.ID, Status: operations.StatusSuccess},
		{ID: rejected.ID, Status: operations.StatusCancelled},
	}
	if len(skipped) != len(wantSkipped) {
		t.Fatalf("skipped = %d entries, want %d", len(skipped), len(wantSkipped))
	}
	for i := range wantSkipped {
		if skipped[i] != wantSkipped[i] {
			t.Errorf("skipped[%d] = %+v, want %+v", i, skipped[i], wantSkipped[i])
		}
	}
}

// TestPartitionApprovalChildrenEmpty: parent без детей (или только с
// решёнными) даёт пустой batch — эндпоинт отвечает 200 идемпотентно.
func TestPartitionApprovalChildrenEmpty(t *testing.T) {
	pending, skipped := partitionApprovalChildren(nil)
	if len(pending) != 0 || len(skipped) != 0 {
		t.Errorf("partition(nil) = %d pending, %d skipped, want 0/0", len(pending), len(skipped))
	}
}

// TestDecisionAuditMetadataPerChild проверяет, что self_approved в metadata
// batch-решения вычисляется по requester КАЖДОГО ребёнка против общего
// approver: дети одного parent от разных акторов получают разные отметки.
func TestDecisionAuditMetadataPerChild(t *testing.T) {
	approverType, approverID := "user", "admin-a@grantor.dev"
	children := []struct {
		name      string
		actorType string
		actorID   string
		wantSelf  bool
	}{
		{"same admin requested", "user", "admin-a@grantor.dev", true},
		{"another admin requested", "user", "admin-b@grantor.dev", false},
		{"service requested", "service", "svc-1", false},
	}
	for _, tc := range children {
		t.Run(tc.name, func(t *testing.T) {
			op := operations.Operation{
				ID:        uuid.New(),
				Kind:      "access.grant",
				ActorType: tc.actorType,
				ActorID:   tc.actorID,
			}
			selfApproved := approval.IsSelf(op.ActorType, op.ActorID, approverType, approverID)
			raw, err := decisionAuditMetadata(op, "batch reason", selfApproved)
			if err != nil {
				t.Fatalf("decisionAuditMetadata: %v", err)
			}
			var meta struct {
				RequesterActorType string `json:"requester_actor_type"`
				RequesterActorID   string `json:"requester_actor_id"`
				OperationKind      string `json:"operation_kind"`
				Reason             string `json:"reason"`
				SelfApproved       bool   `json:"self_approved"`
			}
			if err := json.Unmarshal(raw, &meta); err != nil {
				t.Fatalf("unmarshal metadata: %v", err)
			}
			if meta.SelfApproved != tc.wantSelf {
				t.Errorf("self_approved = %v, want %v", meta.SelfApproved, tc.wantSelf)
			}
			if meta.RequesterActorType != tc.actorType || meta.RequesterActorID != tc.actorID {
				t.Errorf("requester = %s/%s, want %s/%s",
					meta.RequesterActorType, meta.RequesterActorID, tc.actorType, tc.actorID)
			}
			if meta.OperationKind != "access.grant" || meta.Reason != "batch reason" {
				t.Errorf("kind/reason = %q/%q", meta.OperationKind, meta.Reason)
			}
		})
	}
}
