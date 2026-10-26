package notify

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/core/operations"
)

// Событие не содержит payload и секретов — только несекретные метаданные;
// pending_approval и падение различаются типом и заголовком.
func TestOperationEvent(t *testing.T) {
	connID := uuid.New()
	finished := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	failed := operations.Operation{
		ID:           uuid.New(),
		Kind:         "access.revoke",
		Status:       operations.StatusFailed,
		ConnectionID: &connID,
		ActorType:    "user",
		ActorID:      "admin@example.com",
		Error:        "boom",
		FinishedAt:   &finished,
	}
	event := OperationEvent(failed)
	if event.Type != "operation.failed" {
		t.Errorf("type = %q, want operation.failed", event.Type)
	}
	if event.Fields["error"] != "boom" || event.Fields["connection_id"] != connID.String() {
		t.Errorf("fields = %+v", event.Fields)
	}
	if !event.OccurredAt.Equal(finished) {
		t.Errorf("occurred_at = %v, want finished_at", event.OccurredAt)
	}

	pending := operations.Operation{
		ID:        uuid.New(),
		Kind:      "access.grant",
		Status:    operations.StatusPendingApproval,
		ActorType: "user",
		ActorID:   "operator",
		CreatedAt: finished,
	}
	event = OperationEvent(pending)
	if event.Type != "operation.pending_approval" {
		t.Errorf("type = %q, want operation.pending_approval", event.Type)
	}
	if _, has := event.Fields["error"]; has {
		t.Error("pending event carries an error field")
	}
}
