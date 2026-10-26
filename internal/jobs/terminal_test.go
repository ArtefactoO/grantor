package jobs

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
)

// TestIsTerminalClassification фиксирует границу между детерминированными и
// повторяемыми отказами: первые снимаются с ретраев River, вторые обязаны
// ретраиться как раньше.
func TestIsTerminalClassification(t *testing.T) {
	// wrap повторяет обёртки executor: "jobs: <kind> operation <id>: ..." и
	// внутренние префиксы plan/apply/verify.
	wrap := func(err error) error {
		return fmt.Errorf("jobs: %s operation %s: plan: %w", KindAccountDisable, uuid.New(), err)
	}

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{
			"unsupported change",
			wrap(fmt.Errorf("mongodb: plan %s: %w", adapter.ChangeAccountDisable, adapter.ErrUnsupportedChange)),
			true,
		},
		{
			"unsupported change with engine detail",
			wrap(fmt.Errorf("kafka: credential.rotate: %w: requires a SCRAM mechanism", adapter.ErrUnsupportedChange)),
			true,
		},
		{
			"credential proof unsupported",
			wrap(adapter.ErrCredentialProofUnsupported),
			true,
		},
		{
			"external identity conflict",
			wrap(adapter.ErrExternalIdentityConflict),
			true,
		},
		{
			"target identity conflict",
			wrap(adapter.ErrTargetIdentityConflict),
			true,
		},
		{
			"account lifecycle conflict",
			wrap(fmt.Errorf("account %s lifecycle version 3, expected 2: %w", uuid.New(), inventory.ErrAccountLifecycleConflict)),
			true,
		},
		{
			"account status conflict",
			wrap(fmt.Errorf("account %s status %q, expected %q: %w",
				uuid.New(), inventory.AccountDeleted, inventory.AccountActive, inventory.ErrAccountStatusConflict)),
			true,
		},
		{
			"explicitly marked",
			wrap(terminal(errors.New("decode account payload: account_id is not set"))),
			true,
		},
		{
			"joined with terminal cause",
			errors.Join(wrap(adapter.ErrUnsupportedChange), errors.New("write audit event")),
			true,
		},
		{
			"transient network failure",
			wrap(&net.OpError{Op: "dial", Err: errors.New("connection refused")}),
			false,
		},
		{"context deadline", wrap(context.DeadlineExceeded), false},
		{
			"vault unavailable",
			wrap(errors.New("read admin credential: 503 service unavailable")),
			false,
		},
		{
			// Занятость lifecycle разрешается завершением конкурентной
			// операции, поэтому повтор осмыслен.
			"account lifecycle busy",
			wrap(inventory.ErrAccountLifecycleBusy),
			false,
		},
		{
			"operations status conflict",
			wrap(operations.ErrStatusConflict),
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isTerminal(tt.err); got != tt.want {
				t.Errorf("isTerminal(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// TestTerminalPreservesCause: пометка меняет только политику повторов, не
// сообщение и не цепочку причин.
func TestTerminalPreservesCause(t *testing.T) {
	cause := fmt.Errorf("kafka: credential.rotate: %w", adapter.ErrUnsupportedChange)
	marked := terminal(cause)

	if marked.Error() != cause.Error() {
		t.Errorf("marked text = %q, want %q", marked.Error(), cause.Error())
	}
	if !errors.Is(marked, adapter.ErrUnsupportedChange) {
		t.Error("marked error lost its cause")
	}
	if terminal(nil) != nil {
		t.Error("terminal(nil) != nil")
	}
}

// TestTerminalErrorTextMarker: маркер сохраняет исходный текст целиком,
// идемпотентен и распознаётся при повторной доставке job.
func TestTerminalErrorTextMarker(t *testing.T) {
	const original = "jobs: credential.rotate operation 8f: kafka: adapter: unsupported change"

	marked := markTerminalErrorText(original)
	if !hasTerminalErrorText(marked) {
		t.Fatalf("marked %q is not recognized as terminal", marked)
	}
	if got := marked[len(terminalErrorPrefix):]; got != original {
		t.Errorf("original text = %q, want %q", got, original)
	}
	if again := markTerminalErrorText(marked); again != marked {
		t.Errorf("second mark = %q, want idempotent %q", again, marked)
	}
	if markTerminalErrorText("") != "" {
		t.Error("empty error text must stay empty")
	}
	if hasTerminalErrorText(original) {
		t.Error("plain error text must not be recognized as terminal")
	}
}

// TestTerminalRestoreCodes фиксирует разделение sanitized-кодов restore:
// конфликты состояния и capability детерминированы, недоступность зависимостей
// — нет (текст restore не несёт исходной цепочки, классификация идёт по коду).
func TestTerminalRestoreCodes(t *testing.T) {
	terminalCodes := []string{
		"operation_account_mismatch", "lifecycle_conflict", "ineligible_account",
		"binding_evidence", "credential_identity_mismatch", "unsupported_capability",
		"credential_proof_unsupported", "external_identity_conflict",
	}
	for _, code := range terminalCodes {
		if !terminalRestoreCodes[code] {
			t.Errorf("restore code %q must be terminal", code)
		}
	}
	retryableCodes := []string{
		"inventory_unavailable", "credentials_unavailable", "credential_unavailable",
		"target_unavailable", "metadata_activation_failed", "audit_metadata_invalid",
		"artifact_reconstruction_failed", "adapter_failure",
	}
	for _, code := range retryableCodes {
		if terminalRestoreCodes[code] {
			t.Errorf("restore code %q must stay retryable", code)
		}
	}
}
