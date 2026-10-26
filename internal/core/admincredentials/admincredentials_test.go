package admincredentials

import "testing"

func TestPhaseCancellationAndRetryabilityAreFailClosed(t *testing.T) {
	for _, phase := range []Phase{PhaseStaged, PhaseCandidateProving, PhaseTargetApplied} {
		if !phase.CanCancel(false) {
			t.Errorf("phase %q without side-effect fence should be cancellable", phase)
		}
		if phase.CanCancel(true) {
			t.Errorf("phase %q after possible side effect must not be cancellable", phase)
		}
	}
	for _, phase := range []Phase{PhaseCompleted, PhaseFailed, PhaseCancelled} {
		if phase.CanCancel(false) {
			t.Errorf("terminal phase %q must not be cancellable", phase)
		}
	}

	if (Change{Phase: PhaseFailed, ErrorCode: "invalid_candidate"}).Retryable() {
		t.Fatal("deterministically invalid candidate must not be retryable")
	}
	if (Change{Phase: PhaseFailed, ErrorCode: "future_error"}).Retryable() {
		t.Fatal("terminal failed lifecycle must not offer an impossible retry")
	}
	if (Change{Phase: PhaseTargetApplying, ErrorCode: "admin_authority_changed"}).Retryable() {
		t.Fatal("authority error without durable side-effect fence must not be retryable")
	}
	if !(Change{Phase: PhaseTargetApplying, ErrorCode: "admin_authority_changed", TargetSideEffectPossible: true}).Retryable() {
		t.Fatal("authority error after possible target change must remain recoverable by retry")
	}
	if !(Change{Phase: PhaseTargetApplying, ErrorCode: "invalid_candidate", TargetSideEffectPossible: true}).Retryable() {
		t.Fatal("candidate rejection after possible target change must not create a recovery dead-end")
	}
}

func TestPhaseOrderingNeverTreatsPromotionAsPreTarget(t *testing.T) {
	ordered := []Phase{
		PhasePreparing, PhaseStaged, PhaseCandidateProving, PhaseTargetApplying,
		PhaseTargetApplied, PhasePromoting, PhasePromoted,
		PhaseMetadataCommitting, PhaseCompleted,
	}
	for i := range ordered {
		for j := range ordered {
			if got, want := ordered[i].AtLeast(ordered[j]), i >= j; got != want {
				t.Errorf("%q.AtLeast(%q) = %v, want %v", ordered[i], ordered[j], got, want)
			}
		}
	}
}
