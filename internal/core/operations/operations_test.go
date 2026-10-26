package operations

import "testing"

func TestCanTransition(t *testing.T) {
	tests := []struct {
		name string
		from Status
		to   Status
		want bool
	}{
		// Валидные переходы.
		{"pending_approval to pending", StatusPendingApproval, StatusPending, true},
		{"pending_approval to cancelled", StatusPendingApproval, StatusCancelled, true},
		{"pending to running", StatusPending, StatusRunning, true},
		{"pending to cancelled", StatusPending, StatusCancelled, true},
		{"running to success", StatusRunning, StatusSuccess, true},
		{"running to partial", StatusRunning, StatusPartial, true},
		{"running to failed", StatusRunning, StatusFailed, true},
		{"running to cancelled", StatusRunning, StatusCancelled, true},
		{"failed to pending (retry)", StatusFailed, StatusPending, true},
		{"failed to cancelled (give up before external effect)", StatusFailed, StatusCancelled, true},
		{"partial to pending (retry)", StatusPartial, StatusPending, true},

		// Невалидные переходы.
		{"pending_approval to running", StatusPendingApproval, StatusRunning, false},
		{"pending_approval to success", StatusPendingApproval, StatusSuccess, false},
		{"pending to success", StatusPending, StatusSuccess, false},
		{"pending to failed", StatusPending, StatusFailed, false},
		{"pending to pending_approval", StatusPending, StatusPendingApproval, false},
		{"running to pending", StatusRunning, StatusPending, false},
		{"running to pending_approval", StatusRunning, StatusPendingApproval, false},
		{"failed to running", StatusFailed, StatusRunning, false},
		{"failed to success", StatusFailed, StatusSuccess, false},
		{"partial to success", StatusPartial, StatusSuccess, false},
		{"success is final", StatusSuccess, StatusPending, false},
		{"cancelled is final", StatusCancelled, StatusPending, false},
		{"self transition", StatusPending, StatusPending, false},
		{"unknown from", Status("bogus"), StatusPending, false},
		{"unknown to", StatusPending, Status("bogus"), false},
		{"empty statuses", Status(""), Status(""), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CanTransition(tt.from, tt.to); got != tt.want {
				t.Errorf("CanTransition(%q, %q) = %v, want %v", tt.from, tt.to, got, tt.want)
			}
		})
	}
}

func TestStatusIsTerminal(t *testing.T) {
	tests := []struct {
		status Status
		want   bool
	}{
		{StatusPendingApproval, false},
		{StatusPending, false},
		{StatusRunning, false},
		{StatusSuccess, true},
		{StatusPartial, false},
		{StatusFailed, false},
		{StatusCancelled, true},
		{Status("bogus"), false},
	}
	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			if got := tt.status.IsTerminal(); got != tt.want {
				t.Errorf("Status(%q).IsTerminal() = %v, want %v", tt.status, got, tt.want)
			}
		})
	}
}

func TestStatusIsFinished(t *testing.T) {
	tests := []struct {
		status Status
		want   bool
	}{
		{StatusPendingApproval, false},
		{StatusPending, false},
		{StatusRunning, false},
		{StatusSuccess, true},
		{StatusPartial, true},
		{StatusFailed, true},
		{StatusCancelled, true},
		{Status("bogus"), false},
	}
	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			if got := tt.status.IsFinished(); got != tt.want {
				t.Errorf("Status(%q).IsFinished() = %v, want %v", tt.status, got, tt.want)
			}
		})
	}
}

func TestAggregateChildren(t *testing.T) {
	tests := []struct {
		name     string
		children []Status
		want     Status
	}{
		{"no children", nil, Status("")},
		{"empty slice", []Status{}, Status("")},
		{"all success", []Status{StatusSuccess, StatusSuccess}, StatusSuccess},
		{"single success", []Status{StatusSuccess}, StatusSuccess},
		{"pending child keeps running", []Status{StatusSuccess, StatusPending}, StatusRunning},
		{"pending_approval child keeps running", []Status{StatusPendingApproval, StatusFailed}, StatusRunning},
		{"running child keeps running", []Status{StatusRunning, StatusFailed}, StatusRunning},
		{"mixed outcome", []Status{StatusSuccess, StatusFailed}, StatusPartial},
		{"success and cancelled", []Status{StatusSuccess, StatusCancelled}, StatusPartial},
		{"all failed", []Status{StatusFailed, StatusFailed}, StatusFailed},
		{"all cancelled", []Status{StatusCancelled}, StatusFailed},
		{"failed and cancelled", []Status{StatusFailed, StatusCancelled}, StatusFailed},
		{"partial child counts as failure", []Status{StatusPartial, StatusSuccess}, StatusPartial},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AggregateChildren(tt.children); got != tt.want {
				t.Errorf("AggregateChildren(%v) = %q, want %q", tt.children, got, tt.want)
			}
		})
	}
}

// TestAggregateChildrenAllowedFromRunning гарантирует согласованность
// финализации со state machine: любой итог AggregateChildren по
// завершённым детям достижим переходом из running.
func TestAggregateChildrenAllowedFromRunning(t *testing.T) {
	finished := []Status{StatusSuccess, StatusPartial, StatusFailed, StatusCancelled}
	for _, a := range finished {
		for _, b := range finished {
			agg := AggregateChildren([]Status{a, b})
			if !CanTransition(StatusRunning, agg) {
				t.Errorf("aggregate %q of (%q, %q) is not reachable from running", agg, a, b)
			}
		}
	}
}

// TestTerminalStatusesHaveNoTransitions гарантирует согласованность
// IsTerminal с картой переходов: из терминального статуса нет выходов.
func TestTerminalStatusesHaveNoTransitions(t *testing.T) {
	all := []Status{
		StatusPendingApproval, StatusPending, StatusRunning,
		StatusSuccess, StatusPartial, StatusFailed, StatusCancelled,
	}
	for _, from := range all {
		if !from.IsTerminal() {
			continue
		}
		for _, to := range all {
			if CanTransition(from, to) {
				t.Errorf("terminal status %q has transition to %q", from, to)
			}
		}
	}
}
