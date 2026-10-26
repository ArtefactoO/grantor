package connections

import (
	"context"
	"strings"
	"testing"
)

// allStatuses — полный список статусов подключения для перебора пар.
var allStatuses = []Status{
	StatusDraft,
	StatusValidating,
	StatusDiscovering,
	StatusActive,
	StatusConnectionFailed,
	StatusDiscoveryFailed,
	StatusDegraded,
	StatusDisabled,
}

// allowedTransitions — эталонная таблица допустимых переходов из
// docs/architecture.md, раздел 5.1, включая обратные переходы.
var allowedTransitions = []struct{ from, to Status }{
	{StatusDraft, StatusValidating},
	{StatusValidating, StatusDiscovering},
	{StatusValidating, StatusConnectionFailed},
	{StatusConnectionFailed, StatusValidating},
	{StatusDiscovering, StatusActive},
	{StatusDiscovering, StatusDiscoveryFailed},
	{StatusDiscoveryFailed, StatusDiscovering},
	{StatusActive, StatusDegraded},
	{StatusDegraded, StatusActive},
	{StatusActive, StatusDisabled},
	{StatusDisabled, StatusActive},
}

func TestCanTransitionMatchesSpec(t *testing.T) {
	allowed := make(map[[2]Status]bool, len(allowedTransitions))
	for _, tr := range allowedTransitions {
		allowed[[2]Status{tr.from, tr.to}] = true
	}

	// Полный перебор пар: разрешено ровно то, что в эталонной таблице,
	// включая запрет перехода в тот же статус.
	for _, from := range allStatuses {
		for _, to := range allStatuses {
			want := allowed[[2]Status{from, to}]
			if got := CanTransition(from, to); got != want {
				t.Errorf("CanTransition(%q, %q) = %v, want %v", from, to, got, want)
			}
		}
	}
}

func TestCanTransitionUnknownStatus(t *testing.T) {
	if CanTransition("bogus", StatusActive) {
		t.Error(`CanTransition("bogus", active) = true, want false`)
	}
	if CanTransition(StatusActive, "bogus") {
		t.Error(`CanTransition(active, "bogus") = true, want false`)
	}
}

func TestConnectionEditStateGuards(t *testing.T) {
	for _, status := range allStatuses {
		wantMetadata := status != StatusValidating && status != StatusDiscovering
		if got := CanEditMetadata(status); got != wantMetadata {
			t.Errorf("CanEditMetadata(%q) = %v, want %v", status, got, wantMetadata)
		}
		wantOperational := wantMetadata && status != StatusDisabled
		if got := CanReconfigure(status); got != wantOperational {
			t.Errorf("CanReconfigure(%q) = %v, want %v", status, got, wantOperational)
		}
	}
	if CanEditMetadata("bogus") || CanReconfigure("bogus") {
		t.Error("unknown status must reject both connection edit paths")
	}
}

func TestValidExecutionMode(t *testing.T) {
	cases := []struct {
		mode string
		want bool
	}{
		{ExecutionModeDirect, true},
		{ExecutionModeConnector, true},
		{"", false},
		{"tunnel", false},
		{"Direct", false},
	}
	for _, tc := range cases {
		if got := ValidExecutionMode(tc.mode); got != tc.want {
			t.Errorf("ValidExecutionMode(%q) = %v, want %v", tc.mode, got, tc.want)
		}
	}
}

// TestCreateRejectsUnknownExecutionMode — Create отвечает понятной
// ошибкой валидации до обращения к базе (Querier здесь nil: до SQL
// дойти не должно, иначе тест упадёт с nil dereference).
func TestCreateRejectsUnknownExecutionMode(t *testing.T) {
	s := NewStore()
	_, err := s.Create(context.Background(), nil, CreateParams{
		DisplayName:   "target",
		Engine:        "postgres",
		ExecutionMode: "tunnel",
	})
	if err == nil {
		t.Fatal("Create with unknown execution mode: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unknown execution mode") {
		t.Errorf("error %q does not mention unknown execution mode", err)
	}
}
