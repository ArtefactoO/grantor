package approval

import (
	"strings"
	"testing"
)

func TestRequires(t *testing.T) {
	tests := []struct {
		name      string
		enabled   bool
		dangerous bool
		want      bool
	}{
		{"gate off, safe", false, false, false},
		{"gate off, dangerous", false, true, false},
		{"gate on, safe", true, false, false},
		{"gate on, dangerous", true, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Requires(tt.enabled, tt.dangerous); got != tt.want {
				t.Errorf("Requires(%v, %v) = %v, want %v", tt.enabled, tt.dangerous, got, tt.want)
			}
		})
	}
}

func TestRequiresMassRevoke(t *testing.T) {
	tests := []struct {
		name      string
		threshold int
		revokes   int
		want      bool
	}{
		{"disabled zero threshold", 0, 100, false},
		{"disabled negative threshold", -1, 100, false},
		{"below threshold", 5, 3, false},
		{"at threshold", 5, 5, false},
		{"above threshold", 5, 6, true},
		{"single revoke below smallest threshold", 1, 1, false},
		{"two revokes above threshold one", 1, 2, true},
		{"no revokes", 5, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RequiresMassRevoke(tt.threshold, tt.revokes); got != tt.want {
				t.Errorf("RequiresMassRevoke(%d, %d) = %v, want %v",
					tt.threshold, tt.revokes, got, tt.want)
			}
		})
	}
}

func TestIsSelf(t *testing.T) {
	tests := []struct {
		name    string
		reqType string
		reqID   string
		apType  string
		apID    string
		want    bool
	}{
		{"same user", "user", "a@grantor.dev", "user", "a@grantor.dev", true},
		{"different user", "user", "a@grantor.dev", "user", "b@grantor.dev", false},
		{"same id different type", "user", "x", "service", "x", false},
		{"same service", "service", "svc-1", "service", "svc-1", true},
		{"empty both equal", "", "", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSelf(tt.reqType, tt.reqID, tt.apType, tt.apID); got != tt.want {
				t.Errorf("IsSelf() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNormalizeReason(t *testing.T) {
	if got := NormalizeReason("  needs review  "); got != "needs review" {
		t.Errorf("trim: got %q", got)
	}
	if got := NormalizeReason(""); got != "" {
		t.Errorf("empty: got %q", got)
	}
	long := strings.Repeat("x", MaxReasonLen+50)
	if got := NormalizeReason(long); len([]rune(got)) != MaxReasonLen {
		t.Errorf("truncate: len = %d, want %d", len([]rune(got)), MaxReasonLen)
	}
	// Многобайтовые руны не рвутся: результат — валидный UTF-8 длиной MaxReasonLen рун.
	multi := strings.Repeat("ф", MaxReasonLen+10)
	got := NormalizeReason(multi)
	if len([]rune(got)) != MaxReasonLen {
		t.Errorf("truncate multibyte: rune len = %d, want %d", len([]rune(got)), MaxReasonLen)
	}
}
