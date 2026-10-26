package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/rolepolicies"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

func TestParseRFC3339Param(t *testing.T) {
	want := time.Date(2026, 7, 20, 0, 0, 0, 0, time.FixedZone("MSK", 3*60*60))
	req, err := http.NewRequest(http.MethodGet,
		"/api/v1/operations?created_from=2026-07-20T00%3A00%3A00%2B03%3A00", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	got, err := parseRFC3339Param(req, "created_from")
	if err != nil {
		t.Fatalf("parseRFC3339Param(valid): %v", err)
	}
	if got == nil || !got.Equal(want) {
		t.Fatalf("parseRFC3339Param(valid) = %v, want %v", got, want)
	}

	for _, raw := range []string{
		"2026-07-20",
		"2026-07-20T00:00:00",
		"2026-07-20 00:00:00Z",
		" 2026-07-20T00:00:00Z",
		"2026-07-20T00:00:00Z ",
	} {
		t.Run(raw, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "/api/v1/operations?created_from="+url.QueryEscape(raw), nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			if _, err := parseRFC3339Param(req, "created_from"); err == nil {
				t.Errorf("parseRFC3339Param(%q): err = nil, want error", raw)
			}
		})
	}

	req, err = http.NewRequest(http.MethodGet, "/api/v1/operations", nil)
	if err != nil {
		t.Fatalf("NewRequest(empty): %v", err)
	}
	if got, err := parseRFC3339Param(req, "created_from"); err != nil || got != nil {
		t.Errorf("parseRFC3339Param(absent) = %v, %v; want nil, nil", got, err)
	}
}

func TestValidateOperationsTimeRange(t *testing.T) {
	from := time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)
	after := from.Add(24 * time.Hour)
	before := from.Add(-time.Second)

	if err := validateOperationsTimeRange(&from, &after); err != nil {
		t.Fatalf("valid [from, before) range: %v", err)
	}
	if err := validateOperationsTimeRange(nil, &after); err != nil {
		t.Fatalf("open lower bound: %v", err)
	}
	if err := validateOperationsTimeRange(&from, nil); err != nil {
		t.Fatalf("open upper bound: %v", err)
	}
	for name, invalidBefore := range map[string]time.Time{
		"equal":    from,
		"inverted": before,
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateOperationsTimeRange(&from, &invalidBefore); err == nil ||
				err.Error() != "invalid time range: created_before must be after created_from" {
				t.Errorf("validateOperationsTimeRange(%s) error = %v", name, err)
			}
		})
	}
}

// TestSplitCSVParam: CSV query-параметр режется по запятым с обрезкой
// пробелов; пустые элементы и пустая строка не дают условий фильтра.
func TestSplitCSVParam(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{name: "empty", raw: "", want: nil},
		{name: "single", raw: "access.grant", want: []string{"access.grant"}},
		{name: "multiple", raw: "access.grant,account.create", want: []string{"access.grant", "account.create"}},
		{name: "spaces and empties", raw: " a , ,b,", want: []string{"a", "b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := splitCSVParam(tt.raw); !slices.Equal(got, tt.want) {
				t.Errorf("splitCSVParam(%q) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}

// TestParseStatusesParam: статусы валидируются по перечислению
// operations.Status — опечатка в фильтре отдаёт 400, а не пустую выборку.
func TestParseStatusesParam(t *testing.T) {
	got, err := parseStatusesParam("pending,pending_approval,running")
	if err != nil {
		t.Fatalf("parseStatusesParam(valid): err = %v", err)
	}
	want := []operations.Status{
		operations.StatusPending, operations.StatusPendingApproval, operations.StatusRunning,
	}
	if !slices.Equal(got, want) {
		t.Errorf("parseStatusesParam = %v, want %v", got, want)
	}

	if statuses, err := parseStatusesParam(""); err != nil || statuses != nil {
		t.Errorf("parseStatusesParam(\"\") = %v, %v; want nil, nil", statuses, err)
	}

	if _, err := parseStatusesParam("pending,bogus"); err == nil {
		t.Error("parseStatusesParam(unknown status): err = nil, want error")
	}
}

// TestRetryableChildren: retry подлежат только failed дети. success и
// running не трогаются, cancelled пропускается (терминален; отклонённый
// reject ребёнок не возвращается в работу в обход approval-гейта).
func TestRetryableChildren(t *testing.T) {
	mk := func(st operations.Status) operations.Operation {
		return operations.Operation{ID: uuid.New(), Status: st}
	}
	failed1 := mk(operations.StatusFailed)
	failed2 := mk(operations.StatusFailed)
	children := []operations.Operation{
		mk(operations.StatusSuccess),
		failed1,
		mk(operations.StatusCancelled),
		failed2,
		mk(operations.StatusRunning),
	}

	got := retryableChildren(children)
	if len(got) != 2 || got[0].ID != failed1.ID || got[1].ID != failed2.ID {
		t.Errorf("retryableChildren = %v, want [%s %s] in original order", got, failed1.ID, failed2.ID)
	}

	if got := retryableChildren(nil); len(got) != 0 {
		t.Errorf("retryableChildren(nil) = %v, want empty", got)
	}
}

func TestLegacyPostgresOperationsAreNotRetryable(t *testing.T) {
	s := &Server{}
	for _, kind := range []string{
		jobs.KindResourceCreatePreparedDatabase,
		jobs.KindDatabaseCreateWithRoles,
		jobs.KindRolePolicyCreateDatabase,
	} {
		legacy, err := s.legacyPostgresOperationForRetry(t.Context(), operations.Operation{Kind: kind})
		if err != nil || !legacy {
			t.Errorf("kind %q legacy = %v, %v; want true, nil", kind, legacy, err)
		}
	}
	for _, engine := range []string{"postgres", "mongodb"} {
		payload, err := json.Marshal(jobs.RolePolicyPayload{
			Action: rolepolicies.ActionApply,
			Spec:   adapter.RolePolicySpec{Engine: engine, Key: "policy", RoleName: "role"},
		})
		if err != nil {
			t.Fatal(err)
		}
		legacy, err := s.legacyPostgresOperationForRetry(t.Context(), operations.Operation{
			Kind: jobs.KindRolePolicyApply, Payload: payload,
		})
		if err != nil || legacy != (engine == "postgres") {
			t.Errorf("engine %q legacy = %v, %v", engine, legacy, err)
		}
	}
	for _, kind := range []string{
		jobs.KindPostgresRolePolicyApplyV2,
		jobs.KindPostgresRolePolicyAdoptV2,
		jobs.KindPostgresRolePolicyRepairV2,
		jobs.KindPostgresRolePolicyCreateV2,
		jobs.KindPostgresRolePolicyCreateDatabaseV2,
	} {
		if !isRolePolicyOperationKind(kind) {
			t.Errorf("current v2 role-policy kind %q is not classified", kind)
		}
	}
}
