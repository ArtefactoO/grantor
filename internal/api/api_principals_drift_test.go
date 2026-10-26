package api

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
)

func TestCreatePrincipalRequestValidate(t *testing.T) {
	valid := func() createPrincipalRequest {
		return createPrincipalRequest{
			Type:             "human",
			DisplayName:      "Alice",
			ExternalProvider: "dex",
			ExternalSubject:  "sub-1",
		}
	}
	if err := func() error { req := valid(); return req.validate() }(); err != nil {
		t.Fatalf("valid request: unexpected error: %v", err)
	}
	// Локальный принципал без внешней identity тоже валиден.
	local := createPrincipalRequest{Type: "service", DisplayName: "svc"}
	if err := local.validate(); err != nil {
		t.Fatalf("local principal: unexpected error: %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(*createPrincipalRequest)
		wantSub string
	}{
		{
			name:    "empty type",
			mutate:  func(r *createPrincipalRequest) { r.Type = "" },
			wantSub: "type must be",
		},
		{
			name:    "unknown type",
			mutate:  func(r *createPrincipalRequest) { r.Type = "alien" },
			wantSub: "type must be",
		},
		{
			name:    "empty display name",
			mutate:  func(r *createPrincipalRequest) { r.DisplayName = "  " },
			wantSub: "display_name",
		},
		{
			name:    "provider without subject",
			mutate:  func(r *createPrincipalRequest) { r.ExternalSubject = "" },
			wantSub: "must be set together",
		},
		{
			name:    "subject without provider",
			mutate:  func(r *createPrincipalRequest) { r.ExternalProvider = "" },
			wantSub: "must be set together",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := valid()
			tc.mutate(&req)
			err := req.validate()
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not contain %q", err, tc.wantSub)
			}
		})
	}
}

func TestIsDegradedConnectionStatus(t *testing.T) {
	degraded := []connections.Status{
		connections.StatusDegraded,
		connections.StatusConnectionFailed,
		connections.StatusDiscoveryFailed,
	}
	for _, st := range degraded {
		if !isDegradedConnectionStatus(st) {
			t.Errorf("isDegradedConnectionStatus(%q) = false, want true", st)
		}
	}
	healthy := []connections.Status{
		connections.StatusDraft,
		connections.StatusValidating,
		connections.StatusDiscovering,
		connections.StatusActive,
		connections.StatusDisabled,
		connections.Status("ghost"),
	}
	for _, st := range healthy {
		if isDegradedConnectionStatus(st) {
			t.Errorf("isDegradedConnectionStatus(%q) = true, want false", st)
		}
	}
}

func TestDriftCounts(t *testing.T) {
	if got := driftCounts(nil); got != (driftCountsJSON{}) {
		t.Errorf("driftCounts(nil) = %+v, want zero counts", got)
	}

	findings := []driftFindingJSON{
		{Kind: inventory.DriftKindBindingDrift},
		{Kind: inventory.DriftKindBindingDrift},
		{Kind: inventory.DriftKindUnmanagedBinding},
		{Kind: inventory.DriftKindMissingResource},
		{Kind: driftKindConnectionDegraded},
		{Kind: "ghost"},
	}
	want := driftCountsJSON{
		BindingDrift:        2,
		UnmanagedBinding:    1,
		MissingResource:     1,
		DegradedConnections: 1,
	}
	if got := driftCounts(findings); got != want {
		t.Errorf("driftCounts = %+v, want %+v", got, want)
	}
}

func TestToDriftFindingJSON(t *testing.T) {
	bindingID := uuid.New()
	accountID := uuid.New()
	resourceID := uuid.New()
	permissionID := uuid.New()
	f := inventory.DriftFinding{
		Kind:            inventory.DriftKindBindingDrift,
		ConnectionID:    uuid.New(),
		BindingID:       &bindingID,
		AccountID:       &accountID,
		ResourceID:      &resourceID,
		PermissionID:    &permissionID,
		AccountIdentity: "svc",
		PermissionName:  "readers",
		ResourceName:    "public",
		Detail:          "желаемое состояние present, наблюдаемое absent",
	}

	out := toDriftFindingJSON(f)
	if out.Kind != f.Kind || out.ConnectionID != f.ConnectionID || out.Detail != f.Detail {
		t.Errorf("unexpected mapping: %+v", out)
	}
	if out.BindingID == nil || *out.BindingID != bindingID ||
		out.AccountID == nil || *out.AccountID != accountID ||
		out.ResourceID == nil || *out.ResourceID != resourceID ||
		out.PermissionID == nil || *out.PermissionID != permissionID {
		t.Errorf("unexpected reference ids: %+v", out)
	}
	if out.AccountIdentity != "svc" || out.PermissionName != "readers" || out.ResourceName != "public" {
		t.Errorf("unexpected display names: %+v", out)
	}
}

// Baseline прячет находку из активного списка, но сохраняет её видимой с
// атрибуцией; вид без baseline-ref и находка без пары остаются активными.
func TestSplitBaselinedFindings(t *testing.T) {
	bindingID := uuid.New()
	otherBinding := uuid.New()
	resourceID := uuid.New()
	findings := []driftFindingJSON{
		{Kind: inventory.DriftKindUnmanagedBinding, BindingID: &bindingID},
		{Kind: inventory.DriftKindUnmanagedBinding, BindingID: &otherBinding},
		{Kind: inventory.DriftKindMissingResource, ResourceID: &resourceID},
		{Kind: driftKindConnectionDegraded},
	}
	baselines := []inventory.DriftBaseline{
		{ID: uuid.New(), Kind: inventory.DriftKindUnmanagedBinding, RefID: bindingID, Reason: "legacy", CreatedBy: "op"},
		// Baseline без живой находки не показывается: ему нечего скрывать.
		{ID: uuid.New(), Kind: inventory.DriftKindMissingAccount, RefID: uuid.New()},
	}
	active, baselined := splitBaselinedFindings(findings, baselines)
	if len(active) != 3 {
		t.Fatalf("active = %d, want 3: %+v", len(active), active)
	}
	if len(baselined) != 1 {
		t.Fatalf("baselined = %d, want 1: %+v", len(baselined), baselined)
	}
	if baselined[0].BindingID == nil || *baselined[0].BindingID != bindingID {
		t.Errorf("baselined finding = %+v, want binding %s", baselined[0], bindingID)
	}
	if baselined[0].Reason != "legacy" || baselined[0].CreatedBy != "op" {
		t.Errorf("baseline attribution lost: %+v", baselined[0])
	}
}

// Гейт видов: авария подключения и рассинхрон секрета не бывают «нормой».
func TestBaselineableDriftKind(t *testing.T) {
	for kind, want := range map[string]bool{
		inventory.DriftKindBindingDrift:       true,
		inventory.DriftKindUnmanagedBinding:   true,
		inventory.DriftKindMissingResource:    true,
		inventory.DriftKindMissingAccount:     true,
		inventory.DriftKindCredentialDiverged: false,
		driftKindConnectionDegraded:           false,
		"unknown":                             false,
	} {
		if got := inventory.BaselineableDriftKind(kind); got != want {
			t.Errorf("BaselineableDriftKind(%q) = %v, want %v", kind, got, want)
		}
	}
}
