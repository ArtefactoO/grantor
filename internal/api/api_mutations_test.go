package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/operations"
)

func TestAggregateStatus(t *testing.T) {
	const (
		pending   = operations.StatusPending
		running   = operations.StatusRunning
		success   = operations.StatusSuccess
		failed    = operations.StatusFailed
		cancelled = operations.StatusCancelled
		partial   = operations.StatusPartial
	)
	cases := []struct {
		name     string
		children []operations.Status
		want     string
	}{
		{name: "no children", children: nil, want: ""},
		{name: "all success", children: []operations.Status{success, success}, want: "success"},
		{name: "single success", children: []operations.Status{success}, want: "success"},
		{name: "pending child", children: []operations.Status{success, pending}, want: "running"},
		{name: "running child", children: []operations.Status{running, failed}, want: "running"},
		{name: "mixed outcome", children: []operations.Status{success, failed}, want: "partial"},
		{name: "success and cancelled", children: []operations.Status{success, cancelled}, want: "partial"},
		{name: "all failed", children: []operations.Status{failed, failed}, want: "failed"},
		{name: "all cancelled", children: []operations.Status{cancelled}, want: "failed"},
		{name: "partial child counts as failure", children: []operations.Status{partial, success}, want: "partial"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := aggregateStatus(tc.children); got != tc.want {
				t.Errorf("aggregateStatus(%v) = %q, want %q", tc.children, got, tc.want)
			}
		})
	}
}

func TestDangerousGrantCheck(t *testing.T) {
	cases := []struct {
		name       string
		role       auth.Role
		confirmed  bool
		wantStatus int
	}{
		{name: "viewer", role: auth.RoleViewer, confirmed: true, wantStatus: http.StatusForbidden},
		{name: "operator without confirm", role: auth.RoleOperator, wantStatus: http.StatusForbidden},
		{name: "operator with confirm", role: auth.RoleOperator, confirmed: true, wantStatus: http.StatusForbidden},
		{name: "admin without confirm", role: auth.RoleAdmin, wantStatus: http.StatusBadRequest},
		{name: "admin with confirm", role: auth.RoleAdmin, confirmed: true, wantStatus: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, msg := dangerousGrantCheck(tc.role, tc.confirmed)
			if status != tc.wantStatus {
				t.Errorf("status = %d, want %d", status, tc.wantStatus)
			}
			if (status == 0) != (msg == "") {
				t.Errorf("message %q inconsistent with status %d", msg, status)
			}
		})
	}
}

func TestBulkCreateBindingsRequestValidate(t *testing.T) {
	valid := bulkCreateBindingsRequest{Items: []bulkBindingItem{
		{AccountID: uuid.New(), PermissionID: uuid.New()},
	}}
	if err := valid.validate(); err != nil {
		t.Fatalf("valid request: unexpected error: %v", err)
	}

	empty := bulkCreateBindingsRequest{}
	if err := empty.validate(); err == nil {
		t.Error("empty items: err = nil, want error")
	}

	tooMany := bulkCreateBindingsRequest{Items: make([]bulkBindingItem, maxBulkItems+1)}
	for i := range tooMany.Items {
		tooMany.Items[i] = bulkBindingItem{AccountID: uuid.New(), PermissionID: uuid.New()}
	}
	if err := tooMany.validate(); err == nil {
		t.Error("too many items: err = nil, want error")
	}

	missing := bulkCreateBindingsRequest{Items: []bulkBindingItem{
		{AccountID: uuid.New(), PermissionID: uuid.New()},
		{AccountID: uuid.New()},
	}}
	err := missing.validate()
	if err == nil {
		t.Fatal("missing permission_id: err = nil, want error")
	}
	if !strings.Contains(err.Error(), "items[1]") {
		t.Errorf("error %q does not point to failing item", err)
	}
}

func TestManageAccountRolesRequestValidate(t *testing.T) {
	valid := manageAccountRolesRequest{
		AddPermissionIDs: []uuid.UUID{uuid.New()},
		RemoveBindingIDs: []uuid.UUID{uuid.New()},
	}
	if err := valid.validate(); err != nil {
		t.Fatalf("valid request: unexpected error: %v", err)
	}

	if err := (&manageAccountRolesRequest{}).validate(); err == nil {
		t.Error("empty changes: err = nil, want error")
	}
	duplicate := uuid.New()
	if err := (&manageAccountRolesRequest{
		AddPermissionIDs: []uuid.UUID{duplicate, duplicate},
	}).validate(); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Errorf("duplicate permission: err = %v, want duplicate error", err)
	}
	tooMany := manageAccountRolesRequest{
		AddPermissionIDs: make([]uuid.UUID, maxBulkItems+1),
	}
	for i := range tooMany.AddPermissionIDs {
		tooMany.AddPermissionIDs[i] = uuid.New()
	}
	if err := tooMany.validate(); err == nil {
		t.Error("too many changes: err = nil, want error")
	}
}

func TestCreateAccountRequestValidate(t *testing.T) {
	valid := func() createAccountRequest {
		return createAccountRequest{
			ConnectionID:   uuid.New(),
			EngineIdentity: "svc_payments",
			Credential:     &accountCredentialRequest{Mode: credentialModeGenerated},
		}
	}
	if err := func() error { req := valid(); return req.validate() }(); err != nil {
		t.Fatalf("valid request: unexpected error: %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(*createAccountRequest)
		wantSub string
	}{
		{
			name:    "missing connection",
			mutate:  func(r *createAccountRequest) { r.ConnectionID = uuid.Nil },
			wantSub: "connection_id",
		},
		{
			name:    "empty identity",
			mutate:  func(r *createAccountRequest) { r.EngineIdentity = "  " },
			wantSub: "engine_identity",
		},
		{
			name:    "identity with whitespace",
			mutate:  func(r *createAccountRequest) { r.EngineIdentity = "svc payments" },
			wantSub: "whitespace",
		},
		{
			name:    "missing credential",
			mutate:  func(r *createAccountRequest) { r.Credential = nil },
			wantSub: "credential is required",
		},
		{
			name:    "unknown mode",
			mutate:  func(r *createAccountRequest) { r.Credential.Mode = "external_identity" },
			wantSub: "credential.mode",
		},
		{
			name:    "generated with password",
			mutate:  func(r *createAccountRequest) { r.Credential.Password = "x" },
			wantSub: "must not be set",
		},
		{
			name: "provided without password",
			mutate: func(r *createAccountRequest) {
				r.Credential.Mode = credentialModeProvided
				r.Credential.Password = ""
			},
			wantSub: "password is required",
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

func TestBulkBindingItemValidate(t *testing.T) {
	ok := bulkBindingItem{AccountID: uuid.New(), PermissionID: uuid.New()}
	if err := ok.validate(); err != nil {
		t.Errorf("valid item: unexpected error: %v", err)
	}
	noAccount := bulkBindingItem{PermissionID: uuid.New()}
	if err := noAccount.validate(); err == nil {
		t.Error("missing account_id: err = nil, want error")
	}
	noPermission := bulkBindingItem{AccountID: uuid.New()}
	if err := noPermission.validate(); err == nil {
		t.Error("missing permission_id: err = nil, want error")
	}
}

func TestAdoptAccountRequestValidate(t *testing.T) {
	metadata := adoptAccountRequest{Mode: adoptModeMetadata}
	if err := metadata.validate(); err != nil {
		t.Errorf("metadata mode: unexpected error: %v", err)
	}
	setPassword := adoptAccountRequest{Mode: adoptModeSetPassword, Password: "x", AdoptBindings: true}
	if err := setPassword.validate(); err != nil {
		t.Errorf("set_password mode: unexpected error: %v", err)
	}
	verifyPassword := adoptAccountRequest{Mode: adoptModeVerifyPassword, Password: "x", AdoptBindings: true}
	if err := verifyPassword.validate(); err != nil {
		t.Errorf("verify_password mode: unexpected error: %v", err)
	}
	generate := adoptAccountRequest{Mode: adoptModeGenerate, AdoptBindings: true}
	if err := generate.validate(); err != nil {
		t.Errorf("generate mode: unexpected error: %v", err)
	}

	// Обратная совместимость: прежнее имя password принимается и означает
	// ровно set_password (перезапись пароля учётки), а канонизация приводит
	// его к каноническому имени до любой обработки.
	legacy := adoptAccountRequest{Mode: adoptModeLegacyPassword, Password: "x"}
	if err := legacy.validate(); err != nil {
		t.Errorf("legacy password mode: unexpected error: %v", err)
	}
	if got := legacy.canonicalMode(); got != adoptModeSetPassword {
		t.Errorf("legacy mode canonicalized to %q, want %q", got, adoptModeSetPassword)
	}
	for _, mode := range []string{adoptModeMetadata, adoptModeGenerate, adoptModeSetPassword, adoptModeVerifyPassword} {
		req := adoptAccountRequest{Mode: mode}
		if got := req.canonicalMode(); got != mode {
			t.Errorf("canonical mode %q rewritten to %q", mode, got)
		}
	}

	cases := []struct {
		name    string
		req     adoptAccountRequest
		wantSub string
	}{
		{
			name:    "unknown mode",
			req:     adoptAccountRequest{Mode: "takeover"},
			wantSub: "mode must be",
		},
		{
			name:    "empty mode",
			req:     adoptAccountRequest{},
			wantSub: "mode must be",
		},
		{
			name:    "set_password mode without password",
			req:     adoptAccountRequest{Mode: adoptModeSetPassword},
			wantSub: "password is required",
		},
		{
			name:    "verify_password mode without password",
			req:     adoptAccountRequest{Mode: adoptModeVerifyPassword},
			wantSub: "password is required",
		},
		{
			name:    "legacy password mode without password",
			req:     adoptAccountRequest{Mode: adoptModeLegacyPassword},
			wantSub: "password is required",
		},
		{
			name:    "metadata mode with password",
			req:     adoptAccountRequest{Mode: adoptModeMetadata, Password: "x"},
			wantSub: "must not be set",
		},
		{
			name:    "generate mode with password",
			req:     adoptAccountRequest{Mode: adoptModeGenerate, Password: "x"},
			wantSub: "must not be set",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.req.validate()
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not contain %q", err, tc.wantSub)
			}
		})
	}
}
