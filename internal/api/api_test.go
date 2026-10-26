package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/principals"
)

// validCreateRequest возвращает валидное тело создания connection;
// тесты портят отдельные поля.
func validCreateRequest() createConnectionRequest {
	return createConnectionRequest{
		DisplayName: "target (dev)",
		Engine:      "postgres",
		Environment: "dev",
		Endpoints:   []string{"target-postgres:5432"},
		AdminCredential: &adminCredentialRequest{
			Username: "grantor_admin",
			Password: "secret-value",
		},
	}
}

func TestCreateConnectionRequestValidate(t *testing.T) {
	engines := []string{"postgres"}

	if err := func() error {
		req := validCreateRequest()
		return req.validate(engines)
	}(); err != nil {
		t.Fatalf("valid request: unexpected error: %v", err)
	}

	// Оба явных режима исполнения валидны; пустое значение (дефолт direct)
	// покрыто validCreateRequest выше.
	for _, mode := range []string{"direct", "connector"} {
		req := validCreateRequest()
		req.ExecutionMode = mode
		if err := req.validate(engines); err != nil {
			t.Errorf("execution_mode %q: unexpected error: %v", mode, err)
		}
	}

	cases := []struct {
		name    string
		mutate  func(*createConnectionRequest)
		wantSub string
	}{
		{
			name:    "empty display name",
			mutate:  func(r *createConnectionRequest) { r.DisplayName = "  " },
			wantSub: "display_name",
		},
		{
			name:    "empty engine",
			mutate:  func(r *createConnectionRequest) { r.Engine = "" },
			wantSub: "engine is required",
		},
		{
			name:    "unknown execution mode",
			mutate:  func(r *createConnectionRequest) { r.ExecutionMode = "tunnel" },
			wantSub: "execution_mode",
		},
		{
			name:    "unknown engine",
			mutate:  func(r *createConnectionRequest) { r.Engine = "mongodb" },
			wantSub: "unknown engine",
		},
		{
			name:    "no endpoints",
			mutate:  func(r *createConnectionRequest) { r.Endpoints = nil },
			wantSub: "endpoints",
		},
		{
			name:    "empty endpoint value",
			mutate:  func(r *createConnectionRequest) { r.Endpoints = []string{"host:5432", ""} },
			wantSub: "empty",
		},
		{
			name:    "missing credential",
			mutate:  func(r *createConnectionRequest) { r.AdminCredential = nil },
			wantSub: "admin_credential is required",
		},
		{
			name:    "empty username",
			mutate:  func(r *createConnectionRequest) { r.AdminCredential.Username = "" },
			wantSub: "admin_credential.username",
		},
		{
			name:    "empty password",
			mutate:  func(r *createConnectionRequest) { r.AdminCredential.Password = "" },
			wantSub: "admin_credential.password",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := validCreateRequest()
			tc.mutate(&req)
			err := req.validate(engines)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not contain %q", err, tc.wantSub)
			}
		})
	}
}

func TestValidateEndpoint(t *testing.T) {
	valid := []string{
		"target-postgres",
		"target-postgres:5432",
		"10.0.0.1:5432",
		"[::1]:5432",
		"db.internal.example.com:65535",
	}
	for _, ep := range valid {
		if err := validateEndpoint(ep); err != nil {
			t.Errorf("validateEndpoint(%q): unexpected error: %v", ep, err)
		}
	}

	invalid := []string{
		"",
		" ",
		"host name:5432",
		"host:",
		"host:0",
		"host:70000",
		"host:port",
		":5432",
		"::1",
	}
	for _, ep := range invalid {
		if err := validateEndpoint(ep); err == nil {
			t.Errorf("validateEndpoint(%q): expected error", ep)
		}
	}
}

func TestRefreshTransitions(t *testing.T) {
	cases := []struct {
		from    connections.Status
		want    []connections.Status
		wantErr bool
	}{
		{from: connections.StatusDraft, want: []connections.Status{connections.StatusValidating, connections.StatusDiscovering}},
		{from: connections.StatusConnectionFailed, want: []connections.Status{connections.StatusValidating, connections.StatusDiscovering}},
		{from: connections.StatusValidating, want: []connections.Status{connections.StatusDiscovering}},
		{from: connections.StatusDiscoveryFailed, want: []connections.Status{connections.StatusDiscovering}},
		{from: connections.StatusDiscovering, want: nil},
		{from: connections.StatusActive, want: nil},
		{from: connections.StatusDegraded, want: nil},
		{from: connections.StatusDisabled, wantErr: true},
		{from: connections.Status("ghost"), wantErr: true},
	}
	for _, tc := range cases {
		chain, err := refreshTransitions(tc.from)
		if tc.wantErr {
			if err == nil {
				t.Errorf("refreshTransitions(%q): expected error", tc.from)
			}
			continue
		}
		if err != nil {
			t.Errorf("refreshTransitions(%q): unexpected error: %v", tc.from, err)
			continue
		}
		if len(chain) != len(tc.want) {
			t.Errorf("refreshTransitions(%q) = %v, want %v", tc.from, chain, tc.want)
			continue
		}
		for i := range chain {
			if chain[i] != tc.want[i] {
				t.Errorf("refreshTransitions(%q)[%d] = %q, want %q", tc.from, i, chain[i], tc.want[i])
			}
		}
		// Каждая цепочка обязана быть валидной по карте переходов.
		from := tc.from
		for _, to := range chain {
			if !connections.CanTransition(from, to) {
				t.Errorf("refreshTransitions(%q): step %q -> %q is not allowed by transition map", tc.from, from, to)
			}
			from = to
		}
	}
}

func TestRefreshOperationKey(t *testing.T) {
	id := uuid.New()
	base := time.Date(2026, 7, 17, 12, 30, 5, 0, time.UTC)

	same := refreshOperationKey(id, base.Add(50*time.Second))
	if got := refreshOperationKey(id, base); got != same {
		t.Errorf("keys within one minute differ: %q vs %q", got, same)
	}
	if got := refreshOperationKey(id, base.Add(2*time.Minute)); got == same {
		t.Errorf("keys across minutes match: %q", got)
	}
	if other := refreshOperationKey(uuid.New(), base); other == same {
		t.Errorf("keys of different connections match: %q", other)
	}
	if !strings.HasPrefix(same, "discover:"+id.String()+":") {
		t.Errorf("unexpected key format: %q", same)
	}
}

func TestRespondJSONAndError(t *testing.T) {
	rec := httptest.NewRecorder()
	respondJSON(rec, http.StatusCreated, map[string]string{"k": "v"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusCreated)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if body["k"] != "v" {
		t.Fatalf("unexpected body: %v", body)
	}

	rec = httptest.NewRecorder()
	respondError(rec, http.StatusBadRequest, "boom")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if !strings.Contains(rec.Body.String(), `"error":"boom"`) {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}

func TestRespondStoreError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"connections not found", fmt.Errorf("wrap: %w", connections.ErrNotFound), http.StatusNotFound},
		{"operations not found", fmt.Errorf("wrap: %w", operations.ErrNotFound), http.StatusNotFound},
		{"inventory not found", fmt.Errorf("wrap: %w", inventory.ErrNotFound), http.StatusNotFound},
		{"principals not found", fmt.Errorf("wrap: %w", principals.ErrNotFound), http.StatusNotFound},
		{"inventory already exists", fmt.Errorf("wrap: %w", inventory.ErrAlreadyExists), http.StatusConflict},
		{"principals already exists", fmt.Errorf("wrap: %w", principals.ErrAlreadyExists), http.StatusConflict},
		{"binding already managed", fmt.Errorf("wrap: %w", inventory.ErrAlreadyManaged), http.StatusConflict},
		{"connections status conflict", fmt.Errorf("wrap: %w", connections.ErrStatusConflict), http.StatusConflict},
		{"operations status conflict", fmt.Errorf("wrap: %w", operations.ErrStatusConflict), http.StatusConflict},
		{"connections invalid transition", fmt.Errorf("wrap: %w", connections.ErrInvalidTransition), http.StatusConflict},
		{"operations invalid transition", fmt.Errorf("wrap: %w", operations.ErrInvalidTransition), http.StatusConflict},
		{"unknown error", errors.New("boom"), http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			respondStoreError(t.Context(), rec, tc.err)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
			if !strings.Contains(rec.Body.String(), `"error":`) {
				t.Fatalf("unexpected body: %s", rec.Body.String())
			}
			// Внутренние детали не протекают в 500-ответ.
			if tc.want == http.StatusInternalServerError && strings.Contains(rec.Body.String(), "boom") {
				t.Fatalf("internal error text leaked to response: %s", rec.Body.String())
			}
		})
	}
}

func TestQueryLimit(t *testing.T) {
	cases := []struct {
		name    string
		query   string // без ведущего "?"; пусто = параметр отсутствует
		def     int
		want    int
		wantErr bool
	}{
		{"absent -> default", "", 0, 0, false},
		{"within cap", "limit=100", 0, 100, false},
		{"at cap", "limit=500", 0, maxPageLimit, false},
		{"above cap -> capped", "limit=100000", 0, maxPageLimit, false},
		{"just above cap -> capped", "limit=501", 0, maxPageLimit, false},
		{"zero passthrough", "limit=0", 0, 0, false},
		{"negative passthrough", "limit=-5", 0, -5, false},
		{"non-numeric -> error", "limit=abc", 0, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := "/"
			if tc.query != "" {
				target += "?" + tc.query
			}
			req := httptest.NewRequest(http.MethodGet, target, nil)
			got, err := queryLimit(req, "limit", tc.def)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("queryLimit(%q) = %d, want error", tc.query, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("queryLimit(%q): %v", tc.query, err)
			}
			if got != tc.want {
				t.Errorf("queryLimit(%q) = %d, want %d", tc.query, got, tc.want)
			}
		})
	}
}

func TestDecodeJSON(t *testing.T) {
	type payload struct {
		Name string `json:"name"`
	}

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"ok"}`))
	rec := httptest.NewRecorder()
	var p payload
	if !decodeJSON(rec, req, &p) {
		t.Fatalf("decodeJSON(valid) = false; body: %s", rec.Body.String())
	}
	if p.Name != "ok" {
		t.Fatalf("decoded name = %q, want ok", p.Name)
	}

	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":`))
	rec = httptest.NewRecorder()
	if decodeJSON(rec, req, &p) {
		t.Fatal("decodeJSON(malformed) = true, want false")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestPathUUID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	want := uuid.New()
	req.SetPathValue("id", want.String())
	rec := httptest.NewRecorder()
	got, ok := pathUUID(rec, req, "id")
	if !ok || got != want {
		t.Fatalf("pathUUID(valid) = (%v, %v), want (%v, true)", got, ok, want)
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetPathValue("id", "not-a-uuid")
	rec = httptest.NewRecorder()
	if _, ok := pathUUID(rec, req, "id"); ok {
		t.Fatal("pathUUID(invalid) ok = true, want false")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestQueryHelpers(t *testing.T) {
	id := uuid.New()
	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/?limit=10&connection_id=%s", id), nil)

	limit, err := queryInt(req, "limit", 0)
	if err != nil || limit != 10 {
		t.Fatalf("queryInt(limit) = (%d, %v), want (10, nil)", limit, err)
	}
	offset, err := queryInt(req, "offset", 7)
	if err != nil || offset != 7 {
		t.Fatalf("queryInt(offset default) = (%d, %v), want (7, nil)", offset, err)
	}
	got, err := queryUUID(req, "connection_id")
	if err != nil || got == nil || *got != id {
		t.Fatalf("queryUUID(connection_id) = (%v, %v), want (%v, nil)", got, err, id)
	}
	missing, err := queryUUID(req, "account_id")
	if err != nil || missing != nil {
		t.Fatalf("queryUUID(missing) = (%v, %v), want (nil, nil)", missing, err)
	}

	req = httptest.NewRequest(http.MethodGet, "/?limit=abc&connection_id=zzz", nil)
	if _, err := queryInt(req, "limit", 0); err == nil {
		t.Fatal("queryInt(malformed): expected error")
	}
	if _, err := queryUUID(req, "connection_id"); err == nil {
		t.Fatal("queryUUID(malformed): expected error")
	}
}

func TestToConnectionJSONEmptySlicesAndDrift(t *testing.T) {
	conn := connections.Connection{ID: uuid.New(), DisplayName: "c", Engine: "postgres"}

	out := toConnectionJSON(conn, nil)
	if out.Tags == nil || out.Endpoints == nil || out.Capabilities == nil {
		t.Fatal("nil slices must be replaced with empty ones")
	}
	if string(out.TLSConfig) != "{}" || string(out.Topology) != "{}" {
		t.Fatalf("empty jsonb must serialize as {}: tls=%s topology=%s", out.TLSConfig, out.Topology)
	}
	if out.Drift != nil {
		t.Fatal("drift must be nil when not requested")
	}

	drift := inventory.DriftCounters{UnmanagedBindings: 1, DriftBindings: 2, MissingManagedResources: 3}
	out = toConnectionJSON(conn, &drift)
	if out.Drift == nil || out.Drift.UnmanagedBindings != 1 ||
		out.Drift.DriftBindings != 2 || out.Drift.MissingManagedResources != 3 {
		t.Fatalf("unexpected drift: %+v", out.Drift)
	}
}

func TestPostgresConnectionProjectionDropsStaleCreationCapabilities(t *testing.T) {
	stale := connections.Connection{
		ID: uuid.New(), Engine: "postgres", Status: connections.StatusActive,
		Capabilities: []string{
			string(adapter.CapInventoryAccounts),
			string(adapter.CapAccessGrant),
			string(adapter.CapAccountCreate),
			string(adapter.CapAccountRestore),
			string(adapter.CapRoleCreate),
			string(adapter.ResourceCapability("create", resourceKindDatabase)),
			string(adapter.CapRolePolicyApply),
			string(adapter.CapRolePolicyCreate),
			string(adapter.CapPostgresSuperuserDirectV1),
		},
	}
	got := toConnectionJSON(stale, nil).Capabilities
	for _, forbidden := range stale.Capabilities[2:] {
		if slices.Contains(got, forbidden) {
			t.Errorf("stale PostgreSQL capability %q remained in API projection: %v", forbidden, got)
		}
	}
	for _, retained := range stale.Capabilities[:2] {
		if !slices.Contains(got, retained) {
			t.Errorf("inventory/access capability %q disappeared from API projection: %v", retained, got)
		}
	}
}

func TestPostgresProvisioningAuthorityProjection(t *testing.T) {
	observedAt := time.Date(2026, 8, 27, 9, 30, 0, 123, time.UTC)
	conn := connections.Connection{ID: uuid.New(), Engine: "postgres", Status: connections.StatusActive,
		Endpoints: []string{"db:5432"}, AdminCredentialMode: "provided", VaultAdminPath: "connections/c/admin"}
	conn.LastDiscoveryAt = &observedAt
	assessment := adapter.ProvisioningAuthorityAssessment{
		Status: adapter.ProvisioningAuthorityConfirmed, Reason: adapter.ProvisioningAuthoritySuperuserConfirmed,
		ObservedAt: observedAt, ExpectedAdminIdentity: "grantor", ObservedAdminIdentity: "grantor",
		CredentialIncarnation: 4, ConfigIncarnation: connections.ConfigIncarnation(conn),
		TargetIdentity: "postgres:system:123",
	}
	topology, err := json.Marshal(map[string]any{
		adapter.PostgresProvisioningAuthorityTopologyKey: assessment,
		"admin_credential_canonical_identity":            "grantor",
	})
	if err != nil {
		t.Fatal(err)
	}
	conn.Topology = topology
	got := toConnectionJSON(conn, nil).PostgresProvisioningAuthority
	if got == nil || *got != assessment {
		t.Fatalf("authority projection = %+v", got)
	}

	staleDiscovery := observedAt.Add(-time.Minute)
	conn.LastDiscoveryAt = &staleDiscovery
	got = toConnectionJSON(conn, nil).PostgresProvisioningAuthority
	if got.Status != adapter.ProvisioningAuthorityInvalidCurrentVersion ||
		got.Reason != adapter.ProvisioningAuthorityConnectionSnapshotNotActive {
		t.Fatalf("other discovery snapshot remained current: %+v", got)
	}
	conn.LastDiscoveryAt = &observedAt

	conn.Status = connections.StatusDiscovering
	got = toConnectionJSON(conn, nil).PostgresProvisioningAuthority
	if got.Status != adapter.ProvisioningAuthorityInvalidCurrentVersion ||
		got.Reason != adapter.ProvisioningAuthorityConnectionSnapshotNotActive {
		t.Fatalf("stale authority projection = %+v", got)
	}
	if got := toConnectionJSON(connections.Connection{Engine: "postgres"}, nil).PostgresProvisioningAuthority; got == nil || got.Status != adapter.ProvisioningAuthorityUnknown {
		t.Fatalf("missing authority projection = %+v", got)
	}
	if got := toConnectionJSON(connections.Connection{Engine: "mongodb"}, nil).PostgresProvisioningAuthority; got != nil {
		t.Fatalf("non-postgres authority projection = %+v, want nil", got)
	}
}

func TestPostgresProvisioningAuthorityProjectionRejectsMalformedTopology(t *testing.T) {
	observedAt := time.Date(2026, 8, 27, 9, 30, 0, 0, time.UTC)
	conn := connections.Connection{ID: uuid.New(), Engine: "postgres", Status: connections.StatusActive,
		Endpoints: []string{"db:5432"}, AdminCredentialMode: "provided", VaultAdminPath: "connections/c/admin",
		LastDiscoveryAt: &observedAt}
	base := adapter.ProvisioningAuthorityAssessment{
		Status: adapter.ProvisioningAuthorityConfirmed, Reason: adapter.ProvisioningAuthoritySuperuserConfirmed,
		ObservedAt: observedAt, ExpectedAdminIdentity: "grantor", ObservedAdminIdentity: "grantor",
		CredentialIncarnation: 4, ConfigIncarnation: connections.ConfigIncarnation(conn),
		TargetIdentity: "postgres:system:123",
	}
	for name, rawAssessment := range map[string]any{
		"unknown reason": map[string]any{
			"status": "confirmed", "reason": "future", "observed_at": observedAt,
		},
		"zero credential incarnation": func() adapter.ProvisioningAuthorityAssessment {
			malformed := base
			malformed.CredentialIncarnation = 0
			return malformed
		}(),
		"malformed config incarnation": func() adapter.ProvisioningAuthorityAssessment {
			malformed := base
			malformed.ConfigIncarnation = "not-a-sha256"
			return malformed
		}(),
		"missing target identity": func() adapter.ProvisioningAuthorityAssessment {
			malformed := base
			malformed.TargetIdentity = ""
			return malformed
		}(),
		"unknown field": map[string]any{
			"status": "confirmed", "reason": "superuser_confirmed", "observed_at": observedAt,
			"expected_admin_identity": "grantor", "observed_admin_identity": "grantor",
			"credential_incarnation": 4, "config_incarnation": connections.ConfigIncarnation(conn),
			"target_identity": "postgres:system:123", "raw_sql": "select 1",
		},
	} {
		t.Run(name, func(t *testing.T) {
			topology, err := json.Marshal(map[string]any{
				adapter.PostgresProvisioningAuthorityTopologyKey: rawAssessment,
				"admin_credential_canonical_identity":            "grantor",
			})
			if err != nil {
				t.Fatal(err)
			}
			conn.Topology = topology
			got := toConnectionJSON(conn, nil).PostgresProvisioningAuthority
			if got == nil || got.Status != adapter.ProvisioningAuthorityUnknown ||
				got.Reason != adapter.ProvisioningAuthorityProbeFailed {
				t.Fatalf("malformed authority projection = %+v", got)
			}
		})
	}
}
