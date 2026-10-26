package rabbitmq

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adaptertest"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
	"github.com/ArtefactoO/grantor/internal/rabbitmqconfig"
)

func testPermissionTemplate() rabbitmqconfig.PermissionTemplate {
	return rabbitmqconfig.PermissionTemplate{
		Key: "etl-worker", Name: "ETL worker", Description: "ETL queues only",
		Vhost: "app", Configure: `^(status_changes|match_updates)$`,
		Write: `^match_updates$`, Read: `^(status_changes|match_updates)$`,
	}
}

func connectionWithTemplates(endpoint string, templates ...rabbitmqconfig.PermissionTemplate) adapter.Connection {
	return adapter.Connection{
		Engine: Engine, Endpoints: []string{endpoint},
		AdminCredential: adapter.Credential{Kind: "password", Username: "admin", Secret: []byte("admin-password")},
		Attributes:      map[string]any{rabbitmqconfig.AttributePermissionTemplates: templates},
	}
}

func TestManifest(t *testing.T) {
	m := New().Manifest()
	if m.Engine != Engine {
		t.Errorf("engine = %q, want %q", m.Engine, Engine)
	}
	if m.Version == "" || m.ConnectionSchema == "" {
		t.Error("manifest must set Version and ConnectionSchema")
	}
	for _, want := range []adapter.Capability{
		adapter.CapInventoryResources, adapter.CapInventoryAccounts,
		adapter.CapInventoryPermissions, adapter.CapInventoryBindings,
		adapter.CapAccessGrant, adapter.CapAccessRevoke,
		adapter.CapAccountCreate, adapter.CapAccountDisable,
		adapter.CapAccountEnable, adapter.CapAccountDelete,
		adapter.CapCredentialRotate, adapter.CapCredentialProve,
	} {
		if !m.HasCapability(want) {
			t.Errorf("manifest must declare %q", want)
		}
	}
	if !slices.Contains(m.ResourceKinds, "vhost") {
		t.Errorf("manifest must declare vhost resource kind, got %v", m.ResourceKinds)
	}
	// Инвариант: disable снимает саму авторизацию (permissions удаляются,
	// теги заменяются маркером). Ядро полагается на это заявление, чтобы не
	// считать bindings отключённого аккаунта synced и чтобы вернуть права
	// после enable. Молчаливая потеря заявления вернула бы аккаунт без прав.
	if m.AccountDisableEffect != adapter.DisableClearsAccess || !m.DisableClearsAccess() {
		t.Errorf("manifest account disable effect = %q, want %q",
			m.AccountDisableEffect, adapter.DisableClearsAccess)
	}
}

func TestProveCredential(t *testing.T) {
	const (
		identity = "service-user"
		password = "correct-password"
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != identity || pass != password {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(apiWhoami{Name: identity})
	}))
	defer server.Close()

	cfg := adapter.Connection{Endpoints: []string{server.Listener.Addr().String()}}
	account := adapter.Account{Kind: "login", EngineIdentity: identity}
	ad := New()
	if err := ad.ProveCredential(t.Context(), cfg, account, adapter.Credential{Kind: "password", Secret: []byte(password)}); err != nil {
		t.Fatalf("ProveCredential: %v", err)
	}

	wrong := "not-the-password"
	err := ad.ProveCredential(t.Context(), cfg, account, adapter.Credential{Kind: "password", Secret: []byte(wrong)})
	if !errors.Is(err, adapter.ErrExternalIdentityConflict) {
		t.Errorf("wrong password error = %v, want ErrExternalIdentityConflict", err)
	}
	if strings.Contains(fmt.Sprint(err), wrong) {
		t.Error("proof error must not contain the supplied password")
	}
}

func TestProveCredentialFailsClosed(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    error
	}{
		{
			name: "unrelated password accepted",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(apiWhoami{Name: "service-user"})
			},
			want: adapter.ErrCredentialProofUnsupported,
		},
		{
			name: "another identity",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(apiWhoami{Name: "proxy-user"})
			},
			want: adapter.ErrExternalIdentityConflict,
		},
		{
			// 403 без маркера «не хватает management-тега» — отказ
			// аутентификации, а не неоднозначный ответ.
			name: "forbidden without the management marker",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusForbidden)
			},
			want: adapter.ErrExternalIdentityConflict,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()
			cfg := adapter.Connection{Endpoints: []string{server.Listener.Addr().String()}}
			err := New().ProveCredential(t.Context(), cfg,
				adapter.Account{Kind: "login", EngineIdentity: "service-user"},
				adapter.Credential{Kind: "password", Secret: []byte("correct-password")})
			if !errors.Is(err, tt.want) {
				t.Errorf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestProveCredentialServerErrorStaysRetryable фиксирует границу
// классификации: 5xx Management API — недоступность target, а не отказ
// пароля и не «доказать невозможно». Иначе временная авария брокера
// превращалась бы в терминальный identity conflict.
func TestProveCredentialServerErrorStaysRetryable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	err := New().ProveCredential(t.Context(),
		adapter.Connection{Endpoints: []string{server.Listener.Addr().String()}},
		adapter.Account{Kind: "login", EngineIdentity: "service-user"},
		adapter.Credential{Kind: "password", Secret: []byte("correct-password")})
	if err == nil {
		t.Fatal("server error must not be reported as a successful proof")
	}
	if errors.Is(err, adapter.ErrExternalIdentityConflict) ||
		errors.Is(err, adapter.ErrCredentialProofUnsupported) {
		t.Errorf("error = %v, want a plain retryable failure", err)
	}
}

func TestParsePermission(t *testing.T) {
	tests := []struct {
		in      string
		kind    string
		value   string
		wantErr bool
	}{
		{in: "tag:administrator", kind: permKindTag, value: "administrator"},
		{in: "tag:management", kind: permKindTag, value: "management"},
		{in: "vhost-access:app", kind: permKindVhost, value: "app"},
		{in: "vhost-access:/", kind: permKindVhost, value: "/"},
		{in: "vhost-access:my/vhost", kind: permKindVhost, value: "my/vhost"},
		{in: "administrator", wantErr: true},
		{in: "tag:", wantErr: true},
		{in: "vhost-access:", wantErr: true},
		{in: "role:x", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, tt := range tests {
		kind, value, err := parsePermission(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parsePermission(%q): expected error", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parsePermission(%q): %v", tt.in, err)
			continue
		}
		if kind != tt.kind || value != tt.value {
			t.Errorf("parsePermission(%q) = (%q, %q), want (%q, %q)", tt.in, kind, value, tt.kind, tt.value)
		}
	}
}

func TestParseTags(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{name: "array", in: `["administrator","management"]`, want: []string{"administrator", "management"}},
		{name: "comma string", in: `"administrator,monitoring"`, want: []string{"administrator", "monitoring"}},
		{name: "comma string with spaces", in: `"administrator, management "`, want: []string{"administrator", "management"}},
		{name: "empty array", in: `[]`, want: []string{}},
		{name: "empty string", in: `""`, want: []string{}},
		{name: "null", in: `null`, want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseTags(json.RawMessage(tt.in))
			if !slices.Equal(got, tt.want) {
				t.Errorf("parseTags(%s) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestDangerousTag(t *testing.T) {
	if !dangerousTag(tagAdministrator) {
		t.Error("administrator tag must be dangerous")
	}
	for _, tag := range []string{tagManagement, tagMonitoring, tagPolicymaker, "custom", ""} {
		if dangerousTag(tag) {
			t.Errorf("tag %q must not be dangerous", tag)
		}
	}
}

func TestIsBroadConfigure(t *testing.T) {
	if !isBroadConfigure(".*") {
		t.Error(`configure ".*" must be broad`)
	}
	for _, c := range []string{"", "^app-.*$", "amq\\.gen-.*", "specific-queue"} {
		if isBroadConfigure(c) {
			t.Errorf("configure %q must not be broad", c)
		}
	}
}

func TestBuildPermissions(t *testing.T) {
	perms := buildPermissions([]apiVhost{{Name: "/"}, {Name: "app"}})
	byID := map[string]adapter.ObservedPermission{}
	for _, p := range perms {
		if !p.Assignable {
			t.Errorf("permission %q must be assignable", p.ExternalID)
		}
		byID[p.ExternalID] = p
	}
	if len(perms) != len(knownTags)+4 {
		t.Errorf("permission count = %d, want %d", len(perms), len(knownTags)+4)
	}

	admin, ok := byID["tag:administrator"]
	if !ok || !admin.Dangerous {
		t.Error("tag:administrator must exist and be dangerous")
	}
	if admin.ScopeExternalID != "" {
		t.Errorf("tag permission scope = %q, want cluster-wide (empty)", admin.ScopeExternalID)
	}
	if mgmt, ok := byID["tag:management"]; !ok || mgmt.Dangerous {
		t.Error("tag:management must exist and be non-dangerous")
	}

	root, ok := byID["vhost-access:/"]
	if !ok {
		t.Fatal("vhost-access:/ must exist")
	}
	// Полный доступ внутри одного vhost — базовый рабочий доступ, а не
	// эскалация: пока признак был константой true, роль operator не могла
	// выдать ни один доступ к vhost (см. buildPermissions).
	if root.Dangerous {
		t.Error("vhost-access permission must not be dangerous: it is the engine's basic scenario")
	}
	if root.ScopeExternalID != "vhost:/" {
		t.Errorf("vhost-access:/ scope = %q, want vhost:/", root.ScopeExternalID)
	}

	// Должно быть минимум две assignable не-dangerous permissions (для
	// grant/revoke contract-теста).
	nonDangerous := 0
	for _, p := range perms {
		if p.Assignable && !p.Dangerous {
			nonDangerous++
		}
	}
	if nonDangerous < 2 {
		t.Errorf("expected at least two assignable non-dangerous permissions, got %d", nonDangerous)
	}
}

func TestTemplatePermissionsAndBindingMatching(t *testing.T) {
	template := testPermissionTemplate()
	perms := buildPermissions([]apiVhost{{Name: "app"}, {Name: "other"}}, []rabbitmqconfig.PermissionTemplate{template})
	byID := make(map[string]adapter.ObservedPermission, len(perms))
	for _, permission := range perms {
		byID[permission.ExternalID] = permission
	}
	legacy := byID["vhost-access:app"]
	configured := byID["rabbitmq-template:etl-worker"]
	if legacy.AssignmentKey != "rabbitmq:vhost:app" || configured.AssignmentKey != legacy.AssignmentKey {
		t.Fatalf("assignment keys legacy=%q template=%q", legacy.AssignmentKey, configured.AssignmentKey)
	}
	if configured.Name != "ETL worker" || configured.Dangerous || configured.Attributes["description"] != "ETL queues only" {
		t.Fatalf("template permission = %+v", configured)
	}
	if legacy.Attributes["broad"] != true || configured.Attributes["broad"] != false {
		t.Fatalf("broad attributes legacy=%v template=%v", legacy.Attributes["broad"], configured.Attributes["broad"])
	}
	broad := template
	broad.Key, broad.Name, broad.Write = "broad-write", "Broad write", ".*"
	broadPermission := buildPermissions([]apiVhost{{Name: "app"}}, []rabbitmqconfig.PermissionTemplate{broad})
	for _, permission := range broadPermission {
		if permission.ExternalID == templatePermissionID(broad.Key) {
			if permission.Attributes["broad"] != true || permission.Dangerous {
				t.Fatalf("server-computed broad template = %+v", permission)
			}
		}
	}

	exact := vhostBinding(apiPermission{
		User: "svc", Vhost: "app", Configure: template.Configure,
		Write: template.Write, Read: template.Read,
	}, []rabbitmqconfig.PermissionTemplate{template})
	if exact.PermissionExternalID != "rabbitmq-template:etl-worker" || exact.AssignmentKey != "rabbitmq:vhost:app" {
		t.Fatalf("exact binding = %+v", exact)
	}
	if exact.Attributes["template_matched"] != true || exact.Attributes[adapter.AttrBindingEffective] != true {
		t.Fatalf("exact attributes = %+v", exact.Attributes)
	}

	unknown := vhostBinding(apiPermission{
		User: "svc", Vhost: "app", Configure: "^unknown$", Write: "^unknown$", Read: "^unknown$",
	}, []rabbitmqconfig.PermissionTemplate{template})
	if unknown.PermissionExternalID != "vhost-access:app" || unknown.Attributes["template_matched"] != false ||
		unknown.Attributes[adapter.AttrBindingEffective] != false {
		t.Fatalf("unknown binding = %+v", unknown)
	}
}

func TestPlanTemplatePermission(t *testing.T) {
	template := testPermissionTemplate()
	change := adapter.DesiredChange{
		Kind: adapter.ChangeGrant, Connection: connectionWithTemplates("rabbit.example.com", template),
		Account: adapter.Account{EngineIdentity: "svc"}, Permission: templatePermissionID(template.Key),
		Scope: vhostExternalID(template.Vhost),
	}
	plan, err := New().Plan(t.Context(), change)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	step := plan.Steps[0]
	if step.Kind != stepGrantVhost || step.Attributes["template_key"] != template.Key ||
		step.Attributes["configure"] != template.Configure {
		t.Fatalf("template plan step = %+v", step)
	}

	change.Permission = templatePermissionID("not-configured")
	if _, err := New().Plan(t.Context(), change); !errors.Is(err, adapter.ErrUnsupportedChange) {
		t.Fatalf("Plan unknown template error = %v, want ErrUnsupportedChange", err)
	}
}

func TestPinnedTemplateWinsOverChangedConnectionCatalog(t *testing.T) {
	original := testPermissionTemplate()
	changed := original
	changed.Configure, changed.Write, changed.Read = "^new$", "^new$", "^new$"
	change := adapter.DesiredChange{
		Kind: adapter.ChangeGrant, Connection: connectionWithTemplates("rabbit.example.com", changed),
		Account: adapter.Account{EngineIdentity: "svc"}, Permission: templatePermissionID(original.Key),
		Attributes: map[string]any{
			"template_key": original.Key, "vhost": original.Vhost,
			"configure": original.Configure, "write": original.Write, "read": original.Read,
		},
	}
	plan, err := New().Plan(t.Context(), change)
	if err != nil {
		t.Fatalf("Plan pinned template: %v", err)
	}
	if got := plan.Steps[0].Attributes["configure"]; got != original.Configure {
		t.Fatalf("Plan configure = %v, want pinned %q instead of current catalog", got, original.Configure)
	}

	change.Attributes["template_key"] = "another-key"
	if _, err := New().Plan(t.Context(), change); err == nil {
		t.Fatal("mismatched pinned key must fail")
	}
	change.Attributes["template_key"] = original.Key
	change.Attributes["read"] = "("
	if _, err := New().Plan(t.Context(), change); err == nil {
		t.Fatal("invalid pinned regex must fail")
	}
}

func TestTemplateApplyVerifyUsesExactTupleAndSafeRevoke(t *testing.T) {
	template := testPermissionTemplate()
	var current *apiPermission
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/users/svc":
			_ = json.NewEncoder(w).Encode(apiUser{Name: "svc", Tags: json.RawMessage(`[]`)})
		case r.Method == http.MethodGet && r.URL.Path == "/api/permissions/app/svc":
			if current == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(current)
		case r.Method == http.MethodPut && r.URL.Path == "/api/permissions/app/svc":
			var payload permissionPayload
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("decode permission payload: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			current = &apiPermission{User: "svc", Vhost: "app", Configure: payload.Configure, Write: payload.Write, Read: payload.Read}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/permissions/app/svc":
			current = nil
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := connectionWithTemplates(server.Listener.Addr().String(), template)
	change := adapter.DesiredChange{
		Kind: adapter.ChangeGrant, Connection: cfg,
		Account: adapter.Account{EngineIdentity: "svc"}, Permission: templatePermissionID(template.Key),
	}
	adaptertest.PlanApplyVerify(t.Context(), t, New(), change)
	if current == nil || !tupleMatches(*current, templateTuple(template)) {
		t.Fatalf("applied tuple = %+v", current)
	}
	adaptertest.PlanApplyVerify(t.Context(), t, New(), change) // exact retry is skipped

	// Revoke means the assignment slot must be empty even when discovery found
	// an unknown/drifted tuple instead of the selected template.
	current = &apiPermission{User: "svc", Vhost: "app", Configure: "^other$", Write: "^other$", Read: "^other$"}
	change.Kind = adapter.ChangeRevoke
	adaptertest.PlanApplyVerify(t.Context(), t, New(), change)
	if current != nil {
		t.Fatalf("template revoke left assignment slot occupied: %+v", current)
	}
}

func TestTopologyFromNodes(t *testing.T) {
	t.Run("standalone", func(t *testing.T) {
		var nodes []apiNode
		if err := json.Unmarshal([]byte(`[{"name":"rabbit@node1","running":true,"type":"disc"}]`), &nodes); err != nil {
			t.Fatalf("unmarshal nodes: %v", err)
		}
		topo := topologyFromNodes(nodes, apiOverview{ClusterName: "rabbit@node1"})
		if topo["topology"] != "standalone" {
			t.Errorf("topology = %v, want standalone", topo["topology"])
		}
		if topo["node_count"] != 1 {
			t.Errorf("node_count = %v, want 1", topo["node_count"])
		}
		if topo["cluster_name"] != "rabbit@node1" {
			t.Errorf("cluster_name = %v, want rabbit@node1", topo["cluster_name"])
		}
	})

	t.Run("cluster", func(t *testing.T) {
		var nodes []apiNode
		if err := json.Unmarshal([]byte(`[
			{"name":"rabbit@b","running":true,"type":"disc"},
			{"name":"rabbit@a","running":true,"type":"disc"},
			{"name":"rabbit@c","running":false,"type":"disc"}
		]`), &nodes); err != nil {
			t.Fatalf("unmarshal nodes: %v", err)
		}
		topo := topologyFromNodes(nodes, apiOverview{ClusterName: "rabbit@a"})
		if topo["topology"] != "cluster" {
			t.Errorf("topology = %v, want cluster", topo["topology"])
		}
		if topo["node_count"] != 3 {
			t.Errorf("node_count = %v, want 3", topo["node_count"])
		}
		if topo["running_nodes"] != 2 {
			t.Errorf("running_nodes = %v, want 2", topo["running_nodes"])
		}
		names, ok := topo["nodes"].([]string)
		if !ok || !slices.Equal(names, []string{"rabbit@a", "rabbit@b", "rabbit@c"}) {
			t.Errorf("nodes = %v, want sorted [rabbit@a rabbit@b rabbit@c]", topo["nodes"])
		}
	})

	t.Run("empty", func(t *testing.T) {
		topo := topologyFromNodes(nil, apiOverview{})
		if topo["topology"] != "standalone" {
			t.Errorf("topology = %v, want standalone for empty nodes", topo["topology"])
		}
	})
}

func TestUserToObserved(t *testing.T) {
	t.Run("functional tags and bindings", func(t *testing.T) {
		acc, bindings := userToObserved(apiUser{Name: "svc", Tags: json.RawMessage(`["monitoring","management","custom"]`)})
		if acc.Kind != "login" || acc.EngineIdentity != "svc" {
			t.Errorf("account = %+v, want login svc", acc)
		}
		if acc.Disabled {
			t.Error("account must not be disabled")
		}
		tags, _ := acc.Attributes["tags"].([]string)
		if !slices.Equal(tags, []string{"management", "monitoring"}) {
			t.Errorf("functional tags = %v, want [management monitoring] (custom dropped)", tags)
		}
		perms := bindingPermissions(bindings)
		if !slices.Equal(perms, []string{"tag:management", "tag:monitoring"}) {
			t.Errorf("binding permissions = %v, want [tag:management tag:monitoring]", perms)
		}
	})

	t.Run("disabled marker", func(t *testing.T) {
		acc, bindings := userToObserved(apiUser{Name: "off", Tags: json.RawMessage(`["grantor_disabled"]`)})
		if !acc.Disabled {
			t.Error("account with marker tag must be disabled")
		}
		if len(bindings) != 0 {
			t.Errorf("disabled user must have no tag bindings, got %v", bindings)
		}
	})

	t.Run("comma-string tags", func(t *testing.T) {
		acc, bindings := userToObserved(apiUser{Name: "adm", Tags: json.RawMessage(`"administrator,management"`)})
		if acc.Disabled {
			t.Error("account must not be disabled")
		}
		perms := bindingPermissions(bindings)
		if !slices.Equal(perms, []string{"tag:administrator", "tag:management"}) {
			t.Errorf("binding permissions = %v, want [tag:administrator tag:management]", perms)
		}
	})
}

func bindingPermissions(bindings []adapter.ObservedBinding) []string {
	out := make([]string, 0, len(bindings))
	for _, b := range bindings {
		out = append(out, b.PermissionExternalID)
	}
	slices.Sort(out)
	return out
}

func TestExternalIDs(t *testing.T) {
	if got := vhostExternalID("app"); got != "vhost:app" {
		t.Errorf("vhostExternalID = %q, want vhost:app", got)
	}
	if got := tagPermissionID("management"); got != "tag:management" {
		t.Errorf("tagPermissionID = %q, want tag:management", got)
	}
	if got := vhostPermissionID("app"); got != "vhost-access:app" {
		t.Errorf("vhostPermissionID = %q, want vhost-access:app", got)
	}
}

func TestFingerprintDeterminism(t *testing.T) {
	attrs := map[string]any{"description": "app vhost", "default_queue_type": "quorum"}
	same := map[string]any{"default_queue_type": "quorum", "description": "app vhost"}
	a := fingerprint("vhost", "vhost:app", attrs)
	b := fingerprint("vhost", "vhost:app", same)
	if a != b {
		t.Errorf("fingerprints for identical content differ: %q vs %q", a, b)
	}
	if len(a) != 16 {
		t.Errorf("fingerprint length = %d, want 16", len(a))
	}
	if fingerprint("vhost", "vhost:other", attrs) == a {
		t.Error("fingerprint must change when external id changes")
	}
	if fingerprint("vhost", "vhost:app", map[string]any{"description": "changed"}) == a {
		t.Error("fingerprint must change when attributes change")
	}
	if fingerprint("vhost", "vhost:x", nil) != fingerprint("vhost", "vhost:x", map[string]any{}) {
		t.Error("nil and empty attributes must produce the same fingerprint")
	}
}

func TestTagSetHelpers(t *testing.T) {
	if got := withTag([]string{"a"}, "b"); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("withTag added wrong: %v", got)
	}
	if got := withTag([]string{"a", "b"}, "b"); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("withTag must be idempotent: %v", got)
	}
	if got := withoutTag([]string{"a", "b", "a"}, "a"); !slices.Equal(got, []string{"b"}) {
		t.Errorf("withoutTag removed wrong: %v", got)
	}
	if got := joinTags([]string{"monitoring", "administrator", "monitoring"}); got != "administrator,monitoring" {
		t.Errorf("joinTags = %q, want administrator,monitoring", got)
	}
	if joinTags(nil) != "" {
		t.Errorf("joinTags(nil) = %q, want empty", joinTags(nil))
	}
	if !isDisabledTagSet([]string{disabledMarkerTag}) {
		t.Error("single marker tag must be a disabled tag set")
	}
	for _, tags := range [][]string{{}, {"management"}, {disabledMarkerTag, "management"}} {
		if isDisabledTagSet(tags) {
			t.Errorf("%v must not be a disabled tag set", tags)
		}
	}
}

func TestIsFullAccess(t *testing.T) {
	if !isFullAccess(apiPermission{Configure: ".*", Write: ".*", Read: ".*"}) {
		t.Error("full regex triple must be full access")
	}
	if isFullAccess(apiPermission{Configure: ".*", Write: ".*", Read: ""}) {
		t.Error("partial triple must not be full access")
	}
}

func TestPlanAccessTagRedactsSecretAndParses(t *testing.T) {
	ad := New()
	const marker = "s3cr3t-marker"
	change := adapter.DesiredChange{
		Kind:       adapter.ChangeGrant,
		Account:    adapter.Account{Kind: "login", EngineIdentity: "svc"},
		Permission: "tag:management",
		Credential: &adapter.Credential{Kind: "password", Secret: []byte(marker)},
	}
	plan, err := ad.Plan(t.Context(), change)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Steps) != 1 || plan.Steps[0].Kind != stepGrantTag {
		t.Fatalf("unexpected plan steps: %+v", plan.Steps)
	}
	step := plan.Steps[0]
	if strings.Contains(step.Description, marker) {
		t.Errorf("plan description leaks secret: %q", step.Description)
	}
	if step.Attributes["user"] != "svc" || step.Attributes["tag"] != "management" {
		t.Errorf("plan attributes = %v, want user=svc tag=management", step.Attributes)
	}

	revoke := change
	revoke.Kind = adapter.ChangeRevoke
	rplan, err := ad.Plan(t.Context(), revoke)
	if err != nil {
		t.Fatalf("Plan(revoke): %v", err)
	}
	if rplan.Steps[0].Kind != stepRevokeTag {
		t.Errorf("revoke step kind = %q, want %q", rplan.Steps[0].Kind, stepRevokeTag)
	}
}

func TestPlanAccessVhost(t *testing.T) {
	ad := New()
	plan, err := ad.Plan(t.Context(), adapter.DesiredChange{
		Kind:       adapter.ChangeGrant,
		Account:    adapter.Account{Kind: "login", EngineIdentity: "svc"},
		Permission: "vhost-access:app",
		Scope:      "vhost:app",
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	step := plan.Steps[0]
	if step.Kind != stepGrantVhost {
		t.Errorf("step kind = %q, want %q", step.Kind, stepGrantVhost)
	}
	if step.Attributes["user"] != "svc" || step.Attributes["vhost"] != "app" {
		t.Errorf("plan attributes = %v, want user=svc vhost=app", step.Attributes)
	}
}

// TestPlanAccessRejectsForeignScope фиксирует радиус права: тег действует на
// весь кластер, vhost-permission — ровно на свой vhost. Молчаливое
// игнорирование scope записывало бы кластерный тег как ограниченный одним
// vhost, то есть control plane показывал бы радиус, которого нет.
func TestPlanAccessRejectsForeignScope(t *testing.T) {
	ad := New()
	acct := adapter.Account{Kind: "login", EngineIdentity: "svc"}
	for _, tc := range []struct {
		name       string
		permission string
		scope      string
	}{
		{"cluster tag scoped to vhost", "tag:management", "vhost:app"},
		{"vhost permission scoped to another vhost", "vhost-access:app", "vhost:other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, kind := range []adapter.ChangeKind{adapter.ChangeGrant, adapter.ChangeRevoke} {
				_, err := ad.Plan(t.Context(), adapter.DesiredChange{
					Kind: kind, Account: acct, Permission: tc.permission, Scope: tc.scope,
				})
				if !errors.Is(err, adapter.ErrUnsupportedChange) {
					t.Errorf("Plan(%s) error = %v, want adapter.ErrUnsupportedChange", kind, err)
				}
			}
		})
	}
}

// TestVhostBindingEffective фиксирует разницу между «право есть» и «право
// работает»: vhost-permission обещает полный доступ, поэтому суженные снаружи
// regex-ы означают drift, а не synced.
func TestVhostBindingEffective(t *testing.T) {
	for _, tc := range []struct {
		name string
		perm apiPermission
		want bool
	}{
		{"full access", apiPermission{User: "svc", Vhost: "app", Configure: ".*", Write: ".*", Read: ".*"}, true},
		{"narrowed configure", apiPermission{User: "svc", Vhost: "app", Configure: "^$", Write: ".*", Read: ".*"}, false},
		{"narrowed read", apiPermission{User: "svc", Vhost: "app", Configure: ".*", Write: ".*", Read: "^app-"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := vhostBinding(tc.perm)
			if got := b.Attributes[adapter.AttrBindingEffective]; got != tc.want {
				t.Errorf("effective = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPlanAccountCreateRequiresPassword(t *testing.T) {
	ad := New()
	_, err := ad.Plan(t.Context(), adapter.DesiredChange{
		Kind:    adapter.ChangeAccountCreate,
		Account: adapter.Account{Kind: "login", EngineIdentity: "svc"},
	})
	if err == nil {
		t.Error("account.create without password credential must fail")
	}

	// Форма плана проверяется без target: сам Plan обращается к RabbitMQ,
	// чтобы отказать в создании поверх существующего пользователя.
	const marker = "s3cr3t-marker"
	plan := accountCreatePlan(adapter.DesiredChange{
		Kind:       adapter.ChangeAccountCreate,
		Account:    adapter.Account{Kind: "login", EngineIdentity: "svc"},
		Credential: &adapter.Credential{Kind: "password", Secret: []byte(marker)},
	})
	step := plan.Steps[0]
	if step.Kind != stepCreateUser || step.Attributes["with_password"] != true {
		t.Errorf("unexpected create step: %+v", step)
	}
	if strings.Contains(step.Description, marker) {
		t.Errorf("plan description leaks secret: %q", step.Description)
	}
}

func TestPlanDisableEnable(t *testing.T) {
	ad := New()
	acct := adapter.Account{Kind: "login", EngineIdentity: "svc"}

	dis, err := ad.Plan(t.Context(), adapter.DesiredChange{Kind: adapter.ChangeAccountDisable, Account: acct})
	if err != nil {
		t.Fatalf("Plan(disable): %v", err)
	}
	if dis.Steps[0].Kind != stepDisableUser {
		t.Errorf("disable step kind = %q, want %q", dis.Steps[0].Kind, stepDisableUser)
	}
	if dis.Steps[0].Attributes["marker"] != disabledMarkerTag {
		t.Errorf("disable marker attribute = %v, want %q", dis.Steps[0].Attributes["marker"], disabledMarkerTag)
	}

	en, err := ad.Plan(t.Context(), adapter.DesiredChange{Kind: adapter.ChangeAccountEnable, Account: acct})
	if err != nil {
		t.Fatalf("Plan(enable): %v", err)
	}
	if en.Steps[0].Kind != stepEnableUser {
		t.Errorf("enable step kind = %q, want %q", en.Steps[0].Kind, stepEnableUser)
	}
}

func TestPlanUnsupportedChange(t *testing.T) {
	ad := New()
	_, err := ad.Plan(t.Context(), adapter.DesiredChange{
		Kind:    adapter.ChangeResourceCreate,
		Account: adapter.Account{EngineIdentity: "svc"},
	})
	if err == nil {
		t.Error("Plan(resource.create): expected unsupported change error")
	}

	_, err = ad.Plan(t.Context(), adapter.DesiredChange{
		Kind:       adapter.ChangeGrant,
		Account:    adapter.Account{EngineIdentity: "svc"},
		Permission: "role:bad",
	})
	if err == nil {
		t.Error("Plan(grant) with malformed permission must fail")
	}
}

func TestGenerateCredential(t *testing.T) {
	ad := New()
	cred, err := ad.GenerateCredential(t.Context(), adapter.CredentialPolicy{})
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	if cred.Kind != "password" {
		t.Errorf("kind = %q, want password", cred.Kind)
	}
	if len(cred.Secret) != adapterutil.DefaultPasswordLength {
		t.Errorf("default length = %d, want %d", len(cred.Secret), adapterutil.DefaultPasswordLength)
	}
	for _, b := range cred.Secret {
		if !strings.ContainsRune(adapterutil.PasswordAlphabet, rune(b)) {
			t.Fatalf("password contains char outside alphabet: %q", string(b))
		}
	}

	custom, err := ad.GenerateCredential(t.Context(), adapter.CredentialPolicy{Length: 12})
	if err != nil {
		t.Fatalf("GenerateCredential(12): %v", err)
	}
	if len(custom.Secret) != 12 {
		t.Errorf("custom length = %d, want 12", len(custom.Secret))
	}

	other, err := ad.GenerateCredential(t.Context(), adapter.CredentialPolicy{})
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	if string(other.Secret) == string(cred.Secret) {
		t.Error("two generated passwords must differ")
	}
}

func TestSplitEndpoint(t *testing.T) {
	tests := []struct {
		endpoint string
		host     string
		port     uint16
		wantErr  bool
	}{
		{endpoint: "rabbit.example.com:15672", host: "rabbit.example.com", port: 15672},
		{endpoint: "rabbit.example.com", host: "rabbit.example.com", port: defaultPort},
		{endpoint: "[::1]:15672", host: "::1", port: 15672},
		{endpoint: "rabbit.example.com:notaport", wantErr: true},
		{endpoint: "rabbit.example.com:0", wantErr: true},
		{endpoint: "", wantErr: true},
	}
	for _, tt := range tests {
		host, port, err := adapterutil.SplitEndpoint(tt.endpoint, defaultPort)
		if tt.wantErr {
			if err == nil {
				t.Errorf("splitEndpoint(%q): expected error", tt.endpoint)
			}
			continue
		}
		if err != nil {
			t.Errorf("splitEndpoint(%q): %v", tt.endpoint, err)
			continue
		}
		if host != tt.host || port != tt.port {
			t.Errorf("splitEndpoint(%q) = (%q, %d), want (%q, %d)", tt.endpoint, host, port, tt.host, tt.port)
		}
	}
}

func TestNewClientSchemeAndNoSecretLeak(t *testing.T) {
	const password = "s3cr3t-admin-password"
	cfg := adapter.Connection{
		Engine:    Engine,
		Endpoints: []string{"rabbit.example.com:15672"},
		TLS:       adapter.TLSConfig{Mode: "disabled"},
		AdminCredential: adapter.Credential{
			Kind:     "password",
			Username: "admin",
			Secret:   []byte(password),
		},
	}
	c, err := newClient(cfg)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	if c.baseURL != "http://rabbit.example.com:15672" {
		t.Errorf("baseURL = %q, want http://rabbit.example.com:15672", c.baseURL)
	}
	if c.username != "admin" {
		t.Errorf("username = %q, want admin", c.username)
	}

	// Секрет не должен появляться ни в одном текстовом представлении клиента.
	for _, rendered := range []string{
		fmt.Sprintf("%v", c),
		fmt.Sprintf("%+v", c),
		fmt.Sprintf("%#v", c),
		fmt.Sprintf("%s", c.secret),
		fmt.Sprintf("%v", c.secret),
	} {
		if strings.Contains(rendered, password) {
			t.Errorf("rendered client leaks secret: %q", rendered)
		}
	}
	raw, err := json.Marshal(c.secret)
	if err != nil {
		t.Fatalf("marshal secret: %v", err)
	}
	if strings.Contains(string(raw), password) {
		t.Errorf("marshaled secret leaks value: %s", raw)
	}

	// verify-full переключает scheme на https.
	cfg.TLS = adapter.TLSConfig{Mode: "verify-full"}
	tlsClient, err := newClient(cfg)
	if err != nil {
		t.Fatalf("newClient(verify-full): %v", err)
	}
	if !strings.HasPrefix(tlsClient.baseURL, "https://") {
		t.Errorf("verify-full baseURL = %q, want https:// prefix", tlsClient.baseURL)
	}
}

// TestIsManagementAccessDenied фиксирует ключевое для credential proof
// различие ответов Management API: отказ АВТОРИЗАЦИИ пользователя без
// management-тега (credential принят) против отказа АУТЕНТИФИКАЦИИ. Тела
// взяты с живого RabbitMQ 3.13; разбор обязан быть fail-closed — всё
// непонятное считается отказом аутентификации.
func TestIsManagementAccessDenied(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "correct password, user has no management tag",
			body: `{"error":"not_authorised","reason":"Not management user"}`,
			want: true,
		},
		{
			name: "wrong password",
			body: `{"error":"not_authorized","reason":"Not_Authorized"}`,
			want: false,
		},
		{
			name: "unknown user",
			body: `{"error":"not_authorized","reason":"Not_Authorized"}`,
			want: false,
		},
		{name: "empty body", body: "", want: false},
		{name: "non-json body", body: "<html>gateway error</html>", want: false},
		{name: "unrelated json", body: `{"error":"internal"}`, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isManagementAccessDenied([]byte(tt.body)); got != tt.want {
				t.Errorf("isManagementAccessDenied(%q) = %v, want %v", tt.body, got, tt.want)
			}
		})
	}
}

// TestManifestDeclaresRestoreWithProver проверяет обязательное условие
// ADR-0016: CapAccountRestore может объявлять только adapter, реализующий
// CredentialProver.
func TestManifestDeclaresRestoreWithProver(t *testing.T) {
	ad := New()
	if !ad.Manifest().HasCapability(adapter.CapAccountRestore) {
		t.Fatal("manifest must declare account.restore")
	}
	if _, ok := any(ad).(adapter.CredentialProver); !ok {
		t.Error("adapter declares account.restore without CredentialProver")
	}
}

// TestPlanAccountRestoreRequiresCredential — restore без пароля невозможен:
// восстановленная учётка обязана получить доказуемый credential.
func TestPlanAccountRestoreRequiresCredential(t *testing.T) {
	_, err := New().Plan(t.Context(), adapter.DesiredChange{
		Kind:    adapter.ChangeAccountRestore,
		Account: adapter.Account{Kind: "login", EngineIdentity: "svc"},
	})
	if err == nil {
		t.Fatal("Plan account.restore without credential: err = nil, want error")
	}
	if !strings.Contains(err.Error(), "credential") {
		t.Errorf("error = %q, want it to mention the missing credential", err)
	}
}
