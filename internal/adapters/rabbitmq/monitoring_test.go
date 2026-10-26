package rabbitmq

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adaptertest"
	"github.com/ArtefactoO/grantor/internal/rabbitmqconfig"
)

func TestMonitoringPermissionSharesVhostAssignmentSlot(t *testing.T) {
	permissions := buildPermissions([]apiVhost{{Name: "/"}, {Name: "app"}})
	byID := map[string]adapter.ObservedPermission{}
	for _, p := range permissions {
		byID[p.ExternalID] = p
	}
	for _, vhost := range []string{"/", "app"} {
		p, found := byID[vhostMonitoringPermissionID(vhost)]
		if !found || !p.Assignable || p.Dangerous {
			t.Fatalf("monitoring permission for %q = %+v, found=%v", vhost, p, found)
		}
		if p.ScopeExternalID != vhostExternalID(vhost) || p.AssignmentKey != byID[vhostPermissionID(vhost)].AssignmentKey {
			t.Fatalf("monitoring must occupy the existing vhost slot: %+v", p)
		}
		for _, key := range []string{"configure", "write", "read"} {
			if p.Attributes[key] != "^$" {
				t.Fatalf("monitoring %s = %v, want deny-all", key, p.Attributes[key])
			}
		}
		if p.Attributes["broad"] != false || p.Attributes["broad_configure"] != false {
			t.Fatalf("monitoring must not imply broad resource access: %+v", p)
		}
	}
	if byID["tag:monitoring"].ScopeExternalID != "" {
		t.Fatal("the monitoring tag must remain an independent cluster permission")
	}
}

func TestConfiguredDenyTemplateKeepsIdentityAndApprovalPolicy(t *testing.T) {
	template := rabbitmqconfig.PermissionTemplate{
		Key: "existing-monitor", Name: "Existing monitoring", Description: "Operator-defined visibility",
		Vhost: "app", Configure: "^$", Write: "^$", Read: "^$", Dangerous: true,
	}
	permissions := buildPermissions([]apiVhost{{Name: "app"}, {Name: "other"}}, []rabbitmqconfig.PermissionTemplate{template})
	matched := false
	for _, p := range permissions {
		if p.ExternalID == "vhost-monitoring:app" {
			t.Fatal("builtin monitoring duplicates an existing deny-all template")
		}
		if p.ExternalID == templatePermissionID(template.Key) {
			matched = true
			if p.Name != template.Name || !p.Dangerous || p.AssignmentKey != "rabbitmq:vhost:app" {
				t.Fatalf("configured identity or approval policy changed: %+v", p)
			}
		}
	}
	if !matched {
		t.Fatal("existing configured template disappeared")
	}
	binding := vhostBinding(apiPermission{User: "svc", Vhost: "app", Configure: "^$", Write: "^$", Read: "^$"}, []rabbitmqconfig.PermissionTemplate{template})
	if binding.PermissionExternalID != templatePermissionID(template.Key) || binding.Attributes[adapter.AttrBindingEffective] != true {
		t.Fatalf("discovery reinterpreted the configured deny-all tuple: %+v", binding)
	}
}

func TestMonitoringBindingOnlyMatchesExactDenyTuple(t *testing.T) {
	for _, tc := range []struct {
		name, configure, write, read, permission string
		effective                                bool
	}{
		{"monitoring", "^$", "^$", "^$", "vhost-monitoring:app", true},
		{"legacy full access", ".*", ".*", ".*", "vhost-access:app", true},
		{"publish allowed", "^$", ".*", "^$", "vhost-access:app", false},
		{"consume allowed", "^$", "^$", ".*", "vhost-access:app", false},
		{"configure allowed", ".*", "^$", "^$", "vhost-access:app", false},
		{"empty expressions", "", "", "", "vhost-access:app", false},
		{"different deny expressions", "a^", "a^", "a^", "vhost-access:app", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := vhostBinding(apiPermission{User: "svc", Vhost: "app", Configure: tc.configure, Write: tc.write, Read: tc.read})
			if b.PermissionExternalID != tc.permission || b.Attributes[adapter.AttrBindingEffective] != tc.effective || b.Attributes["template_matched"] != tc.effective {
				t.Fatalf("classification = %+v", b)
			}
			if b.AssignmentKey != "rabbitmq:vhost:app" {
				t.Fatalf("assignment slot = %q", b.AssignmentKey)
			}
		})
	}
}

func TestMonitoringPlanPinsDenyTupleAndRejectsWrongScope(t *testing.T) {
	change := adapter.DesiredChange{
		Connection: connectionWithTemplates("rabbit.example.com"), Account: adapter.Account{EngineIdentity: "svc"},
		Permission: "vhost-monitoring:app", Scope: "vhost:app",
		Attributes: map[string]any{"vhost": "other", "configure": ".*", "write": ".*", "read": ".*"},
	}
	for _, kind := range []adapter.ChangeKind{adapter.ChangeGrant, adapter.ChangeRevoke} {
		change.Kind = kind
		plan, err := New().Plan(t.Context(), change)
		if err != nil {
			t.Fatalf("Plan: %v", err)
		}
		if len(plan.Steps) != 1 || plan.Steps[0].Attributes["vhost"] != "app" {
			t.Fatalf("monitoring scope changed: %+v", plan)
		}
		for _, key := range []string{"configure", "write", "read"} {
			if plan.Steps[0].Attributes[key] != "^$" {
				t.Fatalf("monitoring plan can be widened by caller attrs: %+v", plan.Steps[0])
			}
		}
	}
	change.Scope = "vhost:other"
	if _, err := New().Plan(t.Context(), change); !errors.Is(err, adapter.ErrUnsupportedChange) {
		t.Fatalf("wrong-scope Plan error = %v", err)
	}
	change.Scope = ""
	change.Permission = "vhost-monitoring:"
	if _, err := New().Plan(t.Context(), change); err == nil {
		t.Fatal("empty monitoring vhost must fail")
	}
}

func TestMonitoringApplyVerifyAndRevokeUseExactAssignmentSlot(t *testing.T) {
	var mu sync.Mutex
	current := &apiPermission{User: "svc", Vhost: "app", Configure: ".*", Write: ".*", Read: ".*"}
	writes, deletes := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/users/svc":
			_ = json.NewEncoder(w).Encode(apiUser{Name: "svc", Tags: json.RawMessage(`["monitoring"]`)})
		case r.Method == http.MethodGet && r.URL.Path == "/api/permissions/app/svc":
			if current == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(current)
		case r.Method == http.MethodPut && r.URL.Path == "/api/permissions/app/svc":
			var body permissionPayload
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode permission: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if body.Configure != "^$" || body.Write != "^$" || body.Read != "^$" {
				t.Errorf("monitoring granted resource actions: %+v", body)
			}
			current = &apiPermission{User: "svc", Vhost: "app", Configure: body.Configure, Write: body.Write, Read: body.Read}
			writes++
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/permissions/app/svc":
			current = nil
			deletes++
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("monitoring must not mutate tags or another resource: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	change := adapter.DesiredChange{
		Kind: adapter.ChangeGrant, Connection: connectionWithTemplates(server.Listener.Addr().String()),
		Account: adapter.Account{EngineIdentity: "svc"}, Permission: "vhost-monitoring:app", Scope: "vhost:app",
	}
	ad := New()
	plan, err := ad.Plan(t.Context(), change)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	verification, err := ad.Verify(t.Context(), *plan)
	if err != nil || verification.Verified {
		t.Fatalf("full access must not verify as monitoring: verification=%+v error=%v", verification, err)
	}
	adaptertest.PlanApplyVerify(t.Context(), t, ad, change)
	adaptertest.PlanApplyVerify(t.Context(), t, ad, change)
	mu.Lock()
	if writes != 1 || current == nil || !tupleMatches(*current, monitoringTuple("app")) {
		t.Errorf("monitoring grant was not exact/idempotent: writes=%d current=%+v", writes, current)
	}
	// Revoke empties the same assignment slot even when the observed tuple drifted.
	current = &apiPermission{User: "svc", Vhost: "app", Configure: "^other$", Write: ".*", Read: ".*"}
	mu.Unlock()
	change.Kind = adapter.ChangeRevoke
	adaptertest.PlanApplyVerify(t.Context(), t, ad, change)
	adaptertest.PlanApplyVerify(t.Context(), t, ad, change)
	mu.Lock()
	defer mu.Unlock()
	if current != nil || deletes != 1 {
		t.Fatalf("monitoring revoke left the slot occupied: deletes=%d current=%+v", deletes, current)
	}
}
