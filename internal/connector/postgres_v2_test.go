package connector_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/postgresconfig"
)

func postgresV2Payload(kind adapter.ChangeKind) connector.MutationPayload {
	p := connector.MutationPayload{
		Connection: connector.ConnectionRef{
			ID: "connection-id", Engine: "postgres", Endpoints: []string{"db:5432"},
			ConfigIncarnation: strings.Repeat("a", 64),
		},
		Change: connector.ChangeRef{
			Kind: string(kind), ExpectedAdminIdentity: "grantor_admin",
			ExpectedTargetIdentity: "postgres:system:42",
		},
	}
	switch kind {
	case adapter.ChangePostgresAccountCreateV2, adapter.ChangePostgresAccountRestoreV2:
		p.Change.Account = connector.AccountRef{Kind: "login", EngineIdentity: "service_app"}
	case adapter.ChangePostgresRoleCreateV2:
		p.Change.Account = connector.AccountRef{Kind: "group", EngineIdentity: "r_app"}
	case adapter.ChangePostgresDatabaseCreateV2:
		p.Change.Resource = &adapter.ResourceSpec{Kind: "database", Name: "app",
			Attributes: map[string]any{"owner": "app_owner"}}
		p.Change.ExpectedDatabaseOwner = "app_owner"
		p.Change.ExpectedDatabaseOwnerOID = 17001
	case adapter.ChangePostgresRolePolicyApplyV2,
		adapter.ChangePostgresRolePolicyVerifyV2,
		adapter.ChangePostgresRolePolicyAdoptV2,
		adapter.ChangePostgresRolePolicyRepairV2,
		adapter.ChangePostgresRolePolicyCreateV2:
		p.Change.Permission = "role:r_app"
		fallthrough
	case adapter.ChangePostgresRolePolicyCreateDatabaseV2:
		p.Change.RolePolicySpec = &adapter.RolePolicySpec{
			Engine: "postgres", Key: "app-read", Name: "App read",
			RoleName: "r_app", Database: "app", Schemas: []string{"public"},
			OwnerRoles: []string{"app_owner"}, CreatorRoles: []string{"app_owner"}, Profile: "read",
		}
		p.Change.ExpectedDatabaseOID = 16384
		p.Change.ExpectedDatabaseOwner = "app_owner"
		p.Change.ExpectedDatabaseOwnerOID = 17001
		p.Change.ExpectedCatalogFingerprint = strings.Repeat("b", 64)
	}
	return p
}

func TestPostgresV2MutationPayloadRoundTrip(t *testing.T) {
	for _, kind := range []adapter.ChangeKind{
		adapter.ChangePostgresAccountCreateV2,
		adapter.ChangePostgresAccountRestoreV2,
		adapter.ChangePostgresRoleCreateV2,
		adapter.ChangePostgresDatabaseCreateV2,
		adapter.ChangePostgresRolePolicyApplyV2,
		adapter.ChangePostgresRolePolicyVerifyV2,
		adapter.ChangePostgresRolePolicyAdoptV2,
		adapter.ChangePostgresRolePolicyRepairV2,
		adapter.ChangePostgresRolePolicyCreateV2,
		adapter.ChangePostgresRolePolicyCreateDatabaseV2,
	} {
		t.Run(string(kind), func(t *testing.T) {
			payload := postgresV2Payload(kind)
			raw, err := payload.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := connector.ParseMutationPayload(raw)
			if err != nil {
				t.Fatalf("ParseMutationPayload: %v", err)
			}
			if parsed.Change.Kind != string(kind) ||
				parsed.Change.ExpectedAdminIdentity != payload.Change.ExpectedAdminIdentity ||
				parsed.Change.ExpectedTargetIdentity != payload.Change.ExpectedTargetIdentity ||
				parsed.Connection.ConfigIncarnation != payload.Connection.ConfigIncarnation {
				t.Fatalf("PostgreSQL v2 payload lost a fence: %+v", parsed)
			}
		})
	}
}

func TestLegacyPostgresWireVocabularyRemainsReadable(t *testing.T) {
	for _, kind := range []adapter.ChangeKind{
		adapter.ChangeAccountCreate, adapter.ChangeAccountRestore,
		adapter.ChangeRoleCreate, adapter.ChangeResourceCreate,
		adapter.ChangeRolePolicyApply, adapter.ChangeRolePolicyVerify,
		adapter.ChangeRolePolicyCreate, adapter.ChangeRolePolicyCreateDatabase,
	} {
		t.Run(string(kind), func(t *testing.T) {
			payload := connector.MutationPayload{
				Connection: connector.ConnectionRef{ID: "c", Engine: "postgres"},
				Change:     connector.ChangeRef{Kind: string(kind)},
			}
			switch kind {
			case adapter.ChangeAccountCreate, adapter.ChangeAccountRestore:
				payload.Change.Account = connector.AccountRef{Kind: "login", EngineIdentity: "service_app"}
			case adapter.ChangeRoleCreate:
				payload.Change.Account = connector.AccountRef{Kind: "group", EngineIdentity: "r_app"}
			case adapter.ChangeResourceCreate:
				payload.Change.Resource = &adapter.ResourceSpec{Kind: "database", Name: "app"}
			case adapter.ChangeRolePolicyApply, adapter.ChangeRolePolicyVerify, adapter.ChangeRolePolicyCreate:
				payload.Change.Permission = "role:r_app"
				fallthrough
			case adapter.ChangeRolePolicyCreateDatabase:
				payload.Change.RolePolicySpec = &adapter.RolePolicySpec{Engine: "postgres", RoleName: "r_app", Database: "app"}
				payload.Change.ExpectedTargetIdentity = "postgres:system:42"
				if kind == adapter.ChangeRolePolicyCreateDatabase {
					payload.Change.ExpectedDatabaseOID = 16384
				}
			}
			raw, err := payload.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := connector.ParseMutationPayload(raw)
			if err != nil || parsed.Change.Kind != string(kind) {
				t.Fatalf("legacy PostgreSQL kind is not readable: %+v, %v", parsed, err)
			}
		})
	}

	for _, kind := range []adapter.ChangeKind{adapter.ChangeAccountCreate, adapter.ChangeAccountRestore} {
		payload := connector.MutationPayload{
			Connection: connector.ConnectionRef{ID: "mongo", Engine: "mongodb"},
			Change: connector.ChangeRef{Kind: string(kind), Account: connector.AccountRef{
				Kind: "login", EngineIdentity: "service_app@admin",
			}},
		}
		raw, err := payload.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := connector.ParseMutationPayload(raw); err != nil {
			t.Fatalf("generic non-PostgreSQL kind %q was rejected: %v", kind, err)
		}
	}
}

func TestPostgresV2MutationPayloadRequiresIncarnationsAndClosedFields(t *testing.T) {
	base := postgresV2Payload(adapter.ChangePostgresAccountCreateV2)
	for name, mutate := range map[string]func(*connector.MutationPayload){
		"engine":             func(p *connector.MutationPayload) { p.Connection.Engine = "mongodb" },
		"config incarnation": func(p *connector.MutationPayload) { p.Connection.ConfigIncarnation = "" },
		"target identity":    func(p *connector.MutationPayload) { p.Change.ExpectedTargetIdentity = "" },
		"admin identity":     func(p *connector.MutationPayload) { p.Change.ExpectedAdminIdentity = "" },
		"raw attributes":     func(p *connector.MutationPayload) { p.Change.Attributes = map[string]any{"sql": "unsafe"} },
		"permission":         func(p *connector.MutationPayload) { p.Change.Permission = "role:admin" },
		"wrong account kind": func(p *connector.MutationPayload) { p.Change.Account.Kind = "group" },
	} {
		t.Run(name, func(t *testing.T) {
			payload := base
			mutate(&payload)
			raw, err := payload.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := connector.ParseMutationPayload(raw); err == nil {
				t.Fatal("unsafe PostgreSQL v2 payload was accepted")
			}
		})
	}
}

func TestPostgresV2MutationPayloadRejectsUnknownJSONFieldsAtEveryTypedLevel(t *testing.T) {
	tests := []struct {
		name    string
		payload connector.MutationPayload
		path    []string
	}{
		{name: "top level", payload: postgresV2Payload(adapter.ChangePostgresAccountCreateV2)},
		{name: "connection", payload: postgresV2Payload(adapter.ChangePostgresAccountCreateV2), path: []string{"connection"}},
		{name: "change raw sql", payload: postgresV2Payload(adapter.ChangePostgresAccountCreateV2), path: []string{"change"}},
		{name: "account", payload: postgresV2Payload(adapter.ChangePostgresAccountCreateV2), path: []string{"change", "account"}},
		{name: "resource", payload: postgresV2Payload(adapter.ChangePostgresDatabaseCreateV2), path: []string{"change", "resource"}},
		{name: "role policy spec", payload: postgresV2Payload(adapter.ChangePostgresRolePolicyApplyV2), path: []string{"change", "role_policy_spec"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := tc.payload.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			var document map[string]any
			if err := json.Unmarshal(raw, &document); err != nil {
				t.Fatal(err)
			}
			parent := document
			for _, segment := range tc.path {
				next, ok := parent[segment].(map[string]any)
				if !ok {
					t.Fatalf("path %q is not an object", strings.Join(tc.path, "."))
				}
				parent = next
			}
			parent["raw_sql"] = "SELECT pg_sleep(1)"
			raw, err = json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := connector.ParseMutationPayload(raw); err == nil || !strings.Contains(err.Error(), "unknown field") {
				t.Fatalf("unknown PostgreSQL v2 field was not rejected: %v", err)
			}
		})
	}
}

func TestGenericMutationPayloadKeepsUnknownFieldCompatibility(t *testing.T) {
	raw := json.RawMessage(`{
		"connection":{"id":"mongo","engine":"mongodb"},
		"change":{
			"kind":"account.create",
			"account":{"kind":"login","engine_identity":"service_app@admin","future_account_field":true},
			"account_permissions":[],
			"future_change_field":{"version":2}
		},
		"future_top_level_field":true
	}`)
	parsed, err := connector.ParseMutationPayload(raw)
	if err != nil {
		t.Fatalf("generic mutation extension was rejected: %v", err)
	}
	if parsed.Connection.Engine != "mongodb" || parsed.Change.Kind != string(adapter.ChangeAccountCreate) {
		t.Fatalf("generic mutation lost its stable fields: %+v", parsed)
	}
}

func TestPostgresV2MutationPayloadRejectsMapAndEngineUnionEscapeHatches(t *testing.T) {
	tests := []struct {
		name    string
		payload connector.MutationPayload
		want    string
	}{
		{
			name: "connection attributes raw sql",
			payload: func() connector.MutationPayload {
				payload := postgresV2Payload(adapter.ChangePostgresAccountCreateV2)
				payload.Attributes = map[string]any{"raw_sql": "ALTER ROLE grantor SUPERUSER"}
				return payload
			}(),
			want: `connection attribute "raw_sql" is not allowed`,
		},
		{
			name: "database attributes raw sql",
			payload: func() connector.MutationPayload {
				payload := postgresV2Payload(adapter.ChangePostgresDatabaseCreateV2)
				payload.Change.Resource.Attributes = map[string]any{
					"owner": "app_owner", "raw_sql": "CREATE EXTENSION file_fdw",
				}
				return payload
			}(),
			want: `database option "raw_sql" is not allowed`,
		},
		{
			name: "MongoDB inherited roles on PostgreSQL policy",
			payload: func() connector.MutationPayload {
				payload := postgresV2Payload(adapter.ChangePostgresRolePolicyApplyV2)
				payload.Change.RolePolicySpec.MongoInheritedRoles = []adapter.MongoRoleRef{{Role: "root", DB: "admin"}}
				return payload
			}(),
			want: `role policy field "inherited_roles" is not allowed`,
		},
		{
			name: "MongoDB privileges on PostgreSQL policy",
			payload: func() connector.MutationPayload {
				payload := postgresV2Payload(adapter.ChangePostgresRolePolicyApplyV2)
				payload.Change.RolePolicySpec.MongoPrivileges = []adapter.MongoRolePrivilege{{
					Resource: adapter.MongoRoleResource{Cluster: true}, Actions: []string{"anyAction"},
				}}
				return payload
			}(),
			want: `role policy field "privileges" is not allowed`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := tc.payload.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := connector.ParseMutationPayload(raw); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("escape hatch was not rejected with %q: %v", tc.want, err)
			}
		})
	}

	t.Run("empty MongoDB union field is still rejected by presence", func(t *testing.T) {
		payload := postgresV2Payload(adapter.ChangePostgresRolePolicyApplyV2)
		raw, err := payload.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]any
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatal(err)
		}
		change := document["change"].(map[string]any)
		policy := change["role_policy_spec"].(map[string]any)
		policy["inherited_roles"] = []any{}
		raw, err = json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := connector.ParseMutationPayload(raw); err == nil || !strings.Contains(err.Error(), `field "inherited_roles" is not allowed`) {
			t.Fatalf("empty MongoDB union field was accepted: %v", err)
		}
	})
}

func TestPostgresV2MutationPayloadAcceptsReviewedConnectionAndDatabaseOptions(t *testing.T) {
	payload := postgresV2Payload(adapter.ChangePostgresDatabaseCreateV2)
	payload.Attributes = map[string]any{
		"database":                            "postgres",
		adapter.AttrDatabaseCreateTemplates:   []string{"template1"},
		adapter.AttrDatabaseCreateOwners:      []string{"app_owner"},
		adapter.AttrDatabaseCreateTablespaces: []string{"pg_default"},
		postgresconfig.AttributeRolePolicyTemplates: []postgresconfig.RolePolicyTemplate{{
			Key: "app-read", Name: "App read", Description: "Read access",
			RoleName: "r_app", Database: "app", Schemas: []string{"public"},
			OwnerRoles: []string{"app_owner"}, CreatorRoles: []string{"app_owner"},
			Profile: postgresconfig.ProfileRead,
		}},
	}
	payload.Change.Resource.Attributes = map[string]any{
		"owner": "app_owner", "template": "template1", "encoding": "UTF8",
		"locale": "C", "tablespace": "pg_default", "connection_limit": 25,
	}
	raw, err := payload.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connector.ParseMutationPayload(raw); err != nil {
		t.Fatalf("reviewed PostgreSQL v2 options were rejected: %v", err)
	}
}
