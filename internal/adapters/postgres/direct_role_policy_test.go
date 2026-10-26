package postgres

import (
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/postgresconfig"
)

func directPolicyTestChange(kind adapter.ChangeKind) adapter.DesiredChange {
	return adapter.DesiredChange{
		Kind: kind,
		Connection: adapter.Connection{
			Engine: Engine, ConfigIncarnation: "config-v1", AdminCredentialIncarnation: 7,
			AdminCredential: adapter.Credential{Username: "grantor_admin"},
		},
		Permission: "role:r_app",
		RolePolicySpec: &adapter.RolePolicySpec{
			Engine: Engine, Key: "app-read", Name: "App read", Description: "Read app objects",
			RoleName: "r_app", Database: "app", Schemas: []string{"public", "audit"},
			OwnerRoles: []string{"app_owner"}, CreatorRoles: []string{"app_owner", "app_migrator"},
			Profile: postgresconfig.ProfileRead,
		},
		ExpectedAdminIdentity:    "grantor_admin",
		ExpectedTargetIdentity:   "postgres:system:123456789",
		ExpectedDatabaseOID:      16384,
		ExpectedDatabaseOwner:    "app_owner",
		ExpectedDatabaseOwnerOID: 17001,
	}
}

func TestDirectRolePolicyKindsAreClosed(t *testing.T) {
	for _, kind := range []adapter.ChangeKind{
		adapter.ChangePostgresRolePolicyApplyV2,
		adapter.ChangePostgresRolePolicyVerifyV2,
		adapter.ChangePostgresRolePolicyAdoptV2,
		adapter.ChangePostgresRolePolicyRepairV2,
		adapter.ChangePostgresRolePolicyCreateV2,
		adapter.ChangePostgresRolePolicyCreateDatabaseV2,
	} {
		if !isDirectRolePolicyChange(kind) {
			t.Errorf("kind %q is not recognized", kind)
		}
	}
	for _, kind := range []adapter.ChangeKind{
		adapter.ChangeRolePolicyApply, adapter.ChangeRolePolicyVerify,
		adapter.ChangeRolePolicyCreate, adapter.ChangeRolePolicyCreateDatabase,
		adapter.ChangePostgresAccountCreateV2,
	} {
		if isDirectRolePolicyChange(kind) {
			t.Errorf("kind %q escaped the closed policy vocabulary", kind)
		}
	}
}

func TestValidateDirectRolePolicyPinsEveryIdentity(t *testing.T) {
	base := directPolicyTestChange(adapter.ChangePostgresRolePolicyApplyV2)
	if _, err := validateDirectRolePolicyChange(base); err != nil {
		t.Fatalf("valid change: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*adapter.DesiredChange)
	}{
		{"missing admin", func(c *adapter.DesiredChange) { c.ExpectedAdminIdentity = "" }},
		{"credential admin mismatch", func(c *adapter.DesiredChange) { c.Connection.AdminCredential.Username = "other" }},
		{"missing credential incarnation", func(c *adapter.DesiredChange) { c.Connection.AdminCredentialIncarnation = 0 }},
		{"missing config incarnation", func(c *adapter.DesiredChange) { c.Connection.ConfigIncarnation = "" }},
		{"missing target", func(c *adapter.DesiredChange) { c.ExpectedTargetIdentity = "" }},
		{"non-numeric target", func(c *adapter.DesiredChange) { c.ExpectedTargetIdentity = "postgres:system:other" }},
		{"zero target", func(c *adapter.DesiredChange) { c.ExpectedTargetIdentity = "postgres:system:0" }},
		{"non-canonical target", func(c *adapter.DesiredChange) { c.ExpectedTargetIdentity = "postgres:system:001" }},
		{"missing database oid", func(c *adapter.DesiredChange) { c.ExpectedDatabaseOID = 0 }},
		{"missing database owner", func(c *adapter.DesiredChange) { c.ExpectedDatabaseOwner = "" }},
		{"missing database owner oid", func(c *adapter.DesiredChange) { c.ExpectedDatabaseOwnerOID = 0 }},
		{"permission mismatch", func(c *adapter.DesiredChange) { c.Permission = "role:rw_app" }},
		{"legacy kind", func(c *adapter.DesiredChange) { c.Kind = adapter.ChangeRolePolicyApply }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			change := base
			test.mutate(&change)
			if _, err := validateDirectRolePolicyChange(change); err == nil {
				t.Fatal("invalid direct policy change was accepted")
			}
		})
	}
}

func TestCreateDatabaseDirectPolicyRequiresPinnedBasicScope(t *testing.T) {
	base := directPolicyTestChange(adapter.ChangePostgresRolePolicyCreateDatabaseV2)
	spec := *base.RolePolicySpec
	spec.OwnerRoles = []string{base.ExpectedDatabaseOwner}
	spec.CreatorRoles = []string{base.ExpectedDatabaseOwner}
	base.RolePolicySpec = &spec
	if _, err := validateDirectRolePolicyChange(base); err != nil {
		t.Fatalf("valid database-created basic scope: %v", err)
	}
	tests := []struct {
		name     string
		owners   []string
		creators []string
	}{
		{"multiple owners", []string{base.ExpectedDatabaseOwner, "other_owner"}, []string{base.ExpectedDatabaseOwner}},
		{"multiple creators", []string{base.ExpectedDatabaseOwner}, []string{base.ExpectedDatabaseOwner, "other_creator"}},
		{"owner mismatch", []string{"other_owner"}, []string{base.ExpectedDatabaseOwner}},
		{"creator mismatch", []string{base.ExpectedDatabaseOwner}, []string{"other_creator"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			change := base
			candidate := *base.RolePolicySpec
			candidate.OwnerRoles = test.owners
			candidate.CreatorRoles = test.creators
			change.RolePolicySpec = &candidate
			if _, err := validateDirectRolePolicyChange(change); err == nil {
				t.Fatal("malformed database-created basic scope was accepted")
			}
		})
	}
}

func TestDirectPolicyAuthorityFactsRequireExactLiveSuperuser(t *testing.T) {
	change := directPolicyTestChange(adapter.ChangePostgresRolePolicyApplyV2)
	template, err := validateDirectRolePolicyChange(change)
	if err != nil {
		t.Fatal(err)
	}
	facts := directPolicyAuthority{
		admin: "grantor_admin", targetIdentity: change.ExpectedTargetIdentity,
		database: template.Database, databaseOID: change.ExpectedDatabaseOID,
		databaseOwner: change.ExpectedDatabaseOwner, databaseOwnerOID: change.ExpectedDatabaseOwnerOID,
		serverVersion: 160000,
	}
	if err := validateDirectPolicyAuthorityFacts(change, template, facts,
		"grantor_admin", "grantor_admin", true, false, false); err != nil {
		t.Fatalf("valid facts: %v", err)
	}
	tests := []struct {
		name                  string
		facts                 directPolicyAuthority
		session, current      string
		super, recovery, read bool
		insufficient          bool
	}{
		{"session mismatch", facts, "other", "grantor_admin", true, false, false, false},
		{"current mismatch", facts, "grantor_admin", "other", true, false, false, false},
		{"not superuser", facts, "grantor_admin", "grantor_admin", false, false, false, true},
		{"replica", facts, "grantor_admin", "grantor_admin", true, true, false, false},
		{"read only", facts, "grantor_admin", "grantor_admin", true, false, true, false},
		{"system changed", withDirectAuthority(facts, func(f *directPolicyAuthority) { f.targetIdentity = "postgres:system:9" }), "grantor_admin", "grantor_admin", true, false, false, false},
		{"database changed", withDirectAuthority(facts, func(f *directPolicyAuthority) { f.database = "other" }), "grantor_admin", "grantor_admin", true, false, false, false},
		{"oid changed", withDirectAuthority(facts, func(f *directPolicyAuthority) { f.databaseOID++ }), "grantor_admin", "grantor_admin", true, false, false, false},
		{"owner changed", withDirectAuthority(facts, func(f *directPolicyAuthority) { f.databaseOwner = "other" }), "grantor_admin", "grantor_admin", true, false, false, false},
		{"owner oid changed", withDirectAuthority(facts, func(f *directPolicyAuthority) { f.databaseOwnerOID++ }), "grantor_admin", "grantor_admin", true, false, false, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateDirectPolicyAuthorityFacts(change, template, test.facts,
				test.session, test.current, test.super, test.recovery, test.read)
			if err == nil {
				t.Fatal("unsafe live authority was accepted")
			}
			var privilege *adapter.InsufficientPrivilegeError
			if errors.As(err, &privilege) != test.insufficient {
				t.Fatalf("insufficient privilege classification = %v, error %v", errors.As(err, &privilege), err)
			}
		})
	}
}

func withDirectAuthority(value directPolicyAuthority, mutate func(*directPolicyAuthority)) directPolicyAuthority {
	mutate(&value)
	return value
}

func TestDirectACLRevokeVocabularyIsQuotedAndRestricted(t *testing.T) {
	tests := []directACLTarget{
		{kind: "database", name1: `app"db`, grantor: "owner"},
		{kind: "schema", name1: "public", grantor: "owner"},
		{kind: "table", name1: "public", name2: "items", grantor: "owner"},
		{kind: "sequence", name1: "public", name2: "items_id_seq", grantor: "owner"},
		{kind: "column", name1: "public", name2: "items", name3: "secret", grantor: "owner"},
		{kind: "routine", name1: "public.calculate(integer)", grantor: "owner"},
		{kind: "type", name1: "public", name2: "state", grantor: "owner"},
		{kind: "large-object", oid: 123, grantor: "owner"},
		{kind: "foreign-data-wrapper", name1: "postgres_fdw", grantor: "owner"},
		{kind: "foreign-server", name1: "remote", grantor: "owner"},
		{kind: "language", name1: "plpgsql", grantor: "owner"},
		{kind: "tablespace", name1: "fast", grantor: "owner"},
		{kind: "parameter", name1: "log_statement", grantor: "owner"},
	}
	for _, target := range tests {
		t.Run(target.kind, func(t *testing.T) {
			statement, err := directACLRevokeStatement(target, "r_app")
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasSuffix(statement.sql, ` granted by "owner" restrict`) {
				t.Fatalf("statement is not exact-grantor RESTRICT: %s", statement.sql)
			}
			if strings.Contains(statement.sql, ";") {
				t.Fatalf("statement contains a separator: %s", statement.sql)
			}
		})
	}
	if _, err := directACLRevokeStatement(directACLTarget{kind: "routine", name1: "f();drop role x", grantor: "owner"}, "r_app"); err == nil {
		t.Fatal("unsafe catalog routine identity was accepted")
	}
	if _, err := directACLRevokeStatement(directACLTarget{kind: "publication", name1: "p", grantor: "owner"}, "r_app"); err == nil {
		t.Fatal("unknown ACL target escaped the closed vocabulary")
	}
}

func TestDirectProfilesHaveOnlyFixedPrivileges(t *testing.T) {
	tests := []struct {
		profile    string
		table, seq string
	}{
		{postgresconfig.ProfileRead, "select", "select"},
		{postgresconfig.ProfileReadWrite, "select, insert, update, delete", "select, update"},
	}
	for _, test := range tests {
		t.Run(test.profile, func(t *testing.T) {
			table, seq := directProfilePrivileges(test.profile)
			if table != test.table || seq != test.seq {
				t.Fatalf("privileges = %q/%q", table, seq)
			}
			for _, forbidden := range []string{"truncate", "create", "alter", "drop", "trigger", "references"} {
				if strings.Contains(table+","+seq, forbidden) {
					t.Fatalf("fixed profile contains %q", forbidden)
				}
			}
		})
	}
}

func TestDirectPlanPinsCannotBeRewritten(t *testing.T) {
	change := directPolicyTestChange(adapter.ChangePostgresRolePolicyApplyV2)
	template, err := validateDirectRolePolicyChange(change)
	if err != nil {
		t.Fatal(err)
	}
	step := adapter.PlanStep{Kind: stepDirectRolePolicy,
		Attributes: directRolePolicyPlanAttributes(change, template, directPolicyAuthority{serverVersion: 160000})}
	plan := adapter.Plan{Change: change, Steps: []adapter.PlanStep{step}}
	if err := validateDirectRolePolicyPlan(plan, template); err != nil {
		t.Fatalf("valid plan: %v", err)
	}
	for _, key := range []string{"expected_admin_identity", "expected_target_identity", "expected_database",
		"expected_database_owner", "expected_database_owner_oid", "expected_role", "expected_profile", "expected_spec_fingerprint", "expected_database_oid",
		"expected_config_incarnation", "expected_credential_incarnation"} {
		t.Run(key, func(t *testing.T) {
			broken := plan
			broken.Steps = []adapter.PlanStep{{Kind: stepDirectRolePolicy, Attributes: map[string]any{}}}
			for attr, value := range plan.Steps[0].Attributes {
				broken.Steps[0].Attributes[attr] = value
			}
			broken.Steps[0].Attributes[key] = "changed"
			if err := validateDirectRolePolicyPlan(broken, template); err == nil {
				t.Fatal("rewritten plan pin was accepted")
			}
		})
	}
}

func TestDirectRoleCreateStatementCannotSelectAttributes(t *testing.T) {
	sql := directCreatePolicyRoleSQL(`r_"app`)
	for _, required := range []string{"nologin", "nosuperuser", "nocreatedb", "nocreaterole", "noreplication", "nobypassrls", "inherit"} {
		if !strings.Contains(sql, required) {
			t.Errorf("CREATE ROLE does not fix %s: %s", required, sql)
		}
	}
	for _, forbidden := range []string{"password '", "set role", ";", "create schema", "create function", "temporary"} {
		if strings.Contains(strings.ToLower(sql), forbidden) {
			t.Errorf("CREATE ROLE contains forbidden vocabulary %q: %s", forbidden, sql)
		}
	}
}

func TestDirectRoleCreateRaceIsIdentityConflict(t *testing.T) {
	for _, code := range []string{pgCodeDuplicateObject, "23505"} {
		err := directCreatePolicyRoleError("r_app", &pgconn.PgError{Code: code})
		if !errors.Is(err, adapter.ErrExternalIdentityConflict) {
			t.Fatalf("SQLSTATE %s = %v, want external identity conflict", code, err)
		}
	}
	if err := directCreatePolicyRoleError("r_app", &pgconn.PgError{Code: "42501"}); errors.Is(err, adapter.ErrExternalIdentityConflict) {
		t.Fatalf("unrelated PostgreSQL error was misclassified: %v", err)
	}
}
