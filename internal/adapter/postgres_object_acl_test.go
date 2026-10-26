package adapter

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func aclFixture() PostgresObjectPrivilege {
	return PostgresObjectPrivilege{TargetIdentity: "postgres:system:42", Database: "app", DatabaseOID: 10, Kind: "table", Schema: "public", SchemaOID: 11, Name: "items", ObjectOID: 12, OwnerOID: 13, Privilege: "SELECT"}
}

func TestPostgresObjectPrivilegeClosedIdentity(t *testing.T) {
	p := aclFixture()
	got, err := ParsePostgresObjectPrivilege(p.PermissionID())
	if err != nil || got != p {
		t.Fatalf("round trip: %v", err)
	}
	for _, change := range []func(*PostgresObjectPrivilege){
		func(p *PostgresObjectPrivilege) { p.Privilege = "SELECT; DROP TABLE app" },
		func(p *PostgresObjectPrivilege) { p.Kind = "unknown" },
		func(p *PostgresObjectPrivilege) { p.OwnerOID = 0 },
		func(p *PostgresObjectPrivilege) { p.DatabaseOID = 0 },
		func(p *PostgresObjectPrivilege) { p.Schema = "pg_catalog" },
		func(p *PostgresObjectPrivilege) { p.Name = "bad\x00name" },
		func(p *PostgresObjectPrivilege) { p.Column = "unrelated" },
	} {
		bad := p
		change(&bad)
		if _, err := ParsePostgresObjectPrivilege(bad.PermissionID()); err == nil {
			t.Fatalf("invalid identity accepted: %+v", bad)
		}
	}
	raw, _ := json.Marshal(p)
	raw = []byte(strings.TrimSuffix(string(raw), "}") + `,"raw_sql":"select 1"}`)
	if _, err := ParsePostgresObjectPrivilege(PostgresObjectACLPrefix + base64.RawURLEncoding.EncodeToString(raw)); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err := ParsePostgresObjectPrivilege(p.PermissionID() + "="); err == nil {
		t.Fatal("noncanonical ID accepted")
	}
}

func TestPostgresObjectACLNoGenericOrMixedRoute(t *testing.T) {
	p := aclFixture()
	f := &PostgresObjectACLPins{AdminIdentity: "grantor", TargetIdentity: p.TargetIdentity, ConfigIncarnation: "config", CredentialIncarnation: 1, SubjectOID: 20}
	c := DesiredChange{Kind: ChangePostgresObjectACLGrantV1, Account: Account{Kind: "login", EngineIdentity: "alice"},
		Permission: p.PermissionID(), Scope: p.Scope(), ObjectACL: f, ExpectedAdminIdentity: f.AdminIdentity, ExpectedTargetIdentity: f.TargetIdentity}
	if err := ValidatePostgresObjectACLChange(c); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*DesiredChange){
		func(c *DesiredChange) { c.Kind = ChangeGrant }, func(c *DesiredChange) { c.ObjectACL = nil },
		func(c *DesiredChange) { c.Account.EngineIdentity = "grantor" }, func(c *DesiredChange) { c.Account.EngineIdentity = "pg_monitor" },
		func(c *DesiredChange) { c.Scope = "db:other" }, func(c *DesiredChange) { c.ExpectedAdminIdentity = "other" },
		func(c *DesiredChange) { c.Attributes = map[string]any{"sql": "grant anything"} },
		func(c *DesiredChange) { c.Credential = &Credential{} }, func(c *DesiredChange) { c.AccountPermissions = []string{"role:other"} },
	} {
		bad := c
		change(&bad)
		if ValidatePostgresObjectACLChange(bad) == nil {
			t.Fatal("mixed mutation accepted")
		}
	}
}
