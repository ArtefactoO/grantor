package adapter

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
)

const CapPostgresObjectACLV1 Capability = "postgres.object_acl.v1"
const ChangePostgresObjectACLGrantV1 ChangeKind = "postgres.object_acl.grant.v1"
const ChangePostgresObjectACLRevokeV1 ChangeKind = "postgres.object_acl.revoke.v1"
const PostgresObjectACLPrefix = "pgacl:v1:"

var ErrPostgresObjectACL = fmt.Errorf("unsupported or incomplete PostgreSQL object ACL intent: %w", ErrUnsupportedChange)

// Names and OIDs both matter: a rename or replacement must require a new intent.
type PostgresObjectPrivilege struct {
	TargetIdentity string `json:"target_identity"`
	Database       string `json:"database"`
	DatabaseOID    uint32 `json:"database_oid"`
	Kind           string `json:"kind"`
	Schema         string `json:"schema,omitempty"`
	SchemaOID      uint32 `json:"schema_oid,omitempty"`
	Name           string `json:"name"`
	ObjectOID      uint32 `json:"object_oid"`
	OwnerOID       uint32 `json:"owner_oid"`
	Privilege      string `json:"privilege"`
	Column         string `json:"column,omitempty"`
	ColumnNumber   int16  `json:"column_number,omitempty"`
}

type PostgresACLGrantor struct {
	OID         uint32 `json:"oid"`
	Name        string `json:"name"`
	GrantOption bool   `json:"grant_option"`
}

type PostgresObjectACLPins struct {
	AdminIdentity         string               `json:"admin_identity"`
	TargetIdentity        string               `json:"target_identity"`
	ConfigIncarnation     string               `json:"config_incarnation"`
	CredentialIncarnation int                  `json:"credential_incarnation"`
	SubjectOID            uint32               `json:"subject_oid"`
	Grantors              []PostgresACLGrantor `json:"grantors,omitempty"`
}

func IsPostgresObjectACLChange(kind ChangeKind) bool {
	return kind == ChangePostgresObjectACLGrantV1 || kind == ChangePostgresObjectACLRevokeV1
}

func PostgresObjectPrivileges(kind string) []string {
	switch kind {
	case "database":
		return []string{"CONNECT", "CREATE", "TEMPORARY"}
	case "schema":
		return []string{"USAGE", "CREATE"}
	case "table":
		return []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"}
	case "view":
		return []string{"SELECT", "INSERT", "UPDATE", "DELETE"}
	case "materialized_view":
		return []string{"SELECT"}
	case "sequence":
		return []string{"USAGE", "SELECT", "UPDATE"}
	case "column":
		return []string{"SELECT", "INSERT", "UPDATE", "REFERENCES"}
	default:
		return nil
	}
}

func validACLIdentifier(s string) bool {
	return s != "" && len(s) <= 63 && !strings.ContainsRune(s, 0)
}

func (p PostgresObjectPrivilege) Validate() error {
	if !strings.HasPrefix(p.TargetIdentity, "postgres:system:") || len(p.TargetIdentity) <= len("postgres:system:") ||
		!validACLIdentifier(p.Database) || !validACLIdentifier(p.Name) || p.DatabaseOID == 0 || p.ObjectOID == 0 || p.OwnerOID == 0 ||
		!slices.Contains(PostgresObjectPrivileges(p.Kind), p.Privilege) {
		return ErrPostgresObjectACL
	}
	if p.Kind == "database" {
		if p.Schema != "" || p.SchemaOID != 0 || p.Name != p.Database || p.ObjectOID != p.DatabaseOID {
			return ErrPostgresObjectACL
		}
	} else if !validACLIdentifier(p.Schema) || p.SchemaOID == 0 || strings.HasPrefix(p.Schema, "pg_") || p.Schema == "information_schema" {
		return ErrPostgresObjectACL
	}
	if p.Kind == "schema" && (p.Name != p.Schema || p.ObjectOID != p.SchemaOID) {
		return ErrPostgresObjectACL
	}
	if p.Kind == "column" {
		if !validACLIdentifier(p.Column) || p.ColumnNumber <= 0 {
			return ErrPostgresObjectACL
		}
	} else if p.Column != "" || p.ColumnNumber != 0 {
		return ErrPostgresObjectACL
	}
	return nil
}

func (p PostgresObjectPrivilege) PermissionID() string {
	b, _ := json.Marshal(p)
	return PostgresObjectACLPrefix + base64.RawURLEncoding.EncodeToString(b)
}

func ParsePostgresObjectPrivilege(id string) (PostgresObjectPrivilege, error) {
	var p PostgresObjectPrivilege
	if !strings.HasPrefix(id, PostgresObjectACLPrefix) || len(id) > 4096 {
		return p, ErrPostgresObjectACL
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(id, PostgresObjectACLPrefix))
	if err != nil {
		return p, ErrPostgresObjectACL
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || p.Validate() != nil || p.PermissionID() != id {
		return p, ErrPostgresObjectACL
	}
	return p, nil
}

func (p PostgresObjectPrivilege) Scope() string {
	switch p.Kind {
	case "database":
		return "db:" + p.Database
	case "schema":
		return "schema:" + p.Database + "." + p.Schema
	case "column":
		return "table:" + p.Database + "." + p.Schema + "." + p.Name
	default:
		return p.Kind + ":" + p.Database + "." + p.Schema + "." + p.Name
	}
}

func (p PostgresObjectPrivilege) Label() string {
	if p.Kind == "database" {
		return p.Database
	}
	if p.Kind == "schema" {
		return p.Database + "." + p.Schema
	}
	s := p.Database + "." + p.Schema + "." + p.Name
	if p.Column != "" {
		s += "." + p.Column
	}
	return s
}

func ValidatePostgresObjectACLChange(c DesiredChange) error {
	p, err := ParsePostgresObjectPrivilege(c.Permission)
	f := c.ObjectACL
	if err != nil || !IsPostgresObjectACLChange(c.Kind) || f == nil || p.Kind == "column" ||
		f.AdminIdentity == "" || f.TargetIdentity != p.TargetIdentity || f.ConfigIncarnation == "" || f.CredentialIncarnation <= 0 || f.SubjectOID == 0 ||
		c.ExpectedAdminIdentity != f.AdminIdentity || c.ExpectedTargetIdentity != f.TargetIdentity ||
		c.Scope != p.Scope() || (c.Account.Kind != "login" && c.Account.Kind != "group") || !validACLIdentifier(c.Account.EngineIdentity) ||
		strings.HasPrefix(strings.ToLower(c.Account.EngineIdentity), "pg_") || c.Account.EngineIdentity == f.AdminIdentity ||
		c.Account.AuthenticationScope != "" || len(c.AccountPermissions) != 0 || len(c.Attributes) != 0 ||
		c.StatsMembership != nil || c.RolePolicySpec != nil || c.Resource != nil || c.Credential != nil ||
		c.ExpectedDatabaseOID != 0 || c.ExpectedDatabaseOwner != "" || c.ExpectedDatabaseOwnerOID != 0 {
		return ErrPostgresObjectACL
	}
	seen := map[uint32]bool{}
	for _, g := range f.Grantors {
		if g.OID == 0 || !validACLIdentifier(g.Name) || g.GrantOption || seen[g.OID] {
			return ErrPostgresObjectACL
		}
		seen[g.OID] = true
	}
	return nil
}
