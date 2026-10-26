package connector

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/postgresconfig"
)

var postgresV2FingerprintRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

func isPostgresV2ChangeKind(kind adapter.ChangeKind) bool {
	return adapter.IsPostgresSuperuserDirectChange(kind)
}

// validatePostgresV2Change is the connector trust-boundary schema for the
// SUPERUSER-direct vocabulary. It deliberately accepts no raw SQL or generic
// attributes. All mutations pin the physical target, and policy mutations
// additionally pin the database incarnation.
func validatePostgresV2Change(p MutationPayload, kind adapter.ChangeKind) error {
	if p.Connection.Engine != "postgres" {
		return fmt.Errorf("connector: PostgreSQL v2 change kind %q requires engine postgres", kind)
	}
	if p.Connection.ConfigIncarnation == "" {
		return fmt.Errorf("connector: PostgreSQL v2 change kind %q requires config_incarnation", kind)
	}
	c := p.Change
	if c.ExpectedAdminIdentity == "" {
		return fmt.Errorf("connector: PostgreSQL v2 change kind %q requires expected_admin_identity", kind)
	}
	if c.ExpectedTargetIdentity == "" {
		return fmt.Errorf("connector: PostgreSQL v2 change kind %q requires expected_target_identity", kind)
	}
	if len(c.Attributes) != 0 {
		return fmt.Errorf("connector: PostgreSQL v2 change kind %q does not accept generic attributes", kind)
	}
	if err := validatePostgresV2ConnectionAttributes(p.Attributes); err != nil {
		return err
	}
	if !adapter.IsPostgresStatsMembershipChange(kind) && c.StatsMembership != nil {
		return fmt.Errorf("connector: PostgreSQL change kind %q does not accept statistics membership pins", kind)
	}
	if !adapter.IsPostgresObjectACLChange(kind) && c.ObjectACL != nil {
		return adapter.ErrPostgresObjectACL
	}

	switch kind {
	case adapter.ChangePostgresObjectACLGrantV1, adapter.ChangePostgresObjectACLRevokeV1:
		if c.ObjectACL == nil || c.ObjectACL.ConfigIncarnation != p.Connection.ConfigIncarnation || c.ExpectedCatalogFingerprint != "" {
			return adapter.ErrPostgresObjectACL
		}
		return adapter.ValidatePostgresObjectACLChange(adapter.DesiredChange{Kind: kind, Account: adapter.Account{
			Kind: c.Account.Kind, EngineIdentity: c.Account.EngineIdentity, AuthenticationScope: c.Account.AuthenticationScope},
			Permission: c.Permission, Scope: c.Scope, ObjectACL: c.ObjectACL, Attributes: c.Attributes, AccountPermissions: c.AccountPermissions,
			StatsMembership: c.StatsMembership, Resource: c.Resource, RolePolicySpec: c.RolePolicySpec, ExpectedAdminIdentity: c.ExpectedAdminIdentity,
			ExpectedTargetIdentity: c.ExpectedTargetIdentity, ExpectedDatabaseOID: c.ExpectedDatabaseOID,
			ExpectedDatabaseOwner: c.ExpectedDatabaseOwner, ExpectedDatabaseOwnerOID: c.ExpectedDatabaseOwnerOID})
	case adapter.ChangePostgresStatsMembershipGrantV1, adapter.ChangePostgresStatsMembershipRevokeV1:
		pins := c.StatsMembership
		if pins == nil || pins.AdminIdentity != c.ExpectedAdminIdentity || pins.TargetIdentity != c.ExpectedTargetIdentity ||
			pins.ConfigIncarnation != p.Connection.ConfigIncarnation || pins.CredentialIncarnation <= 0 ||
			pins.BuiltinOID == 0 || pins.SubjectOID == 0 || c.Permission != "role:pg_read_all_stats" ||
			c.Account.Kind != "login" || c.Account.EngineIdentity == "" || strings.HasPrefix(strings.ToLower(c.Account.EngineIdentity), "pg_") ||
			c.Account.AuthenticationScope != "" || c.Scope != "" || len(c.AccountPermissions) != 0 ||
			c.Resource != nil || c.RolePolicySpec != nil || c.ExpectedDatabaseOID != 0 ||
			c.ExpectedDatabaseOwner != "" || c.ExpectedDatabaseOwnerOID != 0 || c.ExpectedCatalogFingerprint != "" {
			return fmt.Errorf("connector: statistics membership v1 requires an exact protected permission, login subject and complete matching identity pins")
		}
	case adapter.ChangePostgresAccountCreateV2:
		if c.Account.Kind != "login" || c.Account.EngineIdentity == "" ||
			c.Account.AuthenticationScope != "" || c.Permission != "" || c.Scope != "" ||
			len(c.AccountPermissions) != 0 || c.Resource != nil || c.RolePolicySpec != nil ||
			c.ExpectedDatabaseOID != 0 || c.ExpectedDatabaseOwner != "" ||
			c.ExpectedDatabaseOwnerOID != 0 || c.ExpectedCatalogFingerprint != "" {
			return fmt.Errorf("connector: postgres.account.create.v2 requires only a named login account and target identity")
		}
	case adapter.ChangePostgresAccountRestoreV2:
		if c.Account.Kind != "login" || c.Account.EngineIdentity == "" ||
			c.Account.AuthenticationScope != "" || c.Permission != "" || c.Scope != "" ||
			len(c.AccountPermissions) != 0 || c.Resource != nil || c.RolePolicySpec != nil ||
			c.ExpectedDatabaseOID != 0 || c.ExpectedDatabaseOwner != "" ||
			c.ExpectedDatabaseOwnerOID != 0 || c.ExpectedCatalogFingerprint != "" {
			return fmt.Errorf("connector: postgres.account.restore.v2 requires only a named login account and target identity")
		}
	case adapter.ChangePostgresRoleCreateV2:
		if c.Account.Kind != "group" || c.Account.EngineIdentity == "" ||
			c.Account.AuthenticationScope != "" || c.Permission != "" || c.Scope != "" ||
			len(c.AccountPermissions) != 0 || c.Resource != nil || c.RolePolicySpec != nil ||
			c.ExpectedDatabaseOID != 0 || c.ExpectedDatabaseOwner != "" ||
			c.ExpectedDatabaseOwnerOID != 0 || c.ExpectedCatalogFingerprint != "" {
			return fmt.Errorf("connector: postgres.role.create.v2 requires only a named group account and target identity")
		}
	case adapter.ChangePostgresDatabaseCreateV2:
		if c.Resource == nil || c.Resource.Kind != "database" || c.Resource.Name == "" ||
			c.Account != (AccountRef{}) || c.Permission != "" || c.Scope != "" ||
			len(c.AccountPermissions) != 0 || c.RolePolicySpec != nil || c.ExpectedDatabaseOID != 0 ||
			c.ExpectedDatabaseOwner == "" || c.ExpectedDatabaseOwnerOID == 0 ||
			c.ExpectedCatalogFingerprint != "" {
			return fmt.Errorf("connector: postgres.resource.create.database.v2 requires only a named database resource and target identity")
		}
		if err := validatePostgresV2DatabaseAttributes(c.Resource.Attributes); err != nil {
			return err
		}
		owner, _ := c.Resource.Attributes["owner"].(string)
		if owner == "" || owner != c.ExpectedDatabaseOwner {
			return fmt.Errorf("connector: PostgreSQL v2 database owner pin does not match the resource owner")
		}
	case adapter.ChangePostgresRolePolicyApplyV2,
		adapter.ChangePostgresRolePolicyVerifyV2,
		adapter.ChangePostgresRolePolicyAdoptV2,
		adapter.ChangePostgresRolePolicyRepairV2,
		adapter.ChangePostgresRolePolicyCreateV2,
		adapter.ChangePostgresRolePolicyCreateDatabaseV2:
		if c.RolePolicySpec == nil || c.RolePolicySpec.Engine != "postgres" ||
			c.ExpectedDatabaseOID == 0 || c.ExpectedDatabaseOwner == "" ||
			c.ExpectedDatabaseOwnerOID == 0 ||
			!postgresV2FingerprintRE.MatchString(c.ExpectedCatalogFingerprint) ||
			c.Account != (AccountRef{}) || c.Scope != "" ||
			len(c.AccountPermissions) != 0 || c.Resource != nil {
			return fmt.Errorf("connector: PostgreSQL v2 role policy requires a typed spec, target identity and database OID")
		}
		if len(c.RolePolicySpec.MongoInheritedRoles) != 0 || len(c.RolePolicySpec.MongoPrivileges) != 0 {
			return fmt.Errorf("connector: PostgreSQL v2 role policy does not accept MongoDB fields")
		}
		if kind == adapter.ChangePostgresRolePolicyCreateDatabaseV2 {
			if c.Permission != "" {
				return fmt.Errorf("connector: database-pinned PostgreSQL v2 role creation does not accept permission")
			}
		} else if c.Permission == "" {
			return fmt.Errorf("connector: PostgreSQL v2 role policy change kind %q requires permission", kind)
		}
	default:
		return fmt.Errorf("connector: unknown PostgreSQL v2 change kind %q", kind)
	}
	return nil
}

// validatePostgresV2JSONShape closes tagged union fields which a generic Go
// struct decoder cannot distinguish from valid fields of another engine.
// Presence is rejected even when the MongoDB-only array is empty.
func validatePostgresV2JSONShape(raw json.RawMessage, kind adapter.ChangeKind) error {
	if !postgresV2RolePolicyKind(kind) {
		return nil
	}
	var document struct {
		Change struct {
			RolePolicySpec map[string]json.RawMessage `json:"role_policy_spec"`
		} `json:"change"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return fmt.Errorf("connector: inspect PostgreSQL v2 role policy shape: %w", err)
	}
	allowed := map[string]struct{}{
		"engine": {}, "key": {}, "name": {}, "description": {},
		"role_name": {}, "database": {}, "schemas": {},
		"owner_roles": {}, "creator_roles": {}, "profile": {},
	}
	for field := range document.Change.RolePolicySpec {
		if _, ok := allowed[field]; !ok {
			return fmt.Errorf("connector: PostgreSQL v2 role policy field %q is not allowed", field)
		}
	}
	return nil
}

func postgresV2RolePolicyKind(kind adapter.ChangeKind) bool {
	switch kind {
	case adapter.ChangePostgresRolePolicyApplyV2,
		adapter.ChangePostgresRolePolicyVerifyV2,
		adapter.ChangePostgresRolePolicyAdoptV2,
		adapter.ChangePostgresRolePolicyRepairV2,
		adapter.ChangePostgresRolePolicyCreateV2,
		adapter.ChangePostgresRolePolicyCreateDatabaseV2:
		return true
	default:
		return false
	}
}

func validatePostgresV2ConnectionAttributes(attributes map[string]any) error {
	for key, value := range attributes {
		switch key {
		case "database":
			if _, ok := value.(string); !ok {
				return fmt.Errorf("connector: PostgreSQL v2 connection attribute %q must be a string", key)
			}
		case adapter.AttrDatabaseCreateTemplates,
			adapter.AttrDatabaseCreateOwners,
			adapter.AttrDatabaseCreateTablespaces:
			if err := validatePostgresV2StringList(value); err != nil {
				return fmt.Errorf("connector: PostgreSQL v2 connection attribute %q: %w", key, err)
			}
		case postgresconfig.AttributeRolePolicyTemplates:
			if _, err := postgresconfig.FromAttributes(map[string]any{key: value}); err != nil {
				return fmt.Errorf("connector: PostgreSQL v2 connection attribute %q: %w", key, err)
			}
		default:
			return fmt.Errorf("connector: PostgreSQL v2 connection attribute %q is not allowed", key)
		}
	}
	return nil
}

func validatePostgresV2StringList(value any) error {
	switch values := value.(type) {
	case []string:
		return nil
	case []any:
		for _, item := range values {
			if _, ok := item.(string); !ok {
				return fmt.Errorf("must contain only strings")
			}
		}
		return nil
	default:
		return fmt.Errorf("must be an array of strings")
	}
}

func validatePostgresV2DatabaseAttributes(attributes map[string]any) error {
	for key, value := range attributes {
		switch key {
		case "owner", "template", "encoding", "locale", "tablespace":
			if _, ok := value.(string); !ok {
				return fmt.Errorf("connector: PostgreSQL v2 database option %q must be a string", key)
			}
		case "connection_limit":
			number, ok := value.(float64)
			if !ok || number != float64(int(number)) || number < -1 {
				return fmt.Errorf("connector: PostgreSQL v2 database option %q must be an integer greater than or equal to -1", key)
			}
		default:
			return fmt.Errorf("connector: PostgreSQL v2 database option %q is not allowed", key)
		}
	}
	return nil
}
