package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
	"github.com/ArtefactoO/grantor/internal/postgresconfig"
)

const (
	rolePolicyPreviewLimit = 50

	rolePolicyCatalogFingerprintKey = "postgres_role_policy_catalog_fingerprint"
	rolePolicyApplySupportedKey     = "postgres_role_policy_apply_supported"
	rolePolicyCreateSupportedKey    = "postgres_role_policy_create_supported"
)

var _ adapter.ConnectionCapabilityScoper = (*Adapter)(nil)

// CapabilitiesFor exposes the v2 creation contract only for the exact
// discovery-time SUPERUSER/config/credential attestation. API/jobs still
// perform a current snapshot guard and every adapter Plan repeats the live
// proof before the first target side effect.
func (a *Adapter) CapabilitiesFor(cfg adapter.Connection, topology map[string]any) []adapter.Capability {
	caps := slices.Clone(a.Manifest().Capabilities)
	authority, authorityOK := adapter.ProvisioningAuthorityFromTopology(
		topology, adapter.PostgresProvisioningAuthorityTopologyKey,
	)
	authorityOK = authorityOK && authority.Status == adapter.ProvisioningAuthorityConfirmed &&
		authority.Reason == adapter.ProvisioningAuthoritySuperuserConfirmed &&
		authority.CredentialIncarnation > 0 && cfg.ConfigIncarnation != "" &&
		authority.ConfigIncarnation == cfg.ConfigIncarnation && authority.TargetIdentity != ""
	caps = slices.DeleteFunc(caps, func(capability adapter.Capability) bool {
		if authorityOK {
			return false
		}
		return capability == adapter.CapAccountCreate ||
			capability == adapter.CapAccountRestore ||
			capability == adapter.CapRoleCreate ||
			capability == adapter.ResourceCapability("create", resourceKindDatabase) ||
			capability == adapter.CapRolePolicyApply ||
			capability == adapter.CapRolePolicyCreate ||
			capability == adapter.CapPostgresSuperuserDirectV1
	})
	if authorityOK {
		templates, err := postgresconfig.FromAttributes(cfg.Attributes)
		catalogMatches := err == nil && adapterutil.StringAttr(topology, rolePolicyCatalogFingerprintKey) ==
			postgresconfig.CatalogFingerprint(templates)
		applyReady, _ := topology[rolePolicyApplySupportedKey].(bool)
		createReady, _ := topology[rolePolicyCreateSupportedKey].(bool)
		caps = slices.DeleteFunc(caps, func(capability adapter.Capability) bool {
			return capability == adapter.CapRolePolicyApply && (!catalogMatches || !applyReady) ||
				capability == adapter.CapRolePolicyCreate && (!catalogMatches || !createReady)
		})
	}
	return adapter.ScopeAdminCredentialCapabilities(caps, topology)
}

func isRolePolicyCreate(kind adapter.ChangeKind) bool {
	return kind == adapter.ChangeRolePolicyCreate || kind == adapter.ChangeRolePolicyCreateDatabase
}

func validateRolePolicyChange(change adapter.DesiredChange) error {
	if change.Resource != nil {
		return errors.New("postgres: role policy change must not carry a resource spec")
	}
	if change.Kind == adapter.ChangeRolePolicyCreateDatabase {
		if change.ExpectedDatabaseOID == 0 {
			return fmt.Errorf("postgres: database role policy requires expected database OID: %w", adapter.ErrTargetIdentityConflict)
		}
		if change.Credential != nil || change.Account != (adapter.Account{}) ||
			change.Permission != "" || change.Scope != "" || len(change.AccountPermissions) != 0 || len(change.Attributes) != 0 {
			return errors.New("postgres: database role policy must not carry account or access attributes")
		}
		spec := change.RolePolicySpec
		if spec == nil || len(spec.OwnerRoles) != 1 || len(spec.CreatorRoles) != 1 ||
			spec.OwnerRoles[0] == "" || spec.CreatorRoles[0] != spec.OwnerRoles[0] {
			return errors.New("postgres: database role policy requires the single database owner as owner and creator")
		}
	} else if change.ExpectedDatabaseOID != 0 {
		return errors.New("postgres: only role.policy.create_database accepts expected database OID")
	}
	return nil
}

type rolePolicyRoleState struct {
	exists                bool
	safe                  bool
	canLogin              bool
	super                 bool
	createDB              bool
	createRole            bool
	replication           bool
	bypassRLS             bool
	inherit               bool
	passwordAbsent        bool
	adminMembershipAbsent bool
	adminIdentity         string
}

type rolePolicyState struct {
	expected map[string]struct{}
	actual   map[string]struct{}
	role     rolePolicyRoleState
	// PUBLIC grants are effective for every role but PostgreSQL has no
	// per-role DENY. They are reported separately and never enter exactness.
	publicPrivilegeCount int
	hardBlockCode        string
	missing              []string
	extra                []string
}

type rolePolicyQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func newRolePolicyState(template postgresconfig.RolePolicyTemplate) *rolePolicyState {
	base := "spec:" + postgresconfig.Fingerprint(template)
	return &rolePolicyState{
		expected: map[string]struct{}{base: {}},
		actual:   map[string]struct{}{base: {}},
	}
}

func (s *rolePolicyState) finish() {
	s.missing = setDifference(s.expected, s.actual)
	s.extra = setDifference(s.actual, s.expected)
}

func rolePolicySpec(template postgresconfig.RolePolicyTemplate) adapter.RolePolicySpec {
	template = postgresconfig.Normalize(template)
	return adapter.RolePolicySpec{
		Engine: Engine, Key: template.Key, Name: template.Name,
		Description: template.Description, RoleName: template.RoleName,
		Database: template.Database, Schemas: slices.Clone(template.Schemas),
		OwnerRoles:   slices.Clone(template.OwnerRoles),
		CreatorRoles: slices.Clone(template.CreatorRoles), Profile: template.Profile,
	}
}

func rolePolicyTemplate(spec *adapter.RolePolicySpec) (postgresconfig.RolePolicyTemplate, error) {
	if spec == nil {
		return postgresconfig.RolePolicyTemplate{}, errors.New("role policy spec is required")
	}
	if spec.Engine != "" && spec.Engine != Engine {
		return postgresconfig.RolePolicyTemplate{}, fmt.Errorf("role policy engine %q is not postgres", spec.Engine)
	}
	template := postgresconfig.RolePolicyTemplate{
		Key: spec.Key, Name: spec.Name, Description: spec.Description,
		RoleName: spec.RoleName, Database: spec.Database,
		Schemas: slices.Clone(spec.Schemas), OwnerRoles: slices.Clone(spec.OwnerRoles),
		CreatorRoles: slices.Clone(spec.CreatorRoles), Profile: spec.Profile,
	}
	if err := postgresconfig.Validate([]postgresconfig.RolePolicyTemplate{template}); err != nil {
		return postgresconfig.RolePolicyTemplate{}, err
	}
	return postgresconfig.Normalize(template), nil
}

func unavailableRolePolicy(template postgresconfig.RolePolicyTemplate, reason string) adapter.ObservedRolePolicy {
	state := newRolePolicyState(template)
	addStaticExpectedState(state, template)
	state.finish()
	return observedRolePolicy(template, state, adapter.ProvisioningAuthorityAssessment{}, false, reason, false)
}

// discoverRolePolicies performs exact role-policy read-back independently per
// configured database. A broken database remains a visible blocked row and
// does not hide healthy policies in another database.
func (a *Adapter) discoverRolePolicies(
	ctx context.Context,
	cfg adapter.Connection,
	templates []postgresconfig.RolePolicyTemplate,
	expectedSystemIdentifier string,
	authority adapter.ProvisioningAuthorityAssessment,
) ([]adapter.ObservedRolePolicy, string) {
	policies := make([]adapter.ObservedRolePolicy, 0, len(templates))
	provenSystemIdentifier := expectedSystemIdentifier

	byDatabase := make(map[string][]postgresconfig.RolePolicyTemplate)
	var databases []string
	for _, template := range templates {
		if _, exists := byDatabase[template.Database]; !exists {
			databases = append(databases, template.Database)
		}
		byDatabase[template.Database] = append(byDatabase[template.Database], template)
	}
	slices.Sort(databases)
	for _, database := range databases {
		conn, err := a.connect(ctx, cfg, database)
		if err != nil {
			for _, template := range byDatabase[database] {
				policies = append(policies, unavailableRolePolicy(template, "database_unavailable"))
			}
			continue
		}
		var inRecovery bool
		if err := conn.QueryRow(ctx, `select pg_is_in_recovery()`).Scan(&inRecovery); err != nil {
			for _, template := range byDatabase[database] {
				policies = append(policies, unavailableRolePolicy(template, "topology_probe_failed"))
			}
			closeQuietly(ctx, conn)
			continue
		}
		identityReason := ""
		systemIdentifier, identityOK := discoverSystemIdentifier(ctx, conn)
		if !identityOK || provenSystemIdentifier != "" && systemIdentifier != provenSystemIdentifier {
			identityReason = "target_identity_mismatch"
		} else if provenSystemIdentifier == "" {
			provenSystemIdentifier = systemIdentifier
		}

		for _, template := range byDatabase[database] {
			state, observeErr := observeRolePolicyState(ctx, conn, template)
			if observeErr != nil {
				policies = append(policies, unavailableRolePolicy(template, "policy_observation_failed"))
				continue
			}
			if state.role.exists {
				safety, safetyErr := inspectPolicyRoleAcrossCluster(ctx, conn, template.RoleName, template.Database)
				applyCrossDatabaseSafetyObservation(state, safety, safetyErr)
			}
			reason := state.hardBlockCode
			applySupported := false
			if reason == "" && identityReason != "" {
				reason = identityReason
			}
			if reason == "" && inRecovery {
				reason = "read_only_replica"
			}
			if reason == "" {
				switch authority.Status {
				case adapter.ProvisioningAuthorityInsufficient:
					reason = string(adapter.ProvisioningAuthoritySuperuserRequired)
				case adapter.ProvisioningAuthorityConfirmed:
					if authority.Reason == adapter.ProvisioningAuthoritySuperuserConfirmed {
						applySupported = true
					} else {
						reason = string(authority.Reason)
					}
				default:
					reason = string(authority.Reason)
					if reason == "" {
						reason = string(adapter.ProvisioningAuthorityProbeFailed)
					}
				}
			}
			policy := observedRolePolicy(template, state, authority, inRecovery, reason, applySupported)
			policies = append(policies, policy)
		}
		closeQuietly(ctx, conn)
	}

	slices.SortFunc(policies, func(a, b adapter.ObservedRolePolicy) int {
		return strings.Compare(a.ExternalID, b.ExternalID)
	})
	return policies, provenSystemIdentifier
}

func observedRolePolicy(
	template postgresconfig.RolePolicyTemplate,
	state *rolePolicyState,
	authority adapter.ProvisioningAuthorityAssessment,
	inRecovery bool,
	reason string,
	applySupported bool,
) adapter.ObservedRolePolicy {
	state.finish()
	expectedFingerprint := fingerprintPolicyTokens(state.expected)
	observedFingerprint := fingerprintPolicyTokens(state.actual)
	missing, missingTruncated := previewPolicyTokens(state.missing)
	extra, extraTruncated := previewPolicyTokens(state.extra)
	summary := map[string]any{
		"missing":       missing,
		"extra":         extra,
		"missing_count": len(state.missing),
		"extra_count":   len(state.extra),
		"truncated":     missingTruncated || extraTruncated,
		"authority":     authority,
		"role": map[string]any{
			"exists":                  state.role.exists,
			"safe":                    state.role.safe,
			"admin_membership_absent": state.role.adminMembershipAbsent,
			"admin_identity":          state.role.adminIdentity,
		},
		"read_only": inRecovery,
		"public_privileges": map[string]any{
			"policy_surface_count": state.publicPrivilegeCount,
			"count_scope":          "configured_database_schemas_owner_objects_and_creator_defaults",
			"exactness_scope":      "out_of_scope_no_per_role_deny",
		},
	}
	return adapter.ObservedRolePolicy{
		ExternalID:          rolePermissionID(template.RoleName),
		Spec:                rolePolicySpec(template),
		ExpectedFingerprint: expectedFingerprint,
		ObservedFingerprint: observedFingerprint,
		Exact:               expectedFingerprint == observedFingerprint,
		ApplySupported:      applySupported,
		BlockedReason:       reason,
		Summary:             summary,
	}
}

// annotateRolePolicyPermissions keeps configured policy roles nonassignable
// in the adapter snapshot. The generic lifecycle enables the permission only
// after the policy has been explicitly adopted/applied and is managed+synced.
func annotateRolePolicyPermissions(
	permissions []adapter.ObservedPermission,
	policies []adapter.ObservedRolePolicy,
) []adapter.ObservedPermission {
	byRole := make(map[string]adapter.ObservedRolePolicy, len(policies))
	for _, policy := range policies {
		byRole[policy.Spec.RoleName] = policy
	}
	seen := make(map[string]bool, len(permissions))
	for i := range permissions {
		policy, configured := byRole[permissions[i].Name]
		if !configured {
			continue
		}
		seen[permissions[i].Name] = true
		permissions[i].Assignable = false
		permissions[i].Attributes = cloneAttributes(permissions[i].Attributes)
		permissions[i].Attributes["role_policy_key"] = policy.Spec.Key
		permissions[i].Attributes["role_policy_exact"] = policy.Exact
		permissions[i].Attributes["role_policy_apply_supported"] = policy.ApplySupported
	}
	for role, policy := range byRole {
		if seen[role] {
			continue
		}
		permissions = append(permissions, adapter.ObservedPermission{
			ExternalID: rolePermissionID(role),
			Name:       role,
			Assignable: false,
			Dangerous:  policy.BlockedReason == "role_has_unsafe_attributes",
			Attributes: map[string]any{
				"role_policy_key":                    policy.Spec.Key,
				"role_policy_exact":                  policy.Exact,
				"role_policy_apply_supported":        policy.ApplySupported,
				"role_policy_role_missing_or_unsafe": true,
			},
			AccountEngineIdentity: role,
		})
	}
	return permissions
}

func cloneAttributes(attributes map[string]any) map[string]any {
	out := make(map[string]any, len(attributes)+3)
	for key, value := range attributes {
		out[key] = value
	}
	return out
}

func observeRolePolicyState(
	ctx context.Context,
	conn rolePolicyQuerier,
	template postgresconfig.RolePolicyTemplate,
) (*rolePolicyState, error) {
	state := newRolePolicyState(template)
	var admin string
	if err := conn.QueryRow(ctx, `select session_user`).Scan(&admin); err != nil {
		return nil, fmt.Errorf("read role policy admin identity: %w", err)
	}
	addStaticExpectedState(state, template)
	state.role.adminIdentity = admin
	state.expected["role:admin_not_member:"+admin] = struct{}{}

	if err := observePolicyReferences(ctx, conn, template, state); err != nil {
		return nil, err
	}
	publicCount, err := observePolicyPublicPrivilegeCount(ctx, conn, template)
	if err != nil {
		return nil, err
	}
	state.publicPrivilegeCount = publicCount
	if err := observePolicyRole(ctx, conn, template.RoleName, admin, state); err != nil {
		return nil, err
	}
	objects, err := discoverPolicyObjects(ctx, conn, template)
	if err != nil {
		return nil, err
	}
	addExpectedPolicyACLs(state.expected, template, objects)
	if err := observeActualPolicyACLs(ctx, conn, template.RoleName, state.actual); err != nil {
		return nil, err
	}
	dependent, err := observeDependentPolicyGrants(ctx, conn, template.RoleName, state.actual)
	if err != nil {
		return nil, err
	}
	if dependent && state.hardBlockCode == "" {
		state.hardBlockCode = "role_has_dependent_grants"
	}
	state.finish()
	return state, nil
}

func observePolicyPublicPrivilegeCount(
	ctx context.Context,
	conn rolePolicyQuerier,
	template postgresconfig.RolePolicyTemplate,
) (int, error) {
	var count int
	err := conn.QueryRow(ctx, `
		select count(*)
		from (
			select 1
			from pg_catalog.pg_database d
			cross join lateral pg_catalog.aclexplode(
				coalesce(d.datacl, pg_catalog.acldefault('d', d.datdba))) acl
			where d.datname = $1 and acl.grantee = 0
			union all
			select 1
			from pg_catalog.pg_namespace n
			cross join lateral pg_catalog.aclexplode(
				coalesce(n.nspacl, pg_catalog.acldefault('n', n.nspowner))) acl
			where n.nspname = any($2::name[]) and acl.grantee = 0
			union all
			select 1
			from pg_catalog.pg_class c
			join pg_catalog.pg_namespace n on n.oid = c.relnamespace
			join pg_catalog.pg_roles owner_role on owner_role.oid = c.relowner
			cross join lateral pg_catalog.aclexplode(c.relacl) acl
			where n.nspname = any($2::name[])
			  and owner_role.rolname = any($3::name[])
			  and c.relkind in ('r','p','v','m','f','S') and acl.grantee = 0
			union all
			select 1
			from pg_catalog.pg_default_acl d
			join pg_catalog.pg_roles creator on creator.oid = d.defaclrole
			left join pg_catalog.pg_namespace n on n.oid = d.defaclnamespace
			cross join lateral pg_catalog.aclexplode(d.defaclacl) acl
			where creator.rolname = any($4::name[])
			  and (n.oid is null or n.nspname = any($2::name[]))
			  and acl.grantee = 0
		) public_acl`, template.Database, template.Schemas, template.OwnerRoles, template.CreatorRoles).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("observe PUBLIC role policy privileges: %w", err)
	}
	return count, nil
}

func addStaticExpectedState(state *rolePolicyState, template postgresconfig.RolePolicyTemplate) {
	for _, token := range []string{
		"role:exists", "role:nologin", "role:safe", "role:inherit",
		"role:no_password", "role:no_ownership", "role:no_inherited_roles", "role:no_unexpected_admin_option",
	} {
		state.expected[token] = struct{}{}
	}
	for _, schema := range template.Schemas {
		state.expected["reference:schema:"+schema] = struct{}{}
	}
	for _, owner := range template.OwnerRoles {
		state.expected["reference:owner:"+owner] = struct{}{}
	}
	for _, creator := range template.CreatorRoles {
		state.expected["reference:creator:"+creator] = struct{}{}
	}
}

func observePolicyReferences(ctx context.Context, conn rolePolicyQuerier, template postgresconfig.RolePolicyTemplate, state *rolePolicyState) error {
	for _, schema := range template.Schemas {
		var exists bool
		if err := conn.QueryRow(ctx,
			`select exists (select 1 from pg_namespace where nspname = $1)`, schema).Scan(&exists); err != nil {
			return fmt.Errorf("check role policy schema: %w", err)
		}
		if exists {
			state.actual["reference:schema:"+schema] = struct{}{}
		} else if state.hardBlockCode == "" {
			state.hardBlockCode = "configured_schema_missing"
		}
	}
	roles := make(map[string]bool, len(template.OwnerRoles)+len(template.CreatorRoles))
	for _, name := range append(slices.Clone(template.OwnerRoles), template.CreatorRoles...) {
		if _, checked := roles[name]; checked {
			continue
		}
		var exists bool
		if err := conn.QueryRow(ctx,
			`select exists (select 1 from pg_roles where rolname = $1)`, name).Scan(&exists); err != nil {
			return fmt.Errorf("check role policy reference role: %w", err)
		}
		roles[name] = exists
	}
	for _, owner := range template.OwnerRoles {
		if roles[owner] {
			state.actual["reference:owner:"+owner] = struct{}{}
		} else if state.hardBlockCode == "" {
			state.hardBlockCode = "configured_owner_role_missing"
		}
	}
	for _, creator := range template.CreatorRoles {
		if roles[creator] {
			state.actual["reference:creator:"+creator] = struct{}{}
		} else if state.hardBlockCode == "" {
			state.hardBlockCode = "configured_creator_role_missing"
		}
	}
	return nil
}

func observePolicyRole(
	ctx context.Context,
	conn rolePolicyQuerier,
	roleName, admin string,
	state *rolePolicyState,
) error {
	err := conn.QueryRow(ctx, `
		select rolcanlogin, rolsuper, rolcreatedb, rolcreaterole,
		       rolreplication, rolbypassrls, rolinherit
		from pg_roles where rolname = $1`, roleName).Scan(
		&state.role.canLogin, &state.role.super, &state.role.createDB,
		&state.role.createRole, &state.role.replication,
		&state.role.bypassRLS, &state.role.inherit,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read policy role attributes: %w", err)
	}
	state.role.exists = true
	state.actual["role:exists"] = struct{}{}
	if !state.role.canLogin {
		state.actual["role:nologin"] = struct{}{}
	} else {
		state.actual["role:login"] = struct{}{}
	}
	state.role.safe = !state.role.canLogin && !state.role.super && !state.role.createDB &&
		!state.role.createRole && !state.role.replication && !state.role.bypassRLS && state.role.inherit
	if state.role.safe {
		state.actual["role:safe"] = struct{}{}
	} else {
		state.actual["role:unsafe"] = struct{}{}
		state.hardBlockCode = "role_has_unsafe_attributes"
	}
	if state.role.inherit {
		state.actual["role:inherit"] = struct{}{}
	} else {
		state.actual["role:noinherit"] = struct{}{}
	}
	if err := observePolicyRolePassword(ctx, conn, roleName, state); err != nil {
		return err
	}

	ownerships, err := readPolicyRoleOwnerships(ctx, conn, roleName)
	if err != nil {
		return err
	}
	if len(ownerships) == 0 {
		state.actual["role:no_ownership"] = struct{}{}
	} else {
		for _, ownership := range ownerships {
			state.actual["role:owns:"+ownership] = struct{}{}
		}
		if state.hardBlockCode == "" {
			state.hardBlockCode = "role_owns_database_objects"
		}
	}

	rows, err := conn.Query(ctx, `
		select parent.rolname
		from pg_auth_members am
		join pg_roles parent on parent.oid = am.roleid
		join pg_roles member on member.oid = am.member
		where member.rolname = $1
		order by parent.rolname`, roleName)
	if err != nil {
		return fmt.Errorf("query inherited policy roles: %w", err)
	}
	var inherited []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return fmt.Errorf("scan inherited policy role: %w", err)
		}
		inherited = append(inherited, name)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("read inherited policy roles: %w", err)
	}
	rows.Close()
	if len(inherited) == 0 {
		state.actual["role:no_inherited_roles"] = struct{}{}
	} else {
		for _, name := range inherited {
			state.actual["role:inherits:"+name] = struct{}{}
		}
		if state.hardBlockCode == "" {
			state.hardBlockCode = "role_inherits_other_roles"
		}
	}

	rows, err = conn.Query(ctx, `
		select member.rolname, grantor.rolname, am.admin_option,
		       coalesce((to_jsonb(am)->>'inherit_option')::boolean, false),
		       coalesce((to_jsonb(am)->>'set_option')::boolean, false)
		from pg_auth_members am
		join pg_roles granted on granted.oid = am.roleid
		join pg_roles member on member.oid = am.member
		join pg_roles grantor on grantor.oid = am.grantor
		where granted.rolname = $1
		order by member.rolname, grantor.rolname`, roleName)
	if err != nil {
		return fmt.Errorf("query policy role members: %w", err)
	}
	adminRows := 0
	unexpectedAdmin := false
	for rows.Next() {
		var member, grantor string
		var adminOption, inheritOption, setOption bool
		if err := rows.Scan(&member, &grantor, &adminOption, &inheritOption, &setOption); err != nil {
			rows.Close()
			return fmt.Errorf("scan policy role member: %w", err)
		}
		if member == admin {
			adminRows++
			state.actual[fmt.Sprintf("role:admin_membership:%s:grantor:%s:admin:%t:inherit:%t:set:%t",
				admin, grantor, adminOption, inheritOption, setOption)] = struct{}{}
		}
		if member != admin && adminOption {
			unexpectedAdmin = true
			state.actual["role:unexpected_admin_option:"+member] = struct{}{}
		}
	}
	state.role.adminMembershipAbsent = adminRows == 0
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("read policy role members: %w", err)
	}
	rows.Close()
	if adminRows == 0 {
		state.actual["role:admin_not_member:"+admin] = struct{}{}
	}
	if !unexpectedAdmin {
		state.actual["role:no_unexpected_admin_option"] = struct{}{}
	} else if state.hardBlockCode == "" {
		state.hardBlockCode = "unexpected_role_admin_option"
	}
	return nil
}

func observePolicyRolePassword(
	ctx context.Context,
	conn rolePolicyQuerier,
	roleName string,
	state *rolePolicyState,
) error {
	err := conn.QueryRow(ctx, `
		select rolpassword is null
		from pg_catalog.pg_authid
		where rolname = $1`, roleName).Scan(&state.role.passwordAbsent)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgCodeInsufficientPrivilege {
			state.actual["role:password_unobservable"] = struct{}{}
			if state.hardBlockCode == "" {
				state.hardBlockCode = "role_password_unobservable"
			}
			return nil
		}
		return fmt.Errorf("read policy role password presence: %w", err)
	}
	if state.role.passwordAbsent {
		state.actual["role:no_password"] = struct{}{}
	} else {
		state.actual["role:password_present"] = struct{}{}
	}
	return nil
}

func readPolicyRoleOwnerships(ctx context.Context, conn rolePolicyQuerier, roleName string) ([]string, error) {
	rows, err := conn.Query(ctx, `
		select 'database', d.datname
		from pg_database d join pg_roles r on r.oid = d.datdba
		where r.rolname = $1
		union all
		select 'schema', n.nspname
		from pg_namespace n join pg_roles r on r.oid = n.nspowner
		where r.rolname = $1
		union all
		select 'object', n.nspname || '.' || c.relname
		from pg_class c
		join pg_namespace n on n.oid = c.relnamespace
		join pg_roles r on r.oid = c.relowner
		where r.rolname = $1
		union all select 'routine', p.oid::regprocedure::text
		from pg_proc p join pg_roles r on r.oid = p.proowner where r.rolname = $1
		union all select 'type', t.oid::regtype::text
		from pg_type t join pg_roles r on r.oid = t.typowner where r.rolname = $1
		union all select 'large_object', l.oid::text
		from pg_largeobject_metadata l join pg_roles r on r.oid = l.lomowner where r.rolname = $1
		union all select 'foreign_data_wrapper', f.fdwname
		from pg_foreign_data_wrapper f join pg_roles r on r.oid = f.fdwowner where r.rolname = $1
		union all select 'foreign_server', s.srvname
		from pg_foreign_server s join pg_roles r on r.oid = s.srvowner where r.rolname = $1
		union all select 'language', l.lanname
		from pg_language l join pg_roles r on r.oid = l.lanowner where r.rolname = $1
		union all select 'tablespace', t.spcname
		from pg_tablespace t join pg_roles r on r.oid = t.spcowner where r.rolname = $1
		union all select 'extension', e.extname
		from pg_extension e join pg_roles r on r.oid = e.extowner where r.rolname = $1
		union all select 'publication', p.pubname
		from pg_publication p join pg_roles r on r.oid = p.pubowner where r.rolname = $1
		union all select 'subscription', s.subname
		from pg_subscription s join pg_roles r on r.oid = s.subowner where r.rolname = $1
		union all select 'event_trigger', e.evtname
		from pg_event_trigger e join pg_roles r on r.oid = e.evtowner where r.rolname = $1
		union all select 'collation', c.collname
		from pg_collation c join pg_roles r on r.oid = c.collowner where r.rolname = $1
		union all select 'conversion', c.conname
		from pg_conversion c join pg_roles r on r.oid = c.conowner where r.rolname = $1
		union all select 'operator', o.oprname
		from pg_operator o join pg_roles r on r.oid = o.oprowner where r.rolname = $1
		union all select 'operator_class', o.opcname
		from pg_opclass o join pg_roles r on r.oid = o.opcowner where r.rolname = $1
		union all select 'operator_family', o.opfname
		from pg_opfamily o join pg_roles r on r.oid = o.opfowner where r.rolname = $1
		union all select 'text_search_dictionary', d.dictname
		from pg_ts_dict d join pg_roles r on r.oid = d.dictowner where r.rolname = $1
		union all select 'text_search_config', c.cfgname
		from pg_ts_config c join pg_roles r on r.oid = c.cfgowner where r.rolname = $1
		union all select 'statistics', s.stxname
		from pg_statistic_ext s join pg_roles r on r.oid = s.stxowner where r.rolname = $1
		order by 1, 2`, roleName)
	if err != nil {
		return nil, fmt.Errorf("query policy role ownerships: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var kind, name string
		if err := rows.Scan(&kind, &name); err != nil {
			return nil, fmt.Errorf("scan policy role ownership: %w", err)
		}
		out = append(out, kind+":"+name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read policy role ownerships: %w", err)
	}
	return out, nil
}

type crossDatabaseRoleSafety struct {
	ownsObjects      bool
	crossDatabaseACL bool
}

func applyCrossDatabaseSafetyObservation(
	state *rolePolicyState,
	safety crossDatabaseRoleSafety,
	err error,
) {
	if err != nil {
		delete(state.actual, "role:no_ownership")
		state.actual["role:cross_database_check_incomplete"] = struct{}{}
		state.hardBlockCode = "cross_database_check_incomplete"
		return
	}
	if safety.ownsObjects {
		delete(state.actual, "role:no_ownership")
		state.actual["role:owns:database_objects"] = struct{}{}
		if state.hardBlockCode == "" {
			state.hardBlockCode = "role_owns_database_objects"
		}
	}
	if safety.crossDatabaseACL {
		state.actual["role:cross_database_acl"] = struct{}{}
		if state.hardBlockCode == "" {
			state.hardBlockCode = "role_has_cross_database_acl"
		}
	}
}

// inspectPolicyRoleAcrossCluster uses the shared dependency catalog rather
// than opening every database. deptype=o covers ownership in template and
// datallowconn=false databases; deptype=a identifies ACL references in any
// database. Shared ACL surfaces have dbid=0 and are exact-scanned separately.
func inspectPolicyRoleAcrossCluster(
	ctx context.Context,
	conn rolePolicyQuerier,
	roleName string,
	policyDatabase string,
) (crossDatabaseRoleSafety, error) {
	var result crossDatabaseRoleSafety
	var roleOID, databaseOID uint32
	if err := conn.QueryRow(ctx, `
		select r.oid, d.oid
		from pg_roles r cross join pg_database d
		where r.rolname = $1 and d.datname = $2`, roleName, policyDatabase).
		Scan(&roleOID, &databaseOID); errors.Is(err, pgx.ErrNoRows) {
		return result, nil
	} else if err != nil {
		return result, fmt.Errorf("resolve policy role dependency identity: %w", err)
	}
	if err := conn.QueryRow(ctx, `
		select coalesce(bool_or(deptype = 'o'), false),
		       coalesce(bool_or(deptype = 'a' and dbid <> 0 and dbid <> $2), false)
		from pg_shdepend
		where refclassid = 'pg_authid'::regclass and refobjid = $1`, roleOID, databaseOID).
		Scan(&result.ownsObjects, &result.crossDatabaseACL); err != nil {
		return result, fmt.Errorf("inspect policy role shared dependencies: %w", err)
	}
	return result, nil
}

type policyObject struct {
	schema  string
	name    string
	relkind string
}

func discoverPolicyObjects(ctx context.Context, conn rolePolicyQuerier, template postgresconfig.RolePolicyTemplate) ([]policyObject, error) {
	rows, err := conn.Query(ctx, `
		select n.nspname, c.relname, c.relkind::text
		from pg_class c
		join pg_namespace n on n.oid = c.relnamespace
		join pg_roles owner_role on owner_role.oid = c.relowner
		where n.nspname = any($1::name[])
		  and owner_role.rolname = any($2::name[])
		  and c.relkind in ('r','p','v','m','f','S')
		order by n.nspname, c.relname`, template.Schemas, template.OwnerRoles)
	if err != nil {
		return nil, fmt.Errorf("query role policy objects: %w", err)
	}
	defer rows.Close()
	var out []policyObject
	for rows.Next() {
		var object policyObject
		if err := rows.Scan(&object.schema, &object.name, &object.relkind); err != nil {
			return nil, fmt.Errorf("scan role policy object: %w", err)
		}
		out = append(out, object)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read role policy objects: %w", err)
	}
	return out, nil
}

func addExpectedPolicyACLs(target map[string]struct{}, template postgresconfig.RolePolicyTemplate, objects []policyObject) {
	addACLToken(target, []string{"database", template.Database}, "CONNECT", false)
	for _, schema := range template.Schemas {
		addACLToken(target, []string{"schema", schema}, "USAGE", false)
	}
	tablePrivileges := []string{"SELECT"}
	sequencePrivileges := []string{"SELECT"}
	if template.Profile == postgresconfig.ProfileReadWrite {
		tablePrivileges = []string{"DELETE", "INSERT", "SELECT", "UPDATE"}
		sequencePrivileges = []string{"SELECT", "UPDATE"}
	}
	for _, object := range objects {
		kind := "table"
		privileges := tablePrivileges
		if object.relkind == "S" {
			kind = "sequence"
			privileges = sequencePrivileges
		}
		for _, privilege := range privileges {
			addACLToken(target, []string{kind, object.schema, object.name}, privilege, false)
		}
	}
	for _, creator := range template.CreatorRoles {
		for _, schema := range template.Schemas {
			for _, privilege := range tablePrivileges {
				addACLToken(target, []string{"default", creator, schema, "tables"}, privilege, false)
			}
			for _, privilege := range sequencePrivileges {
				addACLToken(target, []string{"default", creator, schema, "sequences"}, privilege, false)
			}
		}
	}
}

func observeActualPolicyACLs(ctx context.Context, conn rolePolicyQuerier, roleName string, target map[string]struct{}) error {
	if err := observeDatabaseACLs(ctx, conn, roleName, target); err != nil {
		return err
	}
	if err := observeSchemaACLs(ctx, conn, roleName, target); err != nil {
		return err
	}
	if err := observeRelationACLs(ctx, conn, roleName, target); err != nil {
		return err
	}
	if err := observeDefaultACLs(ctx, conn, roleName, target); err != nil {
		return err
	}
	return observeOtherACLs(ctx, conn, roleName, target)
}

func observeDatabaseACLs(ctx context.Context, conn rolePolicyQuerier, roleName string, target map[string]struct{}) error {
	rows, err := conn.Query(ctx, `
		select d.datname, acl.privilege_type, acl.is_grantable
		from pg_database d
		cross join lateral aclexplode(coalesce(d.datacl, acldefault('d', d.datdba))) acl
		join pg_roles grantee on grantee.oid = acl.grantee
		where grantee.rolname = $1
		order by d.datname, acl.privilege_type`, roleName)
	if err != nil {
		return fmt.Errorf("query database role policy ACLs: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var database, privilege string
		var grantable bool
		if err := rows.Scan(&database, &privilege, &grantable); err != nil {
			return fmt.Errorf("scan database role policy ACL: %w", err)
		}
		addACLToken(target, []string{"database", database}, privilege, grantable)
	}
	return rows.Err()
}

func observeSchemaACLs(ctx context.Context, conn rolePolicyQuerier, roleName string, target map[string]struct{}) error {
	rows, err := conn.Query(ctx, `
		select n.nspname, acl.privilege_type, acl.is_grantable
		from pg_namespace n
		cross join lateral aclexplode(coalesce(n.nspacl, acldefault('n', n.nspowner))) acl
		join pg_roles grantee on grantee.oid = acl.grantee
		where grantee.rolname = $1
		order by n.nspname, acl.privilege_type`, roleName)
	if err != nil {
		return fmt.Errorf("query schema role policy ACLs: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var schema, privilege string
		var grantable bool
		if err := rows.Scan(&schema, &privilege, &grantable); err != nil {
			return fmt.Errorf("scan schema role policy ACL: %w", err)
		}
		addACLToken(target, []string{"schema", schema}, privilege, grantable)
	}
	return rows.Err()
}

func observeRelationACLs(ctx context.Context, conn rolePolicyQuerier, roleName string, target map[string]struct{}) error {
	rows, err := conn.Query(ctx, `
		select n.nspname, c.relname, c.relkind::text,
		       acl.privilege_type, acl.is_grantable
		from pg_class c
		join pg_namespace n on n.oid = c.relnamespace
		cross join lateral aclexplode(c.relacl) acl
		join pg_roles grantee on grantee.oid = acl.grantee
		where grantee.rolname = $1
		  and c.relkind in ('r','p','v','m','f','S')
		order by n.nspname, c.relname, acl.privilege_type`, roleName)
	if err != nil {
		return fmt.Errorf("query relation role policy ACLs: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var schema, name, relkind, privilege string
		var grantable bool
		if err := rows.Scan(&schema, &name, &relkind, &privilege, &grantable); err != nil {
			return fmt.Errorf("scan relation role policy ACL: %w", err)
		}
		kind := "table"
		if relkind == "S" {
			kind = "sequence"
		}
		addACLToken(target, []string{kind, schema, name}, privilege, grantable)
	}
	return rows.Err()
}

func observeDefaultACLs(ctx context.Context, conn rolePolicyQuerier, roleName string, target map[string]struct{}) error {
	rows, err := conn.Query(ctx, `
		select creator.rolname, coalesce(n.nspname, '*'), d.defaclobjtype::text,
		       acl.privilege_type, acl.is_grantable
		from pg_default_acl d
		join pg_roles creator on creator.oid = d.defaclrole
		left join pg_namespace n on n.oid = d.defaclnamespace
		cross join lateral aclexplode(d.defaclacl) acl
		join pg_roles grantee on grantee.oid = acl.grantee
		where grantee.rolname = $1
		order by creator.rolname, n.nspname nulls first, d.defaclobjtype, acl.privilege_type`, roleName)
	if err != nil {
		return fmt.Errorf("query default role policy ACLs: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var creator, schema, objectType, privilege string
		var grantable bool
		if err := rows.Scan(&creator, &schema, &objectType, &privilege, &grantable); err != nil {
			return fmt.Errorf("scan default role policy ACL: %w", err)
		}
		kind := map[string]string{"r": "tables", "S": "sequences", "f": "functions", "T": "types", "n": "schemas"}[objectType]
		if kind == "" {
			kind = "type-" + objectType
		}
		addACLToken(target, []string{"default", creator, schema, kind}, privilege, grantable)
	}
	return rows.Err()
}

// observeOtherACLs exposes direct privileges outside the fixed profile. The
// expected set intentionally contains no matching tokens; direct repair
// revokes these grants before applying database/schema/relation defaults.
func observeOtherACLs(ctx context.Context, conn rolePolicyQuerier, roleName string, target map[string]struct{}) error {
	rows, err := conn.Query(ctx, `
		select jsonb_build_array('column', n.nspname, c.relname, a.attname)::text,
		       acl.privilege_type, acl.is_grantable
		from pg_attribute a
		join pg_class c on c.oid = a.attrelid
		join pg_namespace n on n.oid = c.relnamespace
		cross join lateral aclexplode(a.attacl) acl
		join pg_roles grantee on grantee.oid = acl.grantee
		where grantee.rolname = $1 and a.attnum > 0 and not a.attisdropped
		union all
		select jsonb_build_array('routine', p.oid::regprocedure::text)::text,
		       acl.privilege_type, acl.is_grantable
		from pg_proc p
		cross join lateral aclexplode(p.proacl) acl
		join pg_roles grantee on grantee.oid = acl.grantee
		where grantee.rolname = $1
		union all
		select jsonb_build_array('type', t.oid::regtype::text)::text,
		       acl.privilege_type, acl.is_grantable
		from pg_type t
		cross join lateral aclexplode(t.typacl) acl
		join pg_roles grantee on grantee.oid = acl.grantee
		where grantee.rolname = $1
		union all
		select jsonb_build_array('large_object', l.oid::text)::text,
		       acl.privilege_type, acl.is_grantable
		from pg_largeobject_metadata l
		cross join lateral aclexplode(l.lomacl) acl
		join pg_roles grantee on grantee.oid = acl.grantee
		where grantee.rolname = $1
		union all
		select jsonb_build_array('foreign_data_wrapper', f.fdwname)::text,
		       acl.privilege_type, acl.is_grantable
		from pg_foreign_data_wrapper f
		cross join lateral aclexplode(f.fdwacl) acl
		join pg_roles grantee on grantee.oid = acl.grantee
		where grantee.rolname = $1
		union all
		select jsonb_build_array('foreign_server', s.srvname)::text,
		       acl.privilege_type, acl.is_grantable
		from pg_foreign_server s
		cross join lateral aclexplode(s.srvacl) acl
		join pg_roles grantee on grantee.oid = acl.grantee
		where grantee.rolname = $1
		union all
		select jsonb_build_array('language', l.lanname)::text,
		       acl.privilege_type, acl.is_grantable
		from pg_language l
		cross join lateral aclexplode(l.lanacl) acl
		join pg_roles grantee on grantee.oid = acl.grantee
		where grantee.rolname = $1
		union all
		select jsonb_build_array('tablespace', t.spcname)::text,
		       acl.privilege_type, acl.is_grantable
		from pg_tablespace t
		cross join lateral aclexplode(t.spcacl) acl
		join pg_roles grantee on grantee.oid = acl.grantee
		where grantee.rolname = $1
		union all
		select jsonb_build_array('parameter', p.parname)::text,
		       acl.privilege_type, acl.is_grantable
		from pg_parameter_acl p
		cross join lateral aclexplode(p.paracl) acl
		join pg_roles grantee on grantee.oid = acl.grantee
		where grantee.rolname = $1
		order by 1, 2`, roleName)
	if err != nil {
		return fmt.Errorf("query extended role policy ACLs: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var scope, privilege string
		var grantable bool
		if err := rows.Scan(&scope, &privilege, &grantable); err != nil {
			return fmt.Errorf("scan extended role policy ACL: %w", err)
		}
		addRawACLToken(target, scope, privilege, grantable)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read extended role policy ACLs: %w", err)
	}
	return nil
}

// observeDependentPolicyGrants detects ACL entries granted onward by the
// policy role. REVOKE defaults to RESTRICT; silently switching to CASCADE
// would revoke third-party access outside the reviewed template. Such chains
// therefore block repair and remain in the bounded preview for DBA cleanup.
func observeDependentPolicyGrants(
	ctx context.Context,
	conn rolePolicyQuerier,
	roleName string,
	target map[string]struct{},
) (bool, error) {
	rows, err := conn.Query(ctx, `
		select jsonb_build_array('database', d.datname, 'to', coalesce(grantee.rolname, 'PUBLIC'))::text,
		       acl.privilege_type
		from pg_database d
		cross join lateral aclexplode(d.datacl) acl
		join pg_roles grantor on grantor.oid = acl.grantor
		left join pg_roles grantee on grantee.oid = acl.grantee
		where grantor.rolname = $1 and acl.grantee <> grantor.oid
		union all
		select jsonb_build_array('schema', n.nspname, 'to', coalesce(grantee.rolname, 'PUBLIC'))::text,
		       acl.privilege_type
		from pg_namespace n
		cross join lateral aclexplode(n.nspacl) acl
		join pg_roles grantor on grantor.oid = acl.grantor
		left join pg_roles grantee on grantee.oid = acl.grantee
		where grantor.rolname = $1 and acl.grantee <> grantor.oid
		union all
		select jsonb_build_array('relation', n.nspname, c.relname, 'to', coalesce(grantee.rolname, 'PUBLIC'))::text,
		       acl.privilege_type
		from pg_class c join pg_namespace n on n.oid = c.relnamespace
		cross join lateral aclexplode(c.relacl) acl
		join pg_roles grantor on grantor.oid = acl.grantor
		left join pg_roles grantee on grantee.oid = acl.grantee
		where grantor.rolname = $1 and acl.grantee <> grantor.oid
		union all
		select jsonb_build_array('column', n.nspname, c.relname, a.attname, 'to', coalesce(grantee.rolname, 'PUBLIC'))::text,
		       acl.privilege_type
		from pg_attribute a
		join pg_class c on c.oid = a.attrelid
		join pg_namespace n on n.oid = c.relnamespace
		cross join lateral aclexplode(a.attacl) acl
		join pg_roles grantor on grantor.oid = acl.grantor
		left join pg_roles grantee on grantee.oid = acl.grantee
		where grantor.rolname = $1 and acl.grantee <> grantor.oid
		union all
		select jsonb_build_array('default', creator.rolname, coalesce(n.nspname, '*'),
		       d.defaclobjtype::text, 'to', coalesce(grantee.rolname, 'PUBLIC'))::text, acl.privilege_type
		from pg_default_acl d
		join pg_roles creator on creator.oid = d.defaclrole
		left join pg_namespace n on n.oid = d.defaclnamespace
		cross join lateral aclexplode(d.defaclacl) acl
		join pg_roles grantor on grantor.oid = acl.grantor
		left join pg_roles grantee on grantee.oid = acl.grantee
		where grantor.rolname = $1 and acl.grantee <> grantor.oid
		union all
		select jsonb_build_array('routine', p.oid::regprocedure::text, 'to', coalesce(grantee.rolname, 'PUBLIC'))::text,
		       acl.privilege_type
		from pg_proc p cross join lateral aclexplode(p.proacl) acl
		join pg_roles grantor on grantor.oid = acl.grantor
		left join pg_roles grantee on grantee.oid = acl.grantee
		where grantor.rolname = $1 and acl.grantee <> grantor.oid
		union all
		select jsonb_build_array('type', t.oid::regtype::text, 'to', coalesce(grantee.rolname, 'PUBLIC'))::text,
		       acl.privilege_type
		from pg_type t cross join lateral aclexplode(t.typacl) acl
		join pg_roles grantor on grantor.oid = acl.grantor
		left join pg_roles grantee on grantee.oid = acl.grantee
		where grantor.rolname = $1 and acl.grantee <> grantor.oid
		union all
		select jsonb_build_array('large_object', l.oid::text, 'to', coalesce(grantee.rolname, 'PUBLIC'))::text,
		       acl.privilege_type
		from pg_largeobject_metadata l cross join lateral aclexplode(l.lomacl) acl
		join pg_roles grantor on grantor.oid = acl.grantor
		left join pg_roles grantee on grantee.oid = acl.grantee
		where grantor.rolname = $1 and acl.grantee <> grantor.oid
		union all
		select jsonb_build_array('foreign_data_wrapper', f.fdwname, 'to', coalesce(grantee.rolname, 'PUBLIC'))::text,
		       acl.privilege_type
		from pg_foreign_data_wrapper f cross join lateral aclexplode(f.fdwacl) acl
		join pg_roles grantor on grantor.oid = acl.grantor
		left join pg_roles grantee on grantee.oid = acl.grantee
		where grantor.rolname = $1 and acl.grantee <> grantor.oid
		union all
		select jsonb_build_array('foreign_server', s.srvname, 'to', coalesce(grantee.rolname, 'PUBLIC'))::text,
		       acl.privilege_type
		from pg_foreign_server s cross join lateral aclexplode(s.srvacl) acl
		join pg_roles grantor on grantor.oid = acl.grantor
		left join pg_roles grantee on grantee.oid = acl.grantee
		where grantor.rolname = $1 and acl.grantee <> grantor.oid
		union all
		select jsonb_build_array('language', l.lanname, 'to', coalesce(grantee.rolname, 'PUBLIC'))::text,
		       acl.privilege_type
		from pg_language l cross join lateral aclexplode(l.lanacl) acl
		join pg_roles grantor on grantor.oid = acl.grantor
		left join pg_roles grantee on grantee.oid = acl.grantee
		where grantor.rolname = $1 and acl.grantee <> grantor.oid
		union all
		select jsonb_build_array('tablespace', t.spcname, 'to', coalesce(grantee.rolname, 'PUBLIC'))::text,
		       acl.privilege_type
		from pg_tablespace t cross join lateral aclexplode(t.spcacl) acl
		join pg_roles grantor on grantor.oid = acl.grantor
		left join pg_roles grantee on grantee.oid = acl.grantee
		where grantor.rolname = $1 and acl.grantee <> grantor.oid
		union all
		select jsonb_build_array('parameter', p.parname, 'to', coalesce(grantee.rolname, 'PUBLIC'))::text,
		       acl.privilege_type
		from pg_parameter_acl p cross join lateral aclexplode(p.paracl) acl
		join pg_roles grantor on grantor.oid = acl.grantor
		left join pg_roles grantee on grantee.oid = acl.grantee
		where grantor.rolname = $1 and acl.grantee <> grantor.oid
		order by 1, 2`, roleName)
	if err != nil {
		return false, fmt.Errorf("query dependent policy grants: %w", err)
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var scope, privilege string
		if err := rows.Scan(&scope, &privilege); err != nil {
			return false, fmt.Errorf("scan dependent policy grant: %w", err)
		}
		found = true
		target["dependent_acl:"+scope+":"+strings.ToUpper(privilege)] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("read dependent policy grants: %w", err)
	}
	return found, nil
}

func addACLToken(target map[string]struct{}, scope []string, privilege string, grantable bool) {
	raw, _ := json.Marshal(scope)
	addRawACLToken(target, string(raw), privilege, grantable)
}

func addRawACLToken(target map[string]struct{}, scope, privilege string, grantable bool) {
	base := "acl:" + scope + ":" + strings.ToUpper(privilege)
	target[base] = struct{}{}
	if grantable {
		target[base+":GRANT_OPTION"] = struct{}{}
	}
}

func fingerprintPolicyTokens(tokens map[string]struct{}) string {
	values := make([]string, 0, len(tokens))
	for token := range tokens {
		values = append(values, token)
	}
	slices.Sort(values)
	sum := sha256.Sum256([]byte(strings.Join(values, "\x1f")))
	return hex.EncodeToString(sum[:])
}

func setDifference(left, right map[string]struct{}) []string {
	out := make([]string, 0)
	for value := range left {
		if _, exists := right[value]; !exists {
			out = append(out, value)
		}
	}
	slices.Sort(out)
	return out
}

func previewPolicyTokens(values []string) ([]string, bool) {
	if len(values) <= rolePolicyPreviewLimit {
		return slices.Clone(values), false
	}
	return slices.Clone(values[:rolePolicyPreviewLimit]), true
}

func (a *Adapter) planRolePolicy(ctx context.Context, change adapter.DesiredChange) (*adapter.Plan, error) {
	return a.planDirectRolePolicy(ctx, change)
}

func (a *Adapter) applyRolePolicy(ctx context.Context, plan adapter.Plan) (*adapter.Result, error) {
	return a.applyDirectRolePolicy(ctx, plan)
}

func (a *Adapter) verifyRolePolicy(ctx context.Context, plan adapter.Plan) (*adapter.Verification, error) {
	return a.verifyDirectRolePolicy(ctx, plan)
}
