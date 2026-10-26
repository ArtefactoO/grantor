package mongodb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
	"github.com/ArtefactoO/grantor/internal/mongodbconfig"
)

const (
	stepRolePolicyApply  = "role-policy-apply"
	stepRolePolicyVerify = "role-policy-verify"

	mongoRolePolicyPreviewLimit = 50
	mongoPrivilegePreviewLimit  = 20
	mongoActionPreviewBudget    = 100

	mongoRolePolicyCatalogFingerprintKey = "mongodb_role_policy_catalog_fingerprint"
	mongoRolePolicyApplySupportedKey     = "mongodb_role_policy_apply_supported"
)

var _ adapter.ConnectionCapabilityScoper = (*Adapter)(nil)

// CapabilitiesFor enables the engine-wide role.policy.apply maximum only for
// the exact catalog observed on a target where at least one policy passed the
// identity, authorization and role-safety gates. Per-policy ApplySupported is
// still the mandatory finer-grained guard used by the lifecycle API.
func (a *Adapter) CapabilitiesFor(cfg adapter.Connection, topology map[string]any) []adapter.Capability {
	caps := slices.Clone(a.Manifest().Capabilities)
	templates, err := mongodbconfig.FromAttributes(cfg.Attributes)
	applySupported, _ := topology[mongoRolePolicyApplySupportedKey].(bool)
	if err != nil || len(templates) == 0 || topology == nil ||
		adapterutil.StringAttr(topology, mongoRolePolicyCatalogFingerprintKey) !=
			mongodbconfig.CatalogFingerprint(templates) || !applySupported {
		caps = slices.DeleteFunc(caps, func(capability adapter.Capability) bool {
			return capability == adapter.CapRolePolicyApply
		})
	}
	return adapter.ScopeAdminCredentialCapabilities(caps, topology)
}

type mongoRolePolicyState struct {
	exists        bool
	role          customRole
	expected      map[string]struct{}
	actual        map[string]struct{}
	missing       []string
	extra         []string
	blockedReason string
	dangerReasons []string
}

func newMongoRolePolicyState(template mongodbconfig.RolePolicyTemplate) *mongoRolePolicyState {
	state := &mongoRolePolicyState{
		expected: map[string]struct{}{
			"role:exists":                         {},
			"role:custom":                         {},
			"role:no_authentication_restrictions": {},
			"role:no_inherited_authentication_restrictions": {},
		},
		actual: make(map[string]struct{}),
	}
	for _, ref := range template.InheritedRoles {
		state.expected[roleRefToken("inherits", ref.DB, ref.Role)] = struct{}{}
		state.expected[roleRefToken("effective_inherits", ref.DB, ref.Role)] = struct{}{}
	}
	for _, privilege := range template.Privileges {
		for _, action := range privilege.Actions {
			state.expected[privilegeToken(privilege.Resource, action)] = struct{}{}
			state.expected[effectivePrivilegeToken(privilege.Resource, action)] = struct{}{}
		}
	}
	return state
}

func (state *mongoRolePolicyState) finish() {
	state.missing = policySetDifference(state.expected, state.actual)
	state.extra = policySetDifference(state.actual, state.expected)
}

func mongoRolePolicyTemplate(change adapter.DesiredChange) (mongodbconfig.RolePolicyTemplate, error) {
	if change.RolePolicySpec == nil {
		return mongodbconfig.RolePolicyTemplate{}, errors.New("role policy spec is required")
	}
	spec := change.RolePolicySpec
	if spec.Engine != Engine {
		return mongodbconfig.RolePolicyTemplate{}, fmt.Errorf("role policy engine %q is not mongodb", spec.Engine)
	}
	if len(spec.Schemas) != 0 || len(spec.OwnerRoles) != 0 || len(spec.CreatorRoles) != 0 || spec.Profile != "" {
		return mongodbconfig.RolePolicyTemplate{}, errors.New("mongodb role policy contains foreign engine fields")
	}
	templates, err := mongodbconfig.FromAttributes(change.Connection.Attributes)
	if err != nil {
		return mongodbconfig.RolePolicyTemplate{}, err
	}
	for _, template := range templates {
		if template.Key != spec.Key {
			continue
		}
		candidate := mongodbconfig.RolePolicyTemplate{
			Key: spec.Key, Name: spec.Name, Description: spec.Description,
			RoleName: spec.RoleName, RoleDatabase: spec.Database,
			InheritedRoles: slices.Clone(spec.MongoInheritedRoles),
			Privileges:     cloneMongoPrivileges(spec.MongoPrivileges),
		}
		if mongodbconfig.Fingerprint(candidate) != mongodbconfig.Fingerprint(template) {
			return mongodbconfig.RolePolicyTemplate{}, errors.New("pinned role policy differs from the connection catalog")
		}
		if change.Permission != "" && change.Permission != rolePermissionID(template.RoleDatabase, template.RoleName) {
			return mongodbconfig.RolePolicyTemplate{}, errors.New("role policy permission identity does not match the template")
		}
		return template, nil
	}
	return mongodbconfig.RolePolicyTemplate{}, fmt.Errorf("role policy key %q is absent from the connection catalog", spec.Key)
}

func cloneMongoPrivileges(values []adapter.MongoRolePrivilege) []adapter.MongoRolePrivilege {
	out := make([]adapter.MongoRolePrivilege, len(values))
	for i := range values {
		out[i] = values[i]
		out[i].Actions = slices.Clone(values[i].Actions)
	}
	return out
}

func fetchRoleInfo(ctx context.Context, client *mongo.Client, database, role string) (customRole, bool, error) {
	var result struct {
		Roles []customRole `bson:"roles"`
	}
	cmd := bson.D{
		{Key: "rolesInfo", Value: bson.D{
			{Key: "role", Value: role},
			{Key: "db", Value: database},
		}},
		{Key: "showPrivileges", Value: true},
		{Key: "showAuthenticationRestrictions", Value: true},
	}
	if err := client.Database(adminDatabase).RunCommand(ctx, cmd).Decode(&result); err != nil {
		return customRole{}, false, fmt.Errorf("read role %q on db %q: %w", role, database, err)
	}
	if len(result.Roles) == 0 {
		return customRole{}, false, nil
	}
	if len(result.Roles) != 1 || result.Roles[0].Role != role || result.Roles[0].DB != database {
		return customRole{}, false, fmt.Errorf("read role %q on db %q: ambiguous identity", role, database)
	}
	result.Roles[0].ObservationComplete = true
	return normalizeObservedRole(result.Roles[0]), true, nil
}

type mongoRoleObservation struct {
	Role  customRole
	Found bool
	Err   error
}

type mongoRoleObservationCache map[string]mongoRoleObservation

func (cache mongoRoleObservationCache) fetch(
	ctx context.Context,
	client *mongo.Client,
	database, role string,
) (customRole, bool, error) {
	identity := mongodbconfig.RoleIdentity(database, role)
	if observation, exists := cache[identity]; exists {
		return observation.Role, observation.Found, observation.Err
	}
	observed, found, err := fetchRoleInfo(ctx, client, database, role)
	cache[identity] = mongoRoleObservation{Role: observed, Found: found, Err: err}
	return observed, found, err
}

func mongoRolePolicyCatalogByIdentity(
	templates []mongodbconfig.RolePolicyTemplate,
) map[string]mongodbconfig.RolePolicyTemplate {
	out := make(map[string]mongodbconfig.RolePolicyTemplate, len(templates))
	for _, template := range templates {
		out[mongodbconfig.RoleIdentity(template.RoleDatabase, template.RoleName)] = template
	}
	return out
}

func normalizeObservedRole(role customRole) customRole {
	role.DirectRoles = normalizeObservedRoleRefs(role.DirectRoles)
	role.InheritedRoles = normalizeObservedRoleRefs(role.InheritedRoles)
	role.DirectPrivileges = normalizeObservedPrivileges(role.DirectPrivileges)
	role.InheritedPrivileges = normalizeObservedPrivileges(role.InheritedPrivileges)
	return role
}

func normalizeObservedRoleRefs(values []roleRef) []roleRef {
	byIdentity := make(map[string]roleRef, len(values))
	for _, value := range values {
		if value.DB == "" || value.Role == "" {
			continue
		}
		byIdentity[mongodbconfig.RoleIdentity(value.DB, value.Role)] = value
	}
	out := make([]roleRef, 0, len(byIdentity))
	for _, value := range byIdentity {
		out = append(out, value)
	}
	slices.SortFunc(out, func(a, b roleRef) int {
		return strings.Compare(mongodbconfig.RoleIdentity(a.DB, a.Role),
			mongodbconfig.RoleIdentity(b.DB, b.Role))
	})
	return out
}

func normalizeObservedPrivileges(values []rolePrivilege) []rolePrivilege {
	type merged struct {
		resource roleResource
		actions  map[string]struct{}
	}
	byResource := make(map[string]merged, len(values))
	for _, value := range values {
		key := observedResourceKey(value.Resource)
		entry, exists := byResource[key]
		if !exists {
			entry = merged{resource: value.Resource, actions: make(map[string]struct{})}
		}
		for _, action := range value.Actions {
			if action != "" {
				entry.actions[action] = struct{}{}
			}
		}
		byResource[key] = entry
	}
	keys := make([]string, 0, len(byResource))
	for key := range byResource {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	out := make([]rolePrivilege, 0, len(keys))
	for _, key := range keys {
		entry := byResource[key]
		actions := make([]string, 0, len(entry.actions))
		for action := range entry.actions {
			actions = append(actions, action)
		}
		slices.Sort(actions)
		out = append(out, rolePrivilege{Resource: entry.resource, Actions: actions})
	}
	return out
}

func observedResourceKey(resource roleResource) string {
	unknown := make([]string, 0, len(resource.Unknown))
	for key := range resource.Unknown {
		unknown = append(unknown, key)
	}
	slices.Sort(unknown)
	if resource.hasSystemBuckets() {
		return observedSystemBucketsKey(resource) + fmt.Sprintf("|unknown=%q", unknown)
	}
	return fmt.Sprintf("any=%t|cluster=%t|db=%q|collection=%q|unknown=%q",
		resource.AnyResource, resource.Cluster, resource.DB, resource.Collection, unknown)
}

func validObservedRoleResource(resource roleResource) bool {
	if len(resource.Unknown) != 0 {
		return false
	}
	if resource.hasSystemBuckets() {
		return validObservedSystemBuckets(resource)
	}
	if resource.AnyResource {
		return !resource.Cluster && resource.DB == "" && resource.Collection == ""
	}
	if resource.Cluster {
		return resource.DB == "" && resource.Collection == ""
	}
	return true
}

func roleHasUnsupportedResource(role customRole) bool {
	for _, privileges := range [][]rolePrivilege{role.DirectPrivileges, role.InheritedPrivileges} {
		for _, privilege := range privileges {
			if !validObservedRoleResource(privilege.Resource) {
				return true
			}
		}
	}
	return false
}

func unsupportedResourceCount(role customRole) int {
	count := 0
	for _, privileges := range [][]rolePrivilege{role.DirectPrivileges, role.InheritedPrivileges} {
		for _, privilege := range privileges {
			if !validObservedRoleResource(privilege.Resource) {
				count++
			}
		}
	}
	return count
}

func printableResourceKey(resource adapter.MongoRoleResource) string {
	switch {
	case resource.AnyResource:
		return "any_resource"
	case resource.Cluster:
		return "cluster"
	case resource.DB == "":
		return "all_databases/" + resource.Collection
	case resource.Collection == "":
		return "db:" + resource.DB
	default:
		return "namespace:" + resource.DB + "." + resource.Collection
	}
}

func typedRoleResource(resource roleResource) adapter.MongoRoleResource {
	return adapter.MongoRoleResource{
		DB: resource.DB, Collection: resource.Collection,
		Cluster: resource.Cluster, AnyResource: resource.AnyResource,
	}
}

func roleRefToken(kind, database, role string) string {
	return kind + ":" + database + "." + role
}

func privilegeToken(resource adapter.MongoRoleResource, action string) string {
	return "privilege:" + printableResourceKey(resource) + ":" + action
}

func effectivePrivilegeToken(resource adapter.MongoRoleResource, action string) string {
	return "effective_privilege:" + printableResourceKey(resource) + ":" + action
}

func policyFingerprint(values map[string]struct{}) string {
	tokens := make([]string, 0, len(values))
	for token := range values {
		tokens = append(tokens, token)
	}
	slices.Sort(tokens)
	sum := sha256.Sum256([]byte(strings.Join(tokens, "\x1f")))
	return hex.EncodeToString(sum[:])
}

func policySetDifference(left, right map[string]struct{}) []string {
	out := make([]string, 0)
	for value := range left {
		if _, exists := right[value]; !exists {
			out = append(out, value)
		}
	}
	slices.Sort(out)
	return out
}

func previewPolicyStrings(values []string) ([]string, bool) {
	if len(values) <= mongoRolePolicyPreviewLimit {
		return slices.Clone(values), false
	}
	return slices.Clone(values[:mongoRolePolicyPreviewLimit]), true
}

func inspectMongoRolePolicy(
	ctx context.Context,
	client *mongo.Client,
	template mongodbconfig.RolePolicyTemplate,
	catalog []mongodbconfig.RolePolicyTemplate,
) (*mongoRolePolicyState, error) {
	return inspectMongoRolePolicyCached(ctx, client, template,
		mongoRolePolicyCatalogByIdentity(catalog), make(mongoRoleObservationCache), make(map[string]bool))
}

func inspectMongoRolePolicyCached(
	ctx context.Context,
	client *mongo.Client,
	template mongodbconfig.RolePolicyTemplate,
	catalog map[string]mongodbconfig.RolePolicyTemplate,
	cache mongoRoleObservationCache,
	stack map[string]bool,
) (*mongoRolePolicyState, error) {
	identity := mongodbconfig.RoleIdentity(template.RoleDatabase, template.RoleName)
	if stack[identity] {
		return nil, fmt.Errorf("mongodb role policy inheritance cycle at %q", identity)
	}
	stack[identity] = true
	defer delete(stack, identity)

	state := newMongoRolePolicyState(template)
	// Approval is conservative across the whole transition: a dangerous
	// desired template must stay dangerous even when the current role is safe,
	// and dangerous actual drift remains visible until a fresh exact read.
	state.dangerReasons = roleDangerReasons(roleFromTemplate(template))
	role, exists, err := cache.fetch(ctx, client, template.RoleDatabase, template.RoleName)
	if err != nil {
		return nil, err
	}
	state.exists = exists
	if exists {
		state.role = role
		addActualMongoRoleState(state, role)
		state.dangerReasons = append(state.dangerReasons, roleDangerReasons(role)...)
	}

	if err := addExpectedMongoEffectiveClosure(ctx, client, template, catalog, cache,
		state, make(map[string]bool), make(map[string]bool)); err != nil {
		return nil, err
	}
	for _, dependency := range template.InheritedRoles {
		dependencyTemplate, managed := catalog[mongodbconfig.RoleIdentity(dependency.DB, dependency.Role)]
		if !managed {
			continue
		}
		dependencyState, dependencyErr := inspectMongoRolePolicyCached(
			ctx, client, dependencyTemplate, catalog, cache, stack,
		)
		if dependencyErr != nil {
			return nil, dependencyErr
		}
		if policyFingerprint(dependencyState.expected) != policyFingerprint(dependencyState.actual) ||
			dependencyState.blockedReason != "" {
			setMongoPolicyBlock(state, "inherited_policy_drift")
		}
	}
	state.dangerReasons = sortedUnique(state.dangerReasons)
	state.finish()
	return state, nil
}

func setMongoPolicyBlock(state *mongoRolePolicyState, reason string) {
	if state.blockedReason == "" {
		state.blockedReason = reason
	}
}

func addActualMongoRoleState(state *mongoRolePolicyState, role customRole) {
	state.actual["role:exists"] = struct{}{}
	if role.IsBuiltin {
		state.actual["role:builtin"] = struct{}{}
		setMongoPolicyBlock(state, "configured_role_is_builtin")
	} else {
		state.actual["role:custom"] = struct{}{}
	}
	for _, privilege := range role.DirectPrivileges {
		if privilege.Resource.hasSystemBuckets() && validObservedRoleResource(privilege.Resource) {
			// Observation can assign an existing role, but the desired API grammar
			// cannot reproduce this direct privilege. Never repair it lossily.
			setMongoPolicyBlock(state, "observed_role_resource_not_representable")
		}
	}
	if len(role.AuthenticationRestrictions) == 0 {
		state.actual["role:no_authentication_restrictions"] = struct{}{}
	} else {
		state.actual[fmt.Sprintf("role:authentication_restrictions:%d", len(role.AuthenticationRestrictions))] = struct{}{}
		setMongoPolicyBlock(state, "role_has_authentication_restrictions")
	}
	if len(role.InheritedAuthenticationRestrictions) == 0 {
		state.actual["role:no_inherited_authentication_restrictions"] = struct{}{}
	} else {
		state.actual[fmt.Sprintf("role:inherited_authentication_restrictions:%d",
			len(role.InheritedAuthenticationRestrictions))] = struct{}{}
		setMongoPolicyBlock(state, "role_has_authentication_restrictions")
	}
	for _, ref := range role.DirectRoles {
		state.actual[roleRefToken("inherits", ref.DB, ref.Role)] = struct{}{}
	}
	for _, ref := range append(slices.Clone(role.DirectRoles), role.InheritedRoles...) {
		state.actual[roleRefToken("effective_inherits", ref.DB, ref.Role)] = struct{}{}
	}
	for _, privilege := range role.DirectPrivileges {
		addObservedPrivilegeTokens(state, state.actual, privilege, false)
	}
	for _, privilege := range append(slices.Clone(role.DirectPrivileges), role.InheritedPrivileges...) {
		addObservedPrivilegeTokens(state, state.actual, privilege, true)
	}
}

func addObservedPrivilegeTokens(
	state *mongoRolePolicyState,
	tokens map[string]struct{},
	privilege rolePrivilege,
	effective bool,
) {
	if !validObservedRoleResource(privilege.Resource) {
		tokens["privilege:unsupported_resource_shape:"+observedResourceKey(privilege.Resource)] = struct{}{}
		setMongoPolicyBlock(state, "unsupported_role_resource_shape")
		return
	}
	for _, action := range privilege.Actions {
		tokens[observedPrivilegeToken(privilege.Resource, action, effective)] = struct{}{}
	}
}

func addExpectedMongoEffectiveClosure(
	ctx context.Context,
	client *mongo.Client,
	template mongodbconfig.RolePolicyTemplate,
	catalog map[string]mongodbconfig.RolePolicyTemplate,
	cache mongoRoleObservationCache,
	state *mongoRolePolicyState,
	visiting map[string]bool,
	visited map[string]bool,
) error {
	identity := mongodbconfig.RoleIdentity(template.RoleDatabase, template.RoleName)
	if visited[identity] {
		return nil
	}
	if visiting[identity] {
		return fmt.Errorf("mongodb role policy inheritance cycle at %q", identity)
	}
	visiting[identity] = true
	defer delete(visiting, identity)

	state.dangerReasons = append(state.dangerReasons, roleDangerReasons(roleFromTemplate(template))...)
	for _, privilege := range template.Privileges {
		for _, action := range privilege.Actions {
			state.expected[effectivePrivilegeToken(privilege.Resource, action)] = struct{}{}
		}
	}
	for _, dependency := range template.InheritedRoles {
		dependencyIdentity := mongodbconfig.RoleIdentity(dependency.DB, dependency.Role)
		state.expected[roleRefToken("effective_inherits", dependency.DB, dependency.Role)] = struct{}{}
		state.expected[roleRefToken("dependency_exists", dependency.DB, dependency.Role)] = struct{}{}
		observed, found, err := cache.fetch(ctx, client, dependency.DB, dependency.Role)
		if err != nil {
			return err
		}
		if !found {
			setMongoPolicyBlock(state, "inherited_role_missing")
			continue
		}
		state.actual[roleRefToken("dependency_exists", dependency.DB, dependency.Role)] = struct{}{}
		state.dangerReasons = append(state.dangerReasons, inheritedRoleDangerReasons(observed)...)
		if len(observed.AuthenticationRestrictions) > 0 || len(observed.InheritedAuthenticationRestrictions) > 0 {
			setMongoPolicyBlock(state, "role_has_authentication_restrictions")
		}
		if roleHasUnsupportedResource(observed) {
			setMongoPolicyBlock(state, "unsupported_role_resource_shape")
		}
		if managedTemplate, managed := catalog[dependencyIdentity]; managed {
			if err := addExpectedMongoEffectiveClosure(ctx, client, managedTemplate, catalog,
				cache, state, visiting, visited); err != nil {
				return err
			}
			continue
		}
		// The only unmanaged dependencies allowed by catalog validation are
		// server-owned read/readWrite. Their effective definition is versioned
		// by MongoDB itself and therefore becomes the expected closure.
		for _, ref := range append(slices.Clone(observed.DirectRoles), observed.InheritedRoles...) {
			state.expected[roleRefToken("effective_inherits", ref.DB, ref.Role)] = struct{}{}
		}
		for _, privilege := range append(slices.Clone(observed.DirectPrivileges), observed.InheritedPrivileges...) {
			if !validObservedRoleResource(privilege.Resource) {
				setMongoPolicyBlock(state, "unsupported_role_resource_shape")
				continue
			}
			for _, action := range privilege.Actions {
				state.expected[observedPrivilegeToken(privilege.Resource, action, true)] = struct{}{}
			}
		}
	}
	visited[identity] = true
	return nil
}

func roleFromTemplate(template mongodbconfig.RolePolicyTemplate) customRole {
	role := customRole{Role: template.RoleName, DB: template.RoleDatabase, ObservationComplete: true}
	for _, ref := range template.InheritedRoles {
		role.DirectRoles = append(role.DirectRoles, roleRef{Role: ref.Role, DB: ref.DB})
	}
	for _, privilege := range template.Privileges {
		role.DirectPrivileges = append(role.DirectPrivileges, rolePrivilege{
			Resource: roleResource{
				DB: privilege.Resource.DB, Collection: privilege.Resource.Collection,
				Cluster: privilege.Resource.Cluster, AnyResource: privilege.Resource.AnyResource,
			},
			Actions: slices.Clone(privilege.Actions),
		})
	}
	return normalizeObservedRole(role)
}

var safeMongoDataActions = map[string]struct{}{
	"changeStream": {}, "collStats": {}, "dbHash": {}, "dbStats": {},
	"find": {}, "indexStats": {}, "insert": {}, "killCursors": {},
	"listCollections": {}, "listIndexes": {}, "listSearchIndexes": {},
	"planCacheRead": {}, "remove": {}, "update": {}, "validate": {},
}

func roleDangerReasons(role customRole) []string {
	reasons := privilegeDangerReasons(role.DirectPrivileges, "direct")
	reasons = append(reasons, privilegeDangerReasons(role.InheritedPrivileges, "inherited")...)
	if !role.ObservationComplete {
		reasons = append(reasons, "privilege_observation_incomplete")
	}
	if roleHasUnsupportedResource(role) {
		reasons = append(reasons, "unsupported_resource_shape")
	}
	return sortedUnique(reasons)
}

func inheritedRoleDangerReasons(role customRole) []string {
	reasons := privilegeDangerReasons(role.DirectPrivileges, "inherited")
	reasons = append(reasons, privilegeDangerReasons(role.InheritedPrivileges, "inherited")...)
	return sortedUnique(reasons)
}

func privilegeDangerReasons(privileges []rolePrivilege, source string) []string {
	var reasons []string
	for _, privilege := range privileges {
		resource := privilege.Resource
		if !validObservedRoleResource(resource) {
			reasons = append(reasons, source+":unsupported_resource_shape")
			continue
		}
		if resource.Cluster || resource.AnyResource || resource.DB == "" {
			reasons = append(reasons, source+":broad_resource:"+printableObservedResourceKey(resource))
		}
		for _, action := range privilege.Actions {
			if _, safe := safeMongoDataActions[action]; !safe {
				reasons = append(reasons, source+":dangerous_action:"+action)
			}
		}
	}
	return sortedUnique(reasons)
}

func sortedUnique(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			set[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	slices.Sort(out)
	return out
}

type mongoRoleManagementStatus struct {
	Supported bool
	Reason    string
}

type mongoRoleManagementAuthorization struct {
	Authenticated  bool
	Privileges     []rolePrivilege
	AuthorityRoles map[string]struct{}
}

func readMongoRoleManagementAuthorization(
	ctx context.Context,
	client *mongo.Client,
	cfg adapter.Connection,
) (mongoRoleManagementAuthorization, error) {
	if cfg.AdminCredential.Username == "" {
		return mongoRoleManagementAuthorization{}, nil
	}
	var status struct {
		AuthInfo struct {
			AuthenticatedUsers []struct {
				User string `bson:"user"`
				DB   string `bson:"db"`
			} `bson:"authenticatedUsers"`
			AuthenticatedUserRoles      []roleRef       `bson:"authenticatedUserRoles"`
			AuthenticatedUserPrivileges []rolePrivilege `bson:"authenticatedUserPrivileges"`
		} `bson:"authInfo"`
	}
	cmd := bson.D{{Key: "connectionStatus", Value: 1}, {Key: "showPrivileges", Value: true}}
	if err := client.Database(adminDatabase).RunCommand(ctx, cmd).Decode(&status); err != nil {
		return mongoRoleManagementAuthorization{}, fmt.Errorf("read role-management privileges: %w", err)
	}
	users := status.AuthInfo.AuthenticatedUsers
	if len(users) != 1 || users[0].User != cfg.AdminCredential.Username || users[0].DB != authSource(cfg) {
		return mongoRoleManagementAuthorization{}, nil
	}
	authorityRoles := make(map[string]struct{})
	for _, role := range status.AuthInfo.AuthenticatedUserRoles {
		if role.Role != "" && role.DB != "" {
			authorityRoles[mongodbconfig.RoleIdentity(role.DB, role.Role)] = struct{}{}
		}
	}
	var userInfoResult struct {
		Users []struct {
			User           string    `bson:"user"`
			DB             string    `bson:"db"`
			Roles          []roleRef `bson:"roles"`
			InheritedRoles []roleRef `bson:"inheritedRoles"`
		} `bson:"users"`
	}
	userInfoCommand := bson.D{
		{Key: "usersInfo", Value: cfg.AdminCredential.Username},
		{Key: "showPrivileges", Value: true},
	}
	adminDB := authSource(cfg)
	if err := client.Database(adminDB).RunCommand(ctx, userInfoCommand).Decode(&userInfoResult); err != nil {
		return mongoRoleManagementAuthorization{}, fmt.Errorf("read connection admin role chain: %w", err)
	}
	if len(userInfoResult.Users) != 1 || userInfoResult.Users[0].User != cfg.AdminCredential.Username ||
		userInfoResult.Users[0].DB != adminDB {
		return mongoRoleManagementAuthorization{}, errors.New("read connection admin role chain: ambiguous identity")
	}
	for _, role := range append(slices.Clone(userInfoResult.Users[0].Roles),
		userInfoResult.Users[0].InheritedRoles...) {
		if role.Role != "" && role.DB != "" {
			authorityRoles[mongodbconfig.RoleIdentity(role.DB, role.Role)] = struct{}{}
		}
	}
	return mongoRoleManagementAuthorization{
		Authenticated:  true,
		Privileges:     normalizeObservedPrivileges(status.AuthInfo.AuthenticatedUserPrivileges),
		AuthorityRoles: authorityRoles,
	}, nil
}

func mongoRoleManagementForTemplate(
	authorization mongoRoleManagementAuthorization,
	template mongodbconfig.RolePolicyTemplate,
) mongoRoleManagementStatus {
	if !authorization.Authenticated {
		return mongoRoleManagementStatus{Reason: "admin_authentication_required"}
	}
	if _, selfAuthority := authorization.AuthorityRoles[mongodbconfig.RoleIdentity(template.RoleDatabase, template.RoleName)]; selfAuthority {
		return mongoRoleManagementStatus{Reason: "role_is_connection_admin_dependency"}
	}
	for _, action := range []string{"viewRole", "createRole"} {
		if !mongoAuthorizationCoversDatabase(authorization.Privileges, action, template.RoleDatabase) {
			return mongoRoleManagementStatus{Reason: "role_management_privileges_missing"}
		}
	}
	// updateRole can revoke arbitrary unexpected privileges/inheritance from
	// a drifted role, so repair is safe only with all-database revokeRole.
	if !mongoAuthorizationCoversAllDatabases(authorization.Privileges, "revokeRole") {
		return mongoRoleManagementStatus{Reason: "role_management_privileges_missing"}
	}
	grantDatabases := map[string]struct{}{template.RoleDatabase: {}}
	for _, ref := range template.InheritedRoles {
		grantDatabases[ref.DB] = struct{}{}
	}
	for _, privilege := range template.Privileges {
		database := privilege.Resource.DB
		if privilege.Resource.Cluster || database == "" {
			database = adminDatabase
		}
		grantDatabases[database] = struct{}{}
	}
	for database := range grantDatabases {
		if !mongoAuthorizationCoversDatabase(authorization.Privileges, "grantRole", database) {
			return mongoRoleManagementStatus{Reason: "role_management_privileges_missing"}
		}
	}
	return mongoRoleManagementStatus{Supported: true}
}

func mongoAuthorizationCoversDatabase(privileges []rolePrivilege, action, database string) bool {
	for _, privilege := range privileges {
		if !slices.Contains(privilege.Actions, action) {
			continue
		}
		resource := privilege.Resource
		if len(resource.Unknown) == 0 && !resource.hasSystemBuckets() && !resource.Cluster && resource.Collection == "" &&
			(resource.AnyResource || resource.DB == "" || resource.DB == database) {
			return true
		}
	}
	return false
}

func mongoAuthorizationCoversAllDatabases(privileges []rolePrivilege, action string) bool {
	for _, privilege := range privileges {
		if !slices.Contains(privilege.Actions, action) {
			continue
		}
		resource := privilege.Resource
		if len(resource.Unknown) == 0 && !resource.hasSystemBuckets() && !resource.Cluster && resource.Collection == "" &&
			(resource.AnyResource || resource.DB == "") {
			return true
		}
	}
	return false
}

func inspectMongoRoleManagement(
	ctx context.Context,
	client *mongo.Client,
	cfg adapter.Connection,
	template mongodbconfig.RolePolicyTemplate,
) (mongoRoleManagementStatus, error) {
	authorization, err := readMongoRoleManagementAuthorization(ctx, client, cfg)
	if err != nil {
		return mongoRoleManagementStatus{}, err
	}
	return mongoRoleManagementForTemplate(authorization, template), nil
}

func discoverMongoRolePolicies(
	ctx context.Context,
	client *mongo.Client,
	cfg adapter.Connection,
	templates []mongodbconfig.RolePolicyTemplate,
	targetIdentity string,
	targetIdentityErr error,
	writablePrimary bool,
) ([]adapter.ObservedRolePolicy, bool) {
	authorization, managementErr := readMongoRoleManagementAuthorization(ctx, client, cfg)
	catalog := mongoRolePolicyCatalogByIdentity(templates)
	cache := make(mongoRoleObservationCache)
	policies := make([]adapter.ObservedRolePolicy, 0, len(templates))
	anySupported := false
	for _, template := range templates {
		management := mongoRoleManagementForTemplate(authorization, template)
		state, err := inspectMongoRolePolicyCached(
			ctx, client, template, catalog, cache, make(map[string]bool),
		)
		blockedReason := ""
		switch {
		case targetIdentityErr != nil || targetIdentity == "":
			blockedReason = "target_identity_unavailable"
		case !writablePrimary:
			blockedReason = "read_only_target"
		case managementErr != nil:
			blockedReason = "admin_authority_observation_failed"
		case !management.Supported:
			blockedReason = management.Reason
		case err != nil:
			blockedReason = "role_observation_failed"
		case state.blockedReason != "":
			blockedReason = state.blockedReason
		}
		if state == nil {
			state = newMongoRolePolicyState(template)
			state.actual["observation:unavailable"] = struct{}{}
			state.finish()
		}
		applySupported := blockedReason == ""
		policy := observedMongoRolePolicy(template, state, applySupported, blockedReason)
		policies = append(policies, policy)
		anySupported = anySupported || applySupported
	}
	slices.SortFunc(policies, func(a, b adapter.ObservedRolePolicy) int {
		return strings.Compare(a.ExternalID, b.ExternalID)
	})
	return policies, anySupported
}

func observedMongoRolePolicy(
	template mongodbconfig.RolePolicyTemplate,
	state *mongoRolePolicyState,
	applySupported bool,
	blockedReason string,
) adapter.ObservedRolePolicy {
	state.finish()
	missing, missingTruncated := previewPolicyStrings(state.missing)
	extra, extraTruncated := previewPolicyStrings(state.extra)
	directPrivileges, directPrivilegesTruncated := previewTypedPrivileges(state.role.DirectPrivileges)
	inheritedPrivileges, inheritedPrivilegesTruncated := previewTypedPrivileges(state.role.InheritedPrivileges)
	directRoles, directRolesTruncated := previewRoleRefs(state.role.DirectRoles)
	inheritedRoles, inheritedRolesTruncated := previewRoleRefs(state.role.InheritedRoles)
	dangerReasons, dangerTruncated := previewPolicyStrings(state.dangerReasons)
	truncated := missingTruncated || extraTruncated || directPrivilegesTruncated ||
		inheritedPrivilegesTruncated || directRolesTruncated || inheritedRolesTruncated || dangerTruncated
	return adapter.ObservedRolePolicy{
		ExternalID:          rolePermissionID(template.RoleDatabase, template.RoleName),
		Spec:                mongodbconfig.Spec(template),
		ExpectedFingerprint: policyFingerprint(state.expected),
		ObservedFingerprint: policyFingerprint(state.actual),
		Exact:               policyFingerprint(state.expected) == policyFingerprint(state.actual),
		Dangerous:           len(state.dangerReasons) > 0,
		ApplySupported:      applySupported,
		BlockedReason:       blockedReason,
		Summary: map[string]any{
			"exists": state.exists, "builtin": state.role.IsBuiltin,
			"role": map[string]any{
				"exists": state.exists, "builtin": state.role.IsBuiltin,
			},
			"direct_privileges": directPrivileges, "direct_privileges_count": len(state.role.DirectPrivileges),
			"direct_inherited_roles": directRoles, "direct_inherited_roles_count": len(state.role.DirectRoles),
			"inherited_privileges": inheritedPrivileges, "inherited_privileges_count": len(state.role.InheritedPrivileges),
			"inherited_roles": inheritedRoles, "inherited_roles_count": len(state.role.InheritedRoles),
			"missing": missing, "missing_count": len(state.missing),
			"extra": extra, "extra_count": len(state.extra),
			"auth_restrictions_count":           len(state.role.AuthenticationRestrictions),
			"inherited_auth_restrictions_count": len(state.role.InheritedAuthenticationRestrictions),
			"unsupported_resource_count":        unsupportedResourceCount(state.role),
			"danger_reasons":                    dangerReasons, "truncated": truncated,
		},
	}
}

func previewTypedPrivileges(values []rolePrivilege) ([]adapter.MongoRolePrivilege, bool) {
	limit := min(len(values), mongoPrivilegePreviewLimit)
	out := make([]adapter.MongoRolePrivilege, 0, limit)
	truncated := len(values) > limit
	remainingActions := mongoActionPreviewBudget
	for _, value := range values[:limit] {
		if remainingActions == 0 {
			truncated = true
			break
		}
		if !validObservedRoleResource(value.Resource) || value.Resource.hasSystemBuckets() {
			// The typed desired-policy DTO cannot express buckets. Omit and mark
			// the read-only preview truncated rather than widen it to namespaces.
			truncated = true
			continue
		}
		actions := slices.Clone(value.Actions)
		if len(actions) > remainingActions {
			actions = actions[:remainingActions]
			truncated = true
		}
		remainingActions -= len(actions)
		out = append(out, adapter.MongoRolePrivilege{
			Resource: typedRoleResource(value.Resource), Actions: actions,
		})
		if remainingActions == 0 {
			if len(out) < limit {
				truncated = true
			}
			break
		}
	}
	return out, truncated
}

func previewRoleRefs(values []roleRef) ([]adapter.MongoRoleRef, bool) {
	limit := min(len(values), mongoRolePolicyPreviewLimit)
	out := make([]adapter.MongoRoleRef, 0, limit)
	for _, value := range values[:limit] {
		out = append(out, adapter.MongoRoleRef{Role: value.Role, DB: value.DB})
	}
	return out, len(values) > limit
}

func annotateMongoRolePolicyPermissions(
	permissions []adapter.ObservedPermission,
	policies []adapter.ObservedRolePolicy,
	dbSet map[string]bool,
) []adapter.ObservedPermission {
	byID := make(map[string]adapter.ObservedRolePolicy, len(policies))
	for _, policy := range policies {
		byID[policy.ExternalID] = policy
	}
	seen := make(map[string]bool, len(byID))
	for index := range permissions {
		policy, configured := byID[permissions[index].ExternalID]
		if !configured {
			continue
		}
		seen[policy.ExternalID] = true
		permissions[index].Assignable = false
		permissions[index].Dangerous = policy.Dangerous
		permissions[index].Attributes = cloneMongoAttributes(permissions[index].Attributes)
		permissions[index].Attributes["role_policy_key"] = policy.Spec.Key
		permissions[index].Attributes["role_policy_exact"] = policy.Exact
		permissions[index].Attributes["role_policy_apply_supported"] = policy.ApplySupported
	}
	for externalID, policy := range byID {
		if seen[externalID] {
			continue
		}
		permissions = append(permissions, adapter.ObservedPermission{
			ExternalID: externalID, Name: policy.Spec.RoleName,
			ScopeExternalID: scopeForDB(policy.Spec.Database, dbSet),
			Assignable:      false, Dangerous: policy.Dangerous,
			Attributes: map[string]any{
				"role_db": policy.Spec.Database, "builtin": false,
				"role_policy_key": policy.Spec.Key, "role_policy_exact": policy.Exact,
				"role_policy_apply_supported": policy.ApplySupported,
				"role_policy_role_missing":    true,
			},
		})
	}
	return permissions
}

func cloneMongoAttributes(attributes map[string]any) map[string]any {
	out := make(map[string]any, len(attributes)+3)
	for key, value := range attributes {
		out[key] = value
	}
	return out
}

func (a *Adapter) planMongoRolePolicy(ctx context.Context, change adapter.DesiredChange) (*adapter.Plan, error) {
	template, err := mongoRolePolicyTemplate(change)
	if err != nil {
		return nil, fmt.Errorf("mongodb: plan %s: %w", change.Kind, err)
	}
	catalog, err := mongodbconfig.FromAttributes(change.Connection.Attributes)
	if err != nil {
		return nil, fmt.Errorf("mongodb: plan %s: catalog: %w", change.Kind, err)
	}
	if change.ExpectedTargetIdentity == "" {
		return nil, fmt.Errorf("mongodb: plan %s: expected target identity is empty: %w",
			change.Kind, adapter.ErrTargetIdentityConflict)
	}
	client, err := a.connect(ctx, change.Connection)
	if err != nil {
		return nil, fmt.Errorf("mongodb: plan %s: %w", change.Kind, err)
	}
	defer disconnect(client)
	management, err := inspectMongoRoleManagement(ctx, client, change.Connection, template)
	if err != nil {
		return nil, fmt.Errorf("mongodb: plan %s: %w", change.Kind, err)
	}
	if !management.Supported {
		return nil, fmt.Errorf("mongodb: plan %s: %s: %w", change.Kind, management.Reason, adapter.ErrUnsupportedChange)
	}
	if err := requireMongoTargetIdentity(ctx, client, change.ExpectedTargetIdentity); err != nil {
		return nil, fmt.Errorf("mongodb: plan %s: %w", change.Kind, err)
	}
	state, err := inspectMongoRolePolicy(ctx, client, template, catalog)
	if err != nil {
		return nil, fmt.Errorf("mongodb: plan %s: observe policy: %w", change.Kind, err)
	}
	if state.blockedReason != "" {
		return nil, fmt.Errorf("mongodb: plan %s: %s: %w", change.Kind, state.blockedReason, adapter.ErrUnsupportedChange)
	}
	stepKind := stepRolePolicyApply
	description := fmt.Sprintf("apply MongoDB role policy %q to role %q on db %q",
		template.Key, template.RoleName, template.RoleDatabase)
	if change.Kind == adapter.ChangeRolePolicyVerify {
		stepKind = stepRolePolicyVerify
		description = fmt.Sprintf("verify exact MongoDB role policy %q for role %q on db %q",
			template.Key, template.RoleName, template.RoleDatabase)
	}
	return adapterutil.SingleStepPlan(change, stepKind, description, map[string]any{
		"policy_key": template.Key, "role": template.RoleName,
		"role_database":        template.RoleDatabase,
		"expected_fingerprint": policyFingerprint(state.expected),
	}), nil
}

func (a *Adapter) applyMongoRolePolicy(ctx context.Context, plan adapter.Plan) (*adapter.Result, error) {
	if plan.Change.Kind != adapter.ChangeRolePolicyApply || len(plan.Steps) != 1 ||
		plan.Steps[0].Kind != stepRolePolicyApply {
		return nil, errors.New("mongodb: apply role policy: invalid apply plan")
	}
	template, err := mongoRolePolicyTemplate(plan.Change)
	if err != nil {
		return nil, fmt.Errorf("mongodb: apply role policy: %w", err)
	}
	catalog, err := mongodbconfig.FromAttributes(plan.Change.Connection.Attributes)
	if err != nil {
		return nil, fmt.Errorf("mongodb: apply role policy: catalog: %w", err)
	}
	client, err := a.connect(ctx, plan.Change.Connection)
	if err != nil {
		return nil, fmt.Errorf("mongodb: apply role policy: %w", err)
	}
	defer disconnect(client)
	management, err := inspectMongoRoleManagement(ctx, client, plan.Change.Connection, template)
	if err != nil {
		return nil, fmt.Errorf("mongodb: apply role policy: %w", err)
	}
	if !management.Supported {
		return nil, fmt.Errorf("mongodb: apply role policy: %s: %w", management.Reason, adapter.ErrUnsupportedChange)
	}
	state, err := inspectMongoRolePolicy(ctx, client, template, catalog)
	if err != nil {
		return nil, fmt.Errorf("mongodb: apply role policy: observe current state: %w", err)
	}
	if state.blockedReason != "" {
		return nil, fmt.Errorf("mongodb: apply role policy: %s: %w", state.blockedReason, adapter.ErrUnsupportedChange)
	}
	// Final proof on this same client immediately precedes the only mutating
	// command. Endpoint/TLS recovery cannot retarget a queued plan silently.
	if err := requireMongoTargetIdentity(ctx, client, plan.Change.ExpectedTargetIdentity); err != nil {
		return nil, fmt.Errorf("mongodb: apply role policy: %w", err)
	}
	// Re-read the admin authority chain immediately before the target command.
	// The earlier Plan/Apply gate is not a durable lock: another administrator
	// may grant this role to the connection admin while the operation is queued.
	management, err = inspectMongoRoleManagement(ctx, client, plan.Change.Connection, template)
	if err != nil {
		return nil, fmt.Errorf("mongodb: apply role policy: recheck admin authority: %w", err)
	}
	if !management.Supported {
		return nil, fmt.Errorf("mongodb: apply role policy: %s: %w", management.Reason, adapter.ErrUnsupportedChange)
	}
	status := adapter.StepApplied
	if policyFingerprint(state.expected) == policyFingerprint(state.actual) {
		status = adapter.StepSkipped
	} else {
		cmd := mongoRolePolicyCommand(template, state.exists)
		if err := runCommand(ctx, client, template.RoleDatabase, cmd); err != nil {
			return nil, fmt.Errorf("mongodb: apply role policy %q: %w", template.Key, err)
		}
	}
	return &adapter.Result{Steps: []adapter.StepResult{{Step: plan.Steps[0], Status: status}}}, nil
}

func mongoRolePolicyCommand(template mongodbconfig.RolePolicyTemplate, exists bool) bson.D {
	command := "createRole"
	if exists {
		command = "updateRole"
	}
	roles := make(bson.A, 0, len(template.InheritedRoles))
	for _, ref := range template.InheritedRoles {
		roles = append(roles, bson.D{{Key: "role", Value: ref.Role}, {Key: "db", Value: ref.DB}})
	}
	privileges := make(bson.A, 0, len(template.Privileges))
	for _, privilege := range template.Privileges {
		var resource bson.D
		switch {
		case privilege.Resource.AnyResource:
			resource = bson.D{{Key: "anyResource", Value: true}}
		case privilege.Resource.Cluster:
			resource = bson.D{{Key: "cluster", Value: true}}
		default:
			resource = bson.D{
				{Key: "db", Value: privilege.Resource.DB},
				{Key: "collection", Value: privilege.Resource.Collection},
			}
		}
		privileges = append(privileges, bson.D{
			{Key: "resource", Value: resource},
			{Key: "actions", Value: slices.Clone(privilege.Actions)},
		})
	}
	return bson.D{
		{Key: command, Value: template.RoleName},
		{Key: "privileges", Value: privileges},
		{Key: "roles", Value: roles},
		{Key: "writeConcern", Value: bson.D{{Key: "w", Value: "majority"}}},
	}
}

func (a *Adapter) verifyMongoRolePolicy(ctx context.Context, plan adapter.Plan) (*adapter.Verification, error) {
	template, err := mongoRolePolicyTemplate(plan.Change)
	if err != nil {
		return nil, fmt.Errorf("mongodb: verify role policy: %w", err)
	}
	catalog, err := mongodbconfig.FromAttributes(plan.Change.Connection.Attributes)
	if err != nil {
		return nil, fmt.Errorf("mongodb: verify role policy: catalog: %w", err)
	}
	client, err := a.connect(ctx, plan.Change.Connection)
	if err != nil {
		return nil, fmt.Errorf("mongodb: verify role policy: %w", err)
	}
	defer disconnect(client)
	management, err := inspectMongoRoleManagement(ctx, client, plan.Change.Connection, template)
	if err != nil {
		return nil, fmt.Errorf("mongodb: verify role policy: %w", err)
	}
	if !management.Supported {
		return nil, fmt.Errorf("mongodb: verify role policy: %s: %w", management.Reason, adapter.ErrUnsupportedChange)
	}
	if err := requireMongoTargetIdentity(ctx, client, plan.Change.ExpectedTargetIdentity); err != nil {
		return nil, fmt.Errorf("mongodb: verify role policy: %w", err)
	}
	state, err := inspectMongoRolePolicy(ctx, client, template, catalog)
	if err != nil {
		return nil, fmt.Errorf("mongodb: verify role policy: observe: %w", err)
	}
	management, err = inspectMongoRoleManagement(ctx, client, plan.Change.Connection, template)
	if err != nil {
		return nil, fmt.Errorf("mongodb: verify role policy: recheck admin authority: %w", err)
	}
	if !management.Supported {
		return nil, fmt.Errorf("mongodb: verify role policy: %s: %w", management.Reason, adapter.ErrUnsupportedChange)
	}
	exact := policyFingerprint(state.expected) == policyFingerprint(state.actual) && state.blockedReason == ""
	details := fmt.Sprintf("MongoDB role policy %q exact for role %q on db %q",
		template.Key, template.RoleName, template.RoleDatabase)
	return adapterutil.VerifyResult(exact, details), nil
}
