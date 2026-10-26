// Package mongodbconfig defines the non-secret, per-connection MongoDB
// custom-role catalog shared by API validation, connection projection and the
// MongoDB adapter. The package deliberately exposes typed privileges only:
// callers cannot attach raw BSON or arbitrary database commands to a policy.
package mongodbconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

const (
	AttributeRolePolicyTemplates = "mongodb_role_policy_templates"

	MaxTemplates         = 64
	MaxKeyLength         = 64
	MaxNameLength        = 128
	MaxDescriptionLength = 512
	MaxRoleNameLength    = 128
	MaxDatabaseLength    = 63
	MaxCollectionLength  = 255
	MaxInheritedRoles    = 64
	MaxPrivileges        = 128
	MaxActions           = 128
)

var (
	templateKeyRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	roleNameRE    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
	databaseRE    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]*$`)
	collectionRE  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
)

// RolePolicyTemplate describes one materialized MongoDB custom role. A role
// identity is the RoleName/RoleDatabase pair; unlike PostgreSQL, the same name
// may exist independently in different databases.
type RolePolicyTemplate struct {
	Key            string                       `json:"key"`
	Name           string                       `json:"name"`
	Description    string                       `json:"description"`
	RoleName       string                       `json:"role_name"`
	RoleDatabase   string                       `json:"role_database"`
	InheritedRoles []adapter.MongoRoleRef       `json:"inherited_roles"`
	Privileges     []adapter.MongoRolePrivilege `json:"privileges"`
}

// documentedActions is a closed subset of MongoDB authorization actions. It
// covers data, index/view, user/role, diagnostic and cluster administration
// policies while intentionally excluding internal/escape-hatch actions such
// as anyAction, internal and applyOps. An unsupported server version still
// rejects the action during exact Plan/Apply; accepting an arbitrary string in
// metadata would instead make that rejection happen after a security review.
var documentedActions = map[string]struct{}{
	"addShard": {}, "analyzeShardKey": {}, "appendOplogNote": {},
	"applicationMessage": {}, "authSchemaUpgrade": {},
	"bypassDefaultMaxTimeMS": {}, "bypassDocumentValidation": {},
	"bypassWriteBlockingMode": {}, "changeCustomData": {},
	"changeOwnCustomData": {}, "changeOwnPassword": {}, "changePassword": {},
	"changeStream": {}, "checkMetadataConsistency": {}, "cleanupOrphaned": {},
	"clearJumboFlag": {}, "closeAllDatabases": {}, "collMod": {},
	"collStats": {}, "compact": {}, "compactStructuredEncryptionData": {},
	"connPoolStats": {}, "connPoolSync": {}, "convertToCapped": {},
	"cpuProfiler": {}, "createCollection": {}, "createIndex": {},
	"createRole": {}, "createSearchIndexes": {}, "createUser": {},
	"dbHash": {}, "dbStats": {}, "dropCollection": {}, "dropConnections": {},
	"dropDatabase": {}, "dropIndex": {}, "dropRole": {}, "dropSearchIndex": {},
	"dropUser": {}, "enableProfiler": {}, "enableSharding": {}, "find": {},
	"flushRouterConfig": {}, "forceUUID": {}, "fsync": {},
	"getClusterParameter": {}, "getCmdLineOpts": {}, "getDefaultRWConcern": {},
	"getLog": {}, "getParameter": {}, "getShardMap": {}, "grantRole": {},
	"hostInfo": {}, "impersonate": {}, "indexStats": {}, "inprog": {},
	"insert": {}, "invalidateUserCache": {}, "killAnyCursor": {},
	"killAnySession": {}, "killCursors": {}, "killop": {}, "listClusterCatalog": {},
	"listCollections": {}, "listDatabases": {}, "listIndexes": {},
	"listSearchIndexes": {}, "listSessions": {}, "listShards": {},
	"logRotate": {}, "moveChunk": {}, "moveCollection": {}, "oidReset": {},
	"planCacheIndexFilter": {}, "planCacheRead": {}, "planCacheWrite": {},
	"querySettings": {}, "queryStatsRead": {}, "queryStatsReadTransformed": {},
	"refineCollectionShardKey": {}, "reIndex": {}, "remove": {},
	"removeShard": {}, "renameCollectionSameDB": {}, "replSetConfigure": {},
	"replSetGetConfig": {}, "replSetGetStatus": {}, "replSetHeartbeat": {},
	"replSetStateChange": {}, "reshardCollection": {}, "resync": {},
	"revokeRole": {}, "rewriteCollection": {}, "rotateCertificates": {},
	"serverStatus": {}, "setAuthenticationRestriction": {},
	"setDefaultRWConcern": {}, "setFeatureCompatibilityVersion": {},
	"setParameter": {}, "setUserWriteBlockMode": {}, "shardedDataDistribution": {},
	"shardingState": {}, "shutdown": {}, "splitChunk": {}, "top": {},
	"touch": {}, "transitionFromDedicatedConfigServer": {},
	"transitionToDedicatedConfigServer": {}, "unlock": {},
	"unshardCollection": {}, "update": {}, "updateSearchIndex": {},
	"useUUID": {}, "validate": {}, "viewRole": {}, "viewUser": {},
}

// clusterAllowedActions are actions which MongoDB accepts on a cluster resource.
// The list also contains documented actions that support both cluster and
// database/collection resources. It keeps obviously invalid pairs such as
// find/{cluster:true} out of an immutable policy before target access.
var clusterAllowedActions = map[string]struct{}{
	"addShard": {}, "appendOplogNote": {}, "applicationMessage": {},
	"authSchemaUpgrade": {}, "bypassDefaultMaxTimeMS": {},
	"bypassWriteBlockingMode": {}, "checkMetadataConsistency": {},
	"cleanupOrphaned": {}, "closeAllDatabases": {}, "compact": {},
	"connPoolStats": {}, "connPoolSync": {}, "cpuProfiler": {},
	"dropConnections": {}, "enableSharding": {}, "flushRouterConfig": {},
	"forceUUID": {}, "fsync": {}, "getClusterParameter": {},
	"getCmdLineOpts": {}, "getDefaultRWConcern": {}, "getLog": {},
	"getParameter": {}, "getShardMap": {}, "hostInfo": {}, "impersonate": {},
	"inprog": {}, "invalidateUserCache": {}, "killAnySession": {},
	"killop": {}, "listClusterCatalog": {}, "listDatabases": {},
	"listSessions": {}, "listShards": {}, "logRotate": {}, "moveCollection": {},
	"oidReset": {}, "queryStatsRead": {}, "queryStatsReadTransformed": {},
	"removeShard": {}, "replSetConfigure": {}, "replSetGetConfig": {},
	"replSetGetStatus": {}, "replSetHeartbeat": {}, "replSetStateChange": {},
	"resync": {}, "rotateCertificates": {}, "serverStatus": {},
	"setDefaultRWConcern": {}, "setFeatureCompatibilityVersion": {},
	"setParameter": {}, "setUserWriteBlockMode": {}, "shardedDataDistribution": {},
	"shardingState": {}, "shutdown": {}, "splitChunk": {}, "top": {},
	"touch": {}, "transitionFromDedicatedConfigServer": {},
	"transitionToDedicatedConfigServer": {}, "unlock": {},
	"unshardCollection": {}, "useUUID": {},
}

// namespaceForbiddenActions are cluster-only. A few actions above (compact,
// checkMetadataConsistency and enableSharding) intentionally do not appear
// here because MongoDB documents both cluster and namespace resource forms.
var namespaceForbiddenActions = map[string]struct{}{
	"addShard": {}, "appendOplogNote": {}, "applicationMessage": {},
	"authSchemaUpgrade": {}, "bypassDefaultMaxTimeMS": {},
	"bypassWriteBlockingMode": {}, "cleanupOrphaned": {}, "closeAllDatabases": {},
	"connPoolStats": {}, "connPoolSync": {}, "cpuProfiler": {},
	"dropConnections": {}, "flushRouterConfig": {}, "forceUUID": {},
	"fsync": {}, "getClusterParameter": {}, "getCmdLineOpts": {},
	"getDefaultRWConcern": {}, "getLog": {}, "getParameter": {},
	"getShardMap": {}, "hostInfo": {}, "impersonate": {}, "inprog": {},
	"invalidateUserCache": {}, "killAnySession": {}, "killop": {},
	"listClusterCatalog": {}, "listDatabases": {}, "listSessions": {},
	"listShards": {}, "logRotate": {}, "moveCollection": {}, "oidReset": {},
	"queryStatsRead": {}, "queryStatsReadTransformed": {}, "removeShard": {},
	"replSetConfigure": {}, "replSetGetConfig": {}, "replSetGetStatus": {},
	"replSetHeartbeat": {}, "replSetStateChange": {}, "resync": {},
	"rotateCertificates": {}, "serverStatus": {}, "setDefaultRWConcern": {},
	"setFeatureCompatibilityVersion": {}, "setParameter": {},
	"setUserWriteBlockMode": {}, "shardedDataDistribution": {},
	"shardingState": {}, "shutdown": {}, "splitChunk": {}, "top": {},
	"touch": {}, "transitionFromDedicatedConfigServer": {},
	"transitionToDedicatedConfigServer": {}, "unlock": {},
	"unshardCollection": {}, "useUUID": {},
}

// collectionForbiddenActions require a database-wide resource. MongoDB does
// not accept role/user administration or database lifecycle actions scoped to
// one collection.
var collectionForbiddenActions = map[string]struct{}{
	"changeCustomData": {}, "changeOwnCustomData": {}, "changeOwnPassword": {},
	"changePassword": {}, "compactStructuredEncryptionData": {},
	"createRole": {}, "createUser": {}, "dbStats": {}, "dropDatabase": {},
	"dropRole": {}, "dropUser": {}, "enableProfiler": {}, "grantRole": {},
	"listCollections": {}, "renameCollectionSameDB": {}, "revokeRole": {},
	"setAuthenticationRestriction": {}, "viewRole": {}, "viewUser": {},
}

// collectionRequiredActions cannot be attached to a whole database. MongoDB
// defines both actions in terms of one concrete collection/cursor namespace.
var collectionRequiredActions = map[string]struct{}{
	"killAnyCursor": {}, "planCacheIndexFilter": {},
}

var concreteDatabaseActions = map[string]struct{}{
	"changeCustomData": {}, "changeOwnCustomData": {}, "changeOwnPassword": {},
	"changePassword": {}, "compactStructuredEncryptionData": {},
	"createRole": {}, "createUser": {}, "dbStats": {}, "dropDatabase": {},
	"dropRole": {}, "dropUser": {}, "enableProfiler": {}, "grantRole": {},
	"listCollections": {}, "renameCollectionSameDB": {}, "revokeRole": {},
	"setAuthenticationRestriction": {}, "viewRole": {}, "viewUser": {},
}

var builtinRoleNames = map[string]struct{}{
	"__system": {}, "backup": {}, "clusterAdmin": {}, "clusterManager": {},
	"clusterMonitor": {}, "dbAdmin": {}, "dbAdminAnyDatabase": {},
	"dbOwner": {}, "directShardOperations": {}, "enableSharding": {},
	"hostManager": {}, "read": {}, "readAnyDatabase": {}, "readWrite": {},
	"readWriteAnyDatabase": {}, "restore": {}, "root": {}, "userAdmin": {},
	"userAdminAnyDatabase": {}, "searchCoordinator": {},
}

var assignableBuiltinDependencies = map[string]struct{}{
	"read": {}, "readWrite": {},
}

// AllowedActions returns a sorted copy for API/UI option generation and
// tests. The returned slice is detached from the package-owned allowlist.
func AllowedActions() []string {
	out := make([]string, 0, len(documentedActions))
	for action := range documentedActions {
		out = append(out, action)
	}
	slices.Sort(out)
	return out
}

// Normalize returns a canonical copy. Repeated inherited roles are deduped;
// privileges for the same resource are merged and their actions are sorted
// and deduped, matching MongoDB's set semantics.
func Normalize(template RolePolicyTemplate) RolePolicyTemplate {
	out := template

	roleSet := make(map[string]adapter.MongoRoleRef, len(template.InheritedRoles))
	for _, ref := range template.InheritedRoles {
		roleSet[RoleIdentity(ref.DB, ref.Role)] = ref
	}
	out.InheritedRoles = make([]adapter.MongoRoleRef, 0, len(roleSet))
	for _, ref := range roleSet {
		out.InheritedRoles = append(out.InheritedRoles, ref)
	}
	slices.SortFunc(out.InheritedRoles, func(a, b adapter.MongoRoleRef) int {
		return strings.Compare(RoleIdentity(a.DB, a.Role), RoleIdentity(b.DB, b.Role))
	})

	type mergedPrivilege struct {
		resource adapter.MongoRoleResource
		actions  map[string]struct{}
	}
	merged := make(map[string]mergedPrivilege, len(template.Privileges))
	for _, privilege := range template.Privileges {
		key := ResourceKey(privilege.Resource)
		entry, ok := merged[key]
		if !ok {
			entry = mergedPrivilege{resource: privilege.Resource, actions: map[string]struct{}{}}
		}
		for _, action := range privilege.Actions {
			entry.actions[action] = struct{}{}
		}
		merged[key] = entry
	}
	keys := make([]string, 0, len(merged))
	for key := range merged {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	out.Privileges = make([]adapter.MongoRolePrivilege, 0, len(keys))
	for _, key := range keys {
		entry := merged[key]
		actions := make([]string, 0, len(entry.actions))
		for action := range entry.actions {
			actions = append(actions, action)
		}
		slices.Sort(actions)
		out.Privileges = append(out.Privileges, adapter.MongoRolePrivilege{
			Resource: entry.resource,
			Actions:  actions,
		})
	}
	return out
}

// Validate rejects ambiguous, unsafe and unbounded catalogs. Only read and
// readWrite may be inherited as built-ins; every other dependency must be
// another template in this same catalog, and the resulting graph must be
// acyclic.
func Validate(templates []RolePolicyTemplate) error {
	if len(templates) > MaxTemplates {
		return fmt.Errorf("mongodb_role_policy_templates has %d entries; maximum is %d", len(templates), MaxTemplates)
	}
	keys := make(map[string]struct{}, len(templates))
	names := make(map[string]struct{}, len(templates))
	identities := make(map[string]RolePolicyTemplate, len(templates))
	for i, template := range templates {
		field := fmt.Sprintf("mongodb_role_policy_templates[%d]", i)
		if err := validateTemplateShape(field, template); err != nil {
			return err
		}
		identity := RoleIdentity(template.RoleDatabase, template.RoleName)
		if _, exists := keys[template.Key]; exists {
			return fmt.Errorf("mongodb_role_policy_templates key %q is duplicated", template.Key)
		}
		if _, exists := names[template.Name]; exists {
			return fmt.Errorf("mongodb_role_policy_templates name %q is duplicated", template.Name)
		}
		if _, exists := identities[identity]; exists {
			return fmt.Errorf("mongodb_role_policy_templates role %q is managed by more than one template", identity)
		}
		keys[template.Key] = struct{}{}
		names[template.Name] = struct{}{}
		identities[identity] = template
	}

	graph := make(map[string][]string, len(templates))
	for i, raw := range templates {
		template := Normalize(raw)
		identity := RoleIdentity(template.RoleDatabase, template.RoleName)
		for _, ref := range template.InheritedRoles {
			dependency := RoleIdentity(ref.DB, ref.Role)
			if dependency == identity {
				return fmt.Errorf("mongodb_role_policy_templates[%d].inherited_roles contains the policy role itself", i)
			}
			if _, builtin := assignableBuiltinDependencies[ref.Role]; builtin {
				continue
			}
			if _, exists := identities[dependency]; !exists {
				return fmt.Errorf("mongodb_role_policy_templates[%d].inherited_roles references unmanaged role %q", i, dependency)
			}
			graph[identity] = append(graph[identity], dependency)
		}
	}
	if cycle := dependencyCycle(graph); len(cycle) > 0 {
		return fmt.Errorf("mongodb_role_policy_templates inheritance cycle: %s", strings.Join(cycle, " -> "))
	}
	return nil
}

func validateTemplateShape(field string, template RolePolicyTemplate) error {
	if err := validateText(field+".key", template.Key, MaxKeyLength); err != nil {
		return err
	}
	if !templateKeyRE.MatchString(template.Key) {
		return fmt.Errorf("%s.key must match %s", field, templateKeyRE.String())
	}
	if err := validateText(field+".name", template.Name, MaxNameLength); err != nil {
		return err
	}
	if err := validateText(field+".description", template.Description, MaxDescriptionLength); err != nil {
		return err
	}
	if err := validateRoleName(field+".role_name", template.RoleName); err != nil {
		return err
	}
	if _, builtin := builtinRoleNames[template.RoleName]; builtin {
		return fmt.Errorf("%s.role_name collides with a built-in MongoDB role", field)
	}
	if err := validateDatabase(field+".role_database", template.RoleDatabase); err != nil {
		return err
	}
	if len(template.InheritedRoles) > MaxInheritedRoles {
		return fmt.Errorf("%s.inherited_roles has %d entries; maximum is %d", field, len(template.InheritedRoles), MaxInheritedRoles)
	}
	for i, ref := range template.InheritedRoles {
		refField := fmt.Sprintf("%s.inherited_roles[%d]", field, i)
		if err := validateRoleName(refField+".role", ref.Role); err != nil {
			return err
		}
		if err := validateDatabase(refField+".db", ref.DB); err != nil {
			return err
		}
		if _, builtin := builtinRoleNames[ref.Role]; builtin {
			if _, allowed := assignableBuiltinDependencies[ref.Role]; !allowed {
				return fmt.Errorf("%s.role built-in %q is not an allowed dependency", refField, ref.Role)
			}
		}
		if template.RoleDatabase != "admin" && ref.DB != template.RoleDatabase {
			return fmt.Errorf("%s.db must equal role_database for a non-admin role", refField)
		}
	}
	if len(template.Privileges) > MaxPrivileges {
		return fmt.Errorf("%s.privileges has %d entries; maximum is %d", field, len(template.Privileges), MaxPrivileges)
	}
	for i, privilege := range template.Privileges {
		privilegeField := fmt.Sprintf("%s.privileges[%d]", field, i)
		if err := validateResource(privilegeField+".resource", template.RoleDatabase, privilege.Resource); err != nil {
			return err
		}
		if len(privilege.Actions) == 0 {
			return fmt.Errorf("%s.actions must not be empty", privilegeField)
		}
		if len(privilege.Actions) > MaxActions {
			return fmt.Errorf("%s.actions has %d entries; maximum is %d", privilegeField, len(privilege.Actions), MaxActions)
		}
		for _, action := range privilege.Actions {
			if _, allowed := documentedActions[action]; !allowed {
				return fmt.Errorf("%s.actions contains unsupported action %q", privilegeField, action)
			}
			_, clusterAllowed := clusterAllowedActions[action]
			_, namespaceForbidden := namespaceForbiddenActions[action]
			if privilege.Resource.Cluster && !clusterAllowed ||
				!privilege.Resource.Cluster && namespaceForbidden {
				return fmt.Errorf("%s action %q is not valid for this resource shape", privilegeField, action)
			}
			if privilege.Resource.Collection != "" {
				if _, forbidden := collectionForbiddenActions[action]; forbidden {
					return fmt.Errorf("%s action %q requires a database resource", privilegeField, action)
				}
			} else if _, required := collectionRequiredActions[action]; required {
				return fmt.Errorf("%s action %q requires a collection resource", privilegeField, action)
			}
			if privilege.Resource.DB == "" {
				if _, concrete := concreteDatabaseActions[action]; concrete {
					return fmt.Errorf("%s action %q requires a concrete database", privilegeField, action)
				}
			}
		}
	}
	return nil
}

func validateResource(field, roleDatabase string, resource adapter.MongoRoleResource) error {
	if resource.AnyResource {
		return fmt.Errorf("%s.any_resource is not supported by managed templates", field)
	}
	if resource.Cluster {
		if resource.DB != "" || resource.Collection != "" {
			return fmt.Errorf("%s cluster resource must not include db or collection", field)
		}
		if roleDatabase != "admin" {
			return fmt.Errorf("%s cluster resource is allowed only for a role in admin", field)
		}
		return nil
	}
	if resource.DB != "" {
		if err := validateDatabase(field+".db", resource.DB); err != nil {
			return err
		}
	}
	if resource.Collection != "" {
		if err := validateIdentifier(field+".collection", resource.Collection, MaxCollectionLength, collectionRE); err != nil {
			return err
		}
	}
	if roleDatabase != "admin" && resource.DB != roleDatabase {
		return fmt.Errorf("%s.db must equal role_database for a non-admin role", field)
	}
	return nil
}

func dependencyCycle(graph map[string][]string) []string {
	state := make(map[string]uint8, len(graph))
	stack := make([]string, 0, len(graph))
	var visit func(string) []string
	visit = func(node string) []string {
		state[node] = 1
		stack = append(stack, node)
		for _, dependency := range graph[node] {
			switch state[dependency] {
			case 0:
				if cycle := visit(dependency); len(cycle) > 0 {
					return cycle
				}
			case 1:
				start := slices.Index(stack, dependency)
				cycle := append([]string(nil), stack[start:]...)
				return append(cycle, dependency)
			}
		}
		stack = stack[:len(stack)-1]
		state[node] = 2
		return nil
	}
	keys := make([]string, 0, len(graph))
	for key := range graph {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		if state[key] == 0 {
			if cycle := visit(key); len(cycle) > 0 {
				return cycle
			}
		}
	}
	return nil
}

// RoleIdentity returns the stable MongoDB role identity used by validation
// and fingerprints. External permission IDs add the role: prefix separately.
func RoleIdentity(database, role string) string { return database + "." + role }

// ResourceKey returns a stable, collision-free key for privilege merging and
// adapter fingerprints.
func ResourceKey(resource adapter.MongoRoleResource) string {
	switch {
	case resource.AnyResource:
		return "any"
	case resource.Cluster:
		return "cluster"
	default:
		return "namespace\x00" + resource.DB + "\x00" + resource.Collection
	}
}

// Fingerprint includes the normalized full template, matching the durable
// immutable intent pinned into role-policy operations.
func Fingerprint(template RolePolicyTemplate) string {
	raw, _ := json.Marshal(Normalize(template))
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func CatalogFingerprint(templates []RolePolicyTemplate) string {
	normalized := make([]RolePolicyTemplate, len(templates))
	for i := range templates {
		normalized[i] = Normalize(templates[i])
	}
	slices.SortFunc(normalized, func(a, b RolePolicyTemplate) int {
		return strings.Compare(a.Key, b.Key)
	})
	raw, _ := json.Marshal(normalized)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Spec converts a validated catalog entry into the shared immutable adapter
// envelope. Database intentionally carries MongoDB's role_database so generic
// core identity fencing remains Engine/RoleName/Database.
func Spec(template RolePolicyTemplate) adapter.RolePolicySpec {
	template = Normalize(template)
	out := adapter.RolePolicySpec{
		Engine: "mongodb", Key: template.Key, Name: template.Name,
		Description: template.Description, RoleName: template.RoleName,
		Database: template.RoleDatabase,
	}
	// Mongo fields are omitempty in the durable shared envelope. Canonical nil
	// for empty slices survives JSONB/connector round-trips; a non-nil empty
	// slice would come back nil and make reflect-based transition fencing see a
	// phantom spec edit on every discovery.
	if len(template.InheritedRoles) > 0 {
		out.MongoInheritedRoles = slices.Clone(template.InheritedRoles)
	}
	if len(template.Privileges) > 0 {
		out.MongoPrivileges = clonePrivileges(template.Privileges)
	}
	return out
}

func clonePrivileges(values []adapter.MongoRolePrivilege) []adapter.MongoRolePrivilege {
	out := make([]adapter.MongoRolePrivilege, len(values))
	for i := range values {
		out[i] = values[i]
		out[i].Actions = slices.Clone(values[i].Actions)
	}
	return out
}

// FromAttributes restores typed templates after a direct connection
// projection or a connector JSON round-trip.
func FromAttributes(attributes map[string]any) ([]RolePolicyTemplate, error) {
	value, ok := attributes[AttributeRolePolicyTemplates]
	if !ok || value == nil {
		return nil, nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal %s: %w", AttributeRolePolicyTemplates, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var templates []RolePolicyTemplate
	if err := dec.Decode(&templates); err != nil {
		return nil, fmt.Errorf("decode %s: %w", AttributeRolePolicyTemplates, err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("decode %s: trailing data", AttributeRolePolicyTemplates)
	}
	if err := Validate(templates); err != nil {
		return nil, err
	}
	for i := range templates {
		templates[i] = Normalize(templates[i])
	}
	return templates, nil
}

func validateText(field, value string, max int) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", field)
	}
	if value != strings.TrimSpace(value) {
		return fmt.Errorf("%s must not have leading or trailing whitespace", field)
	}
	if len(value) > max {
		return fmt.Errorf("%s exceeds %d bytes", field, max)
	}
	if strings.ContainsRune(value, '\x00') || strings.ContainsFunc(value, func(r rune) bool {
		return r < 0x20 || r == 0x7f
	}) {
		return fmt.Errorf("%s contains control characters", field)
	}
	return nil
}

func validateIdentifier(field, value string, max int, pattern *regexp.Regexp) error {
	if err := validateText(field, value, max); err != nil {
		return err
	}
	if !pattern.MatchString(value) {
		return fmt.Errorf("%s must match %s", field, pattern.String())
	}
	return nil
}

func validateRoleName(field, value string) error {
	return validateIdentifier(field, value, MaxRoleNameLength, roleNameRE)
}

func validateDatabase(field, value string) error {
	return validateIdentifier(field, value, MaxDatabaseLength, databaseRE)
}
