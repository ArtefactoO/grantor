package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/databaseprovisioning"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/rolepolicies"
	"github.com/ArtefactoO/grantor/internal/postgresconfig"
)

// Only the root is queued. Child operations are durable progress/receipts and
// run inline while its worker owns the connection advisory lock.
const (
	KindDatabaseCreateWithRoles = "resource.create.database_with_roles"
	// Distinct child kinds prevent an old worker from ignoring the authority/OID
	// fence if a stale client attempts to enqueue an inline child directly.
	KindResourceCreatePreparedDatabase = "resource.create.prepared_database"
	KindRolePolicyCreateDatabase       = "role.policy.create_database"
)

type DatabaseCreateWithRolesPayload struct {
	ResourceID                    uuid.UUID      `json:"resource_id"`
	Name                          string         `json:"name"`
	Options                       map[string]any `json:"options,omitempty"`
	ExpectedTargetIdentity        string         `json:"expected_target_identity"`
	ExpectedAdminIdentity         string         `json:"expected_admin_identity,omitempty"`
	ExpectedConfigIncarnation     string         `json:"expected_config_incarnation,omitempty"`
	ExpectedCredentialIncarnation int            `json:"expected_credential_incarnation,omitempty"`
	ExpectedDatabaseOwner         string         `json:"expected_database_owner,omitempty"`
	ExpectedDatabaseOwnerOID      uint32         `json:"expected_database_owner_oid,omitempty"`
	ExpectedCatalogFingerprint    string         `json:"expected_catalog_fingerprint,omitempty"`
}

type databaseCreationProof struct {
	OID            uint32
	Owner          string
	OwnerOID       uint32
	TargetIdentity string
}

func databaseOID(value any) (uint32, bool) {
	switch n := value.(type) {
	case uint32:
		return n, n > 0
	case float64:
		if n > 0 && n <= math.MaxUint32 && n == math.Trunc(n) {
			return uint32(n), true
		}
	case json.Number:
		i, err := n.Int64()
		if err == nil && i > 0 && i <= math.MaxUint32 {
			return uint32(i), true
		}
	}
	return 0, false
}

func parseDatabaseCreationProof(v *adapter.Verification, name, target string) (databaseCreationProof, error) {
	if v == nil || !v.Verified {
		return databaseCreationProof{}, errors.New("database creation has no successful verification")
	}
	oid, ok := databaseOID(v.Observed["database_oid"])
	owner, _ := v.Observed["database_owner"].(string)
	ownerOID, ownerOK := databaseOID(v.Observed["database_owner_oid"])
	actualTarget, _ := v.Observed["target_identity"].(string)
	if !ok || !ownerOK || owner == "" || v.Observed["database_name"] != name || actualTarget != target || target == "" {
		return databaseCreationProof{}, errors.New("database creation verification lacks pinned database identity")
	}
	return databaseCreationProof{OID: oid, Owner: owner, OwnerOID: ownerOID, TargetIdentity: actualTarget}, nil
}

// Run the read-only preflight before the durable first-side-effect marker.
// Never clear that marker based on error text: a lost CREATE response is not a
// safe authorization to assign rights on a database discovered by name later.
func (e *MainExecutor) executeDatabaseCreateWithRoles(ctx context.Context, op operations.Operation) error {
	var payload DatabaseCreateWithRolesPayload
	if err := json.Unmarshal(op.Payload, &payload); err != nil {
		return terminal(fmt.Errorf("database workflow payload: %w", err))
	}
	if op.Kind != KindPostgresDatabaseCreateWithRolesV2 || op.ParentID != nil || op.ConnectionID == nil ||
		payload.ResourceID == uuid.Nil || payload.Name == "" || payload.ExpectedTargetIdentity == "" ||
		payload.ExpectedAdminIdentity == "" || payload.ExpectedConfigIncarnation == "" ||
		payload.ExpectedCredentialIncarnation <= 0 || payload.ExpectedDatabaseOwner == "" ||
		payload.ExpectedDatabaseOwnerOID == 0 || payload.ExpectedCatalogFingerprint == "" {
		return terminal(errors.New("database workflow requires root, resource, name and target identity"))
	}
	if err := e.preflightPostgresV2Connector(ctx, op.Kind, *op.ConnectionID); err != nil {
		return err
	}
	store := databaseprovisioning.NewStore()
	row, err := store.Get(ctx, e.deps.Pool, op.ID)
	if err != nil {
		return err
	}
	if row.ConnectionID != *op.ConnectionID || row.ResourceID != payload.ResourceID {
		return terminal(databaseprovisioning.ErrConflict)
	}
	if _, err := e.databaseWorkflowTarget(ctx, payload, row); err != nil {
		return e.failDatabaseWorkflow(ctx, op, "target_changed", err)
	}
	if row.ReadWriteCreated {
		e.databaseWorkflowResult(op.ID, row)
		return nil
	}
	if row.DatabaseCreateStarted && !row.DatabaseCreated {
		return e.failDatabaseWorkflow(ctx, op, "creation_outcome_unconfirmed", terminal(errors.New(
			"database creation outcome is unconfirmed; no role creation or automatic adoption is allowed")))
	}
	if !row.DatabaseCreated {
		if err := e.checkDatabaseCatalogVacancy(ctx, row.ConnectionID, payload.Name); err != nil {
			return e.failDatabaseWorkflow(ctx, op, "catalog_conflict", err)
		}
		resourcePayload := ResourcePayload{ResourceID: payload.ResourceID, Kind: "database", Name: payload.Name,
			Options: payload.Options, ExpectedTargetIdentity: payload.ExpectedTargetIdentity,
			ExpectedAdminIdentity:         payload.ExpectedAdminIdentity,
			ExpectedConfigIncarnation:     payload.ExpectedConfigIncarnation,
			ExpectedCredentialIncarnation: payload.ExpectedCredentialIncarnation,
			ExpectedDatabaseOwner:         payload.ExpectedDatabaseOwner,
			ExpectedDatabaseOwnerOID:      payload.ExpectedDatabaseOwnerOID}
		child, err := e.databaseChild(ctx, op, "database", KindPostgresResourceCreateDatabaseForRolesV2, resourcePayload)
		if err != nil {
			return err
		}
		if err := e.runDatabaseChild(ctx, child, e.executeResourceCreate); err != nil {
			row, loadErr := store.Get(ctx, e.deps.Pool, op.ID)
			if loadErr != nil {
				return errors.Join(err, loadErr)
			}
			code := "database_preflight_failed"
			if row.DatabaseCreateStarted && !row.DatabaseCreated {
				code = "creation_outcome_unconfirmed"
				err = terminal(err)
			}
			return e.failDatabaseWorkflow(ctx, op, code, err)
		}
		row, err = store.Get(ctx, e.deps.Pool, op.ID)
		if err != nil {
			return err
		}
		if !row.DatabaseCreated {
			return e.failDatabaseWorkflow(ctx, op, "creation_outcome_unconfirmed", terminal(databaseprovisioning.ErrConflict))
		}
	} else {
		child, err := operations.NewStore().Get(ctx, e.deps.Pool, databaseChildID(op.ID, "database"))
		if err != nil {
			return err
		}
		if err := e.runDatabaseChild(ctx, child, e.executeResourceCreate); err != nil {
			return err
		}
	}
	if _, err := e.databaseWorkflowTarget(ctx, payload, row); err != nil {
		return e.failDatabaseWorkflow(ctx, op, "target_changed", err)
	}
	if row.Phase == "database_created" {
		child, err := e.databaseChild(ctx, op, "discover_database", KindConnectionDiscover, struct{}{})
		if err != nil {
			return err
		}
		if err := e.refreshDatabaseDiscovery(ctx, child); err != nil {
			return e.failDatabaseWorkflow(ctx, op, "database_discovery_failed", err)
		}
		if err := e.prepareDatabaseCatalog(ctx, payload, row); err != nil {
			return e.failDatabaseWorkflow(ctx, op, "catalog_preparation_failed", err)
		}
		row, err = store.Get(ctx, e.deps.Pool, op.ID)
		if err != nil {
			return err
		}
	}
	if _, err := e.databaseWorkflowTarget(ctx, payload, row); err != nil {
		return e.failDatabaseWorkflow(ctx, op, "target_changed", err)
	}
	if err := e.validateDatabaseCatalog(ctx, row); err != nil {
		return e.failDatabaseWorkflow(ctx, op, "catalog_changed", err)
	}
	child, err := e.databaseChild(ctx, op, "discover_policies", KindConnectionDiscover, struct{}{})
	if err != nil {
		return err
	}
	_, reservedErr := operations.NewStore().Get(ctx, e.deps.Pool, databaseChildID(op.ID, "read"))
	if reservedErr != nil && !errors.Is(reservedErr, operations.ErrNotFound) {
		return reservedErr
	}
	if errors.Is(reservedErr, operations.ErrNotFound) {
		// A successful snapshot can carry unavailable/blocked policy authority. Until
		// policy transitions have been reserved, refresh those observations on
		// retry, but never re-derive the already frozen catalog/specs.
		err = e.refreshDatabaseDiscovery(ctx, child)
	} else {
		err = e.runDatabaseChild(ctx, child, e.executeDiscover)
	}
	if err != nil {
		return e.failDatabaseWorkflow(ctx, op, "policy_discovery_failed", err)
	}
	if _, err := e.databaseWorkflowTarget(ctx, payload, row); err != nil {
		return e.failDatabaseWorkflow(ctx, op, "target_changed", err)
	}
	children, err := e.reserveDatabasePolicies(ctx, op, payload, row)
	if err != nil {
		return e.failDatabaseWorkflow(ctx, op, "policy_preparation_failed", err)
	}
	if !row.ReadCreated {
		// Both target Plans must pass before READ is allowed to mutate. This
		// catches unsafe/colliding RW roles without leaving a avoidable half-pair.
		for _, child := range children {
			if err := e.preflightDatabasePolicy(ctx, child); err != nil {
				return e.failDatabaseWorkflow(ctx, op, "policy_preflight_failed", err)
			}
		}
	}
	for i, child := range children {
		if (i == 0 && row.ReadCreated) || (i == 1 && row.ReadWriteCreated) {
			continue
		}
		if _, err := e.databaseWorkflowTarget(ctx, payload, row); err != nil {
			return e.failDatabaseWorkflow(ctx, op, "target_changed", err)
		}
		if err := e.validateDatabaseCatalog(ctx, row); err != nil {
			return e.failDatabaseWorkflow(ctx, op, "catalog_changed", err)
		}
		if err := e.runDatabaseChild(ctx, child, e.executeRolePolicy); err != nil {
			stage := "read_role_failed"
			if i == 1 {
				stage = "read_write_role_failed"
			}
			return e.failDatabaseWorkflow(ctx, op, stage, err)
		}
		if err := store.ConfirmRole(ctx, e.deps.Pool, op.ID, i == 1); err != nil {
			return err
		}
	}
	row, err = store.Get(ctx, e.deps.Pool, op.ID)
	if err != nil {
		return err
	}
	e.databaseWorkflowResult(op.ID, row)
	return nil
}

// A successful discovery is not proof of complete scope/authority availability.
// Callers refresh only before freezing the catalog or reserving the policies.
// Scope is never re-derived after PrepareCatalog. The immutable history child
// remains stable; connector attempts get fresh read-only dedup keys.
func (e *MainExecutor) refreshDatabaseDiscovery(ctx context.Context, child operations.Operation) error {
	if child.Status == operations.StatusSuccess {
		return e.executeDiscover(ctx, child)
	}
	return e.runDatabaseChild(ctx, child, e.executeDiscover)
}

func (e *MainExecutor) databaseWorkflowTarget(ctx context.Context, p DatabaseCreateWithRolesPayload, r databaseprovisioning.Row) (connections.Connection, error) {
	conn, err := e.deps.Connections.Get(ctx, e.deps.Pool, r.ConnectionID)
	if err != nil {
		return conn, err
	}
	if conn.Engine != "postgres" || connections.TargetIdentity(conn) != p.ExpectedTargetIdentity ||
		(r.DatabaseCreated && r.TargetIdentity != p.ExpectedTargetIdentity) {
		return conn, terminal(errors.New("database workflow target identity changed"))
	}
	if conn.Status != connections.StatusActive {
		return conn, terminal(fmt.Errorf("database workflow connection is %s", conn.Status))
	}
	var topology map[string]any
	if json.Unmarshal(conn.Topology, &topology) != nil {
		return conn, terminal(errors.New("database workflow authority topology is malformed"))
	}
	authority, ok := adapter.ProvisioningAuthorityFromTopology(topology, adapter.PostgresProvisioningAuthorityTopologyKey)
	if !ok || authority.Status != adapter.ProvisioningAuthorityConfirmed ||
		authority.ExpectedAdminIdentity != p.ExpectedAdminIdentity ||
		authority.CredentialIncarnation != p.ExpectedCredentialIncarnation ||
		authority.TargetIdentity != p.ExpectedTargetIdentity {
		return conn, terminal(errors.New("database workflow SUPERUSER authority changed"))
	}
	catalogMustMatchRootIntent := !r.DatabaseCreated || r.Phase == "database_created"
	if catalogMustMatchRootIntent && connections.ConfigIncarnation(conn) != p.ExpectedConfigIncarnation {
		return conn, terminal(errors.New("database workflow connection config changed before the catalog was frozen"))
	}
	if catalogMustMatchRootIntent {
		var attrs map[string]any
		if json.Unmarshal(conn.DiscoveryConfig, &attrs) != nil {
			return conn, terminal(errors.New("database workflow catalog config is malformed"))
		}
		catalog, err := postgresconfig.FromAttributes(attrs)
		if err != nil || postgresconfig.CatalogFingerprint(catalog) != p.ExpectedCatalogFingerprint {
			return conn, terminal(errors.New("database workflow catalog changed before it was frozen"))
		}
	}
	if r.DatabaseCreated && (r.DatabaseOwner != p.ExpectedDatabaseOwner || r.DatabaseOwnerOID != p.ExpectedDatabaseOwnerOID) {
		return conn, terminal(errors.New("database workflow owner receipt changed"))
	}
	return conn, nil
}

func (e *MainExecutor) failDatabaseWorkflow(ctx context.Context, op operations.Operation, code string, cause error) error {
	if err := databaseprovisioning.NewStore().SetError(ctx, e.deps.Pool, op.ID, code); err != nil {
		return errors.Join(cause, err)
	}
	if row, err := databaseprovisioning.NewStore().Get(ctx, e.deps.Pool, op.ID); err == nil {
		e.databaseWorkflowResult(op.ID, row)
	}
	return fmt.Errorf("database workflow %s: %w", code, cause)
}

func (e *MainExecutor) databaseWorkflowResult(id uuid.UUID, r databaseprovisioning.Row) {
	result, _ := json.Marshal(map[string]any{"phase": r.Phase, "database_created": r.DatabaseCreated,
		"read_created": r.ReadCreated, "read_write_created": r.ReadWriteCreated, "error_code": r.ErrorCode})
	e.setResultArtifact(id, result)
}

func databaseChildID(parent uuid.UUID, stage string) uuid.UUID {
	return uuid.NewSHA1(parent, []byte("database-with-roles:"+stage))
}

func (e *MainExecutor) databaseChild(ctx context.Context, parent operations.Operation, stage, kind string, payload any) (operations.Operation, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return operations.Operation{}, err
	}
	id := databaseChildID(parent.ID, stage)
	key := "database-with-roles:" + parent.ID.String() + ":" + stage
	child, _, err := operations.NewStore().Create(ctx, e.deps.Pool, operations.CreateParams{
		ID: &id, ParentID: &parent.ID, Kind: kind, IdempotencyKey: &key, ConnectionID: parent.ConnectionID,
		ResourceID: parent.ResourceID, Payload: raw, ActorType: parent.ActorType, ActorID: parent.ActorID, CorrelationID: parent.CorrelationID})
	if err != nil {
		return operations.Operation{}, err
	}
	if child.ID != id || child.Kind != kind || child.ParentID == nil || *child.ParentID != parent.ID {
		return operations.Operation{}, terminal(databaseprovisioning.ErrConflict)
	}
	return child, nil
}

// Child statuses commit independently of the root's long-running transaction.
// No River enqueue and no FinalizeParent: that would lock the root row held by
// the current worker, or allow a partial sequence to run outside its lock.
func (e *MainExecutor) runDatabaseChild(ctx context.Context, child operations.Operation, execute func(context.Context, operations.Operation) error) error {
	if child.Status == operations.StatusSuccess {
		return nil
	}
	store := operations.NewStore()
	var err error
	if child.Status == operations.StatusFailed {
		child, err = store.Transition(ctx, e.deps.Pool, child.ID, child.Status, operations.StatusPending, operations.TransitionOpts{})
		if err != nil {
			return err
		}
	}
	if child.Status == operations.StatusPending {
		child, err = store.Transition(ctx, e.deps.Pool, child.ID, child.Status, operations.StatusRunning, operations.TransitionOpts{})
		if err != nil {
			return err
		}
	}
	if child.Status != operations.StatusRunning {
		return terminal(fmt.Errorf("database child %s is %s", child.ID, child.Status))
	}
	execErr := execute(ctx, child)
	artifacts := e.TakeOperationArtifacts(child.ID)
	status := operations.StatusSuccess
	opts := operations.TransitionOpts{Plan: artifacts.Plan, Result: artifacts.Result}
	if execErr != nil {
		status = operations.StatusFailed
		opts.Error = execErr.Error()
	}
	if _, err := store.Transition(ctx, e.deps.Pool, child.ID, operations.StatusRunning, status, opts); err != nil {
		return errors.Join(execErr, err)
	}
	return execErr
}

// Build the same fixed profiles as the existing basic-role form. No account
// membership is included. Unsupported names/schemas fail instead of guessing.
func databaseRoleTemplates(name, owner string, schemas []string) ([]postgresconfig.RolePolicyTemplate, error) {
	if len(name) > 60 {
		return nil, errors.New("database name exceeds the 60-byte default-role limit")
	}
	base := strings.ToLower(name)
	if len(base) > 48 {
		base = base[:48]
	}
	makeTemplate := func(profile, role, suffix, title string) postgresconfig.RolePolicyTemplate {
		return postgresconfig.Normalize(postgresconfig.RolePolicyTemplate{
			Key: "pg-" + base + "-" + suffix, Name: name + " — " + title,
			Description: "Standard " + profile + " access to existing and future objects of the database owner.",
			RoleName:    role + name, Database: name, Schemas: schemas, OwnerRoles: []string{owner}, CreatorRoles: []string{owner}, Profile: profile})
	}
	items := []postgresconfig.RolePolicyTemplate{
		makeTemplate(postgresconfig.ProfileRead, "r_", "read", "чтение"),
		makeTemplate(postgresconfig.ProfileReadWrite, "rw_", "read-write", "чтение и запись")}
	if err := postgresconfig.Validate(items); err != nil {
		return nil, err
	}
	return items, nil
}

func (e *MainExecutor) checkDatabaseCatalogVacancy(ctx context.Context, connectionID uuid.UUID, name string) error {
	// Only identifier validation uses placeholders; target owner and schemas
	// always come from the verified creation receipt and fresh discovery.
	pair, err := databaseRoleTemplates(name, "validation_owner", []string{"validation_schema"})
	if err != nil {
		return terminal(err)
	}
	conn, err := e.deps.Connections.Get(ctx, e.deps.Pool, connectionID)
	if err != nil {
		return err
	}
	var attrs map[string]any
	if err := json.Unmarshal(conn.DiscoveryConfig, &attrs); err != nil {
		return err
	}
	catalog, err := postgresconfig.FromAttributes(attrs)
	if err != nil {
		return err
	}
	if len(catalog)+2 > postgresconfig.MaxTemplates {
		return terminal(errors.New("default role catalog limit exceeded"))
	}
	for _, draft := range pair {
		for _, item := range catalog {
			if item.Key == draft.Key || item.RoleName == draft.RoleName || item.Name == draft.Name {
				return terminal(errors.New("default role catalog identity is already reserved"))
			}
		}
	}
	return nil
}

func (e *MainExecutor) prepareDatabaseCatalog(ctx context.Context, p DatabaseCreateWithRolesPayload, r databaseprovisioning.Row) error {
	conn, err := e.databaseWorkflowTarget(ctx, p, r)
	if err != nil {
		return err
	}
	resources, err := e.deps.Inventory.ListResources(ctx, e.deps.Pool, r.ConnectionID)
	if err != nil {
		return err
	}
	schemas := []string{}
	found := false
	for _, resource := range resources {
		if resource.ID == r.ResourceID {
			var attrs map[string]any
			if err := json.Unmarshal(resource.Attributes, &attrs); err != nil {
				return err
			}
			oid, ok := databaseOID(attrs["database_oid"])
			ownerOID, ownerOK := databaseOID(attrs["owner_oid"])
			if !ok || !ownerOK || oid != r.DatabaseOID || ownerOID != r.DatabaseOwnerOID ||
				attrs["owner"] != r.DatabaseOwner || resource.Name != p.Name ||
				resource.Kind != "database" || resource.Status != inventory.ResourceObserved {
				return terminal(errors.New("discovered database does not match durable creation receipt"))
			}
			found = true
		}
		if resource.ParentID != nil && *resource.ParentID == r.ResourceID && resource.Kind == "schema" && resource.Status == inventory.ResourceObserved {
			name := strings.ToLower(resource.Name)
			if !strings.HasPrefix(name, "pg_") && name != "information_schema" && name != "grantor" {
				schemas = append(schemas, resource.Name)
			}
		}
	}
	if !found {
		return errors.New("created database is absent from discovery")
	}
	slices.Sort(schemas)
	pair, err := databaseRoleTemplates(p.Name, r.DatabaseOwner, schemas)
	if err != nil {
		return terminal(err)
	}
	var attrs map[string]any
	if err := json.Unmarshal(conn.DiscoveryConfig, &attrs); err != nil {
		return err
	}
	if attrs == nil {
		attrs = map[string]any{}
	}
	existing, err := postgresconfig.FromAttributes(attrs)
	if err != nil {
		return err
	}
	for _, draft := range pair {
		for _, item := range existing {
			if item.Key == draft.Key || item.Name == draft.Name || item.RoleName == draft.RoleName {
				return terminal(errors.New("default role catalog identity is already reserved; existing template was not changed"))
			}
		}
	}
	catalog := slices.Concat(existing, pair)
	if err := postgresconfig.Validate(catalog); err != nil {
		return terminal(err)
	}
	attrs[postgresconfig.AttributeRolePolicyTemplates] = catalog
	config, err := json.Marshal(attrs)
	if err != nil {
		return err
	}
	pinned, err := json.Marshal(pair)
	if err != nil {
		return err
	}
	tx, err := e.deps.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	_, err = e.deps.Connections.PatchCAS(ctx, tx, conn.ID, connections.PatchParams{
		DisplayName: conn.DisplayName, Environment: conn.Environment, Tags: conn.Tags, Endpoints: conn.Endpoints, TLSConfig: conn.TLSConfig,
		DiscoveryConfig: config, ExpectedUpdatedAt: conn.UpdatedAt, ExpectedStatus: conn.Status})
	if err != nil {
		return err
	}
	if err := databaseprovisioning.NewStore().PrepareCatalog(ctx, tx, r.OperationID, pinned, pair[0].Key, pair[1].Key); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (e *MainExecutor) validateDatabaseCatalog(ctx context.Context, r databaseprovisioning.Row) error {
	conn, err := e.deps.Connections.Get(ctx, e.deps.Pool, r.ConnectionID)
	if err != nil {
		return err
	}
	var attrs map[string]any
	if err := json.Unmarshal(conn.DiscoveryConfig, &attrs); err != nil {
		return err
	}
	catalog, err := postgresconfig.FromAttributes(attrs)
	if err != nil {
		return err
	}
	var pinned []postgresconfig.RolePolicyTemplate
	if err := json.Unmarshal(r.Templates, &pinned); err != nil {
		return err
	}
	if len(pinned) != 2 {
		return terminal(databaseprovisioning.ErrConflict)
	}
	for _, item := range pinned {
		index := slices.IndexFunc(catalog, func(t postgresconfig.RolePolicyTemplate) bool { return t.Key == item.Key })
		if index < 0 || !reflect.DeepEqual(catalog[index], item) {
			return terminal(errors.New("default role template changed after workflow preparation"))
		}
	}
	return nil
}

func (e *MainExecutor) reserveDatabasePolicies(ctx context.Context, parent operations.Operation,
	p DatabaseCreateWithRolesPayload, r databaseprovisioning.Row) ([]operations.Operation, error) {
	conn, err := e.deps.Connections.Get(ctx, e.deps.Pool, r.ConnectionID)
	if err != nil {
		return nil, err
	}
	var topology map[string]any
	if json.Unmarshal(conn.Topology, &topology) != nil {
		return nil, terminal(errors.New("database policy authority topology is malformed"))
	}
	authority, ok := adapter.ProvisioningAuthorityFromTopology(topology, adapter.PostgresProvisioningAuthorityTopologyKey)
	if !ok || authority.Status != adapter.ProvisioningAuthorityConfirmed {
		return nil, terminal(errors.New("database policy SUPERUSER authority is unavailable"))
	}
	var configAttrs map[string]any
	if json.Unmarshal(conn.DiscoveryConfig, &configAttrs) != nil {
		return nil, terminal(errors.New("database policy catalog is malformed"))
	}
	catalog, err := postgresconfig.FromAttributes(configAttrs)
	if err != nil {
		return nil, err
	}
	catalogFingerprint := postgresconfig.CatalogFingerprint(catalog)
	store := operations.NewStore()
	roleStore := rolepolicies.NewStore()
	stages := []string{"read", "read_write"}
	keys := []string{r.ReadPolicyKey, r.ReadWritePolicyKey}
	children := make([]operations.Operation, 2)
	tx, err := e.deps.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	for i, stage := range stages {
		id := databaseChildID(parent.ID, stage)
		existing, err := store.Get(ctx, tx, id)
		if err == nil {
			payload, err := decodeRolePolicyPayload(existing.Payload)
			if err != nil || existing.ParentID == nil || *existing.ParentID != parent.ID || existing.Kind != KindPostgresRolePolicyCreateDatabaseV2 ||
				payload.ExpectedDatabaseOID != r.DatabaseOID || payload.ExpectedTargetIdentity != p.ExpectedTargetIdentity || payload.Spec.Key != keys[i] {
				return nil, terminal(databaseprovisioning.ErrConflict)
			}
			children[i] = existing
			continue
		}
		if !errors.Is(err, operations.ErrNotFound) {
			return nil, err
		}
		policy, err := roleStore.GetByKey(ctx, tx, r.ConnectionID, keys[i])
		if err != nil {
			return nil, err
		}
		if policy.Managed || policy.Status != rolepolicies.StatusMissing || !policy.ApplySupported || policy.BlockedReason != "" || policy.Dangerous {
			return nil, terminal(errors.New("both default roles must be missing, safe and supported before either is created"))
		}
		key := "database-with-roles:" + parent.ID.String() + ":" + stage
		payload := RolePolicyPayload{RolePolicyID: policy.ID, Action: rolepolicies.ActionCreate, ExpectedVersion: policy.Version + 1,
			ObservedFingerprint: policy.ObservedFingerprint, ExpectedFingerprint: policy.ExpectedFingerprint,
			ExpectedTargetIdentity: p.ExpectedTargetIdentity, ExpectedDatabaseOID: r.DatabaseOID,
			ExpectedDatabaseOwner: r.DatabaseOwner, ExpectedDatabaseOwnerOID: r.DatabaseOwnerOID,
			ExpectedAdminIdentity:         authority.ExpectedAdminIdentity,
			ExpectedConfigIncarnation:     connections.ConfigIncarnation(conn),
			ExpectedCredentialIncarnation: authority.CredentialIncarnation,
			ExpectedCatalogFingerprint:    catalogFingerprint,
			ExternalID:                    policy.ExternalID, Spec: policy.DesiredSpec}
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		child, _, err := store.Create(ctx, tx, operations.CreateParams{ID: &id, Kind: KindPostgresRolePolicyCreateDatabaseV2, IdempotencyKey: &key,
			ParentID: &parent.ID, ConnectionID: parent.ConnectionID, ResourceID: &r.ResourceID, Payload: raw,
			ActorType: parent.ActorType, ActorID: parent.ActorID, CorrelationID: parent.CorrelationID})
		if err != nil {
			return nil, err
		}
		if _, err := roleStore.Reserve(ctx, tx, rolepolicies.ReserveParams{ConnectionID: r.ConnectionID, TemplateKey: keys[i],
			Action: rolepolicies.ActionCreate, OperationID: child.ID, Version: policy.Version, ObservedFingerprint: policy.ObservedFingerprint}); err != nil {
			return nil, err
		}
		children[i] = child
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return children, nil
}

func (e *MainExecutor) preflightDatabasePolicy(ctx context.Context, op operations.Operation) error {
	payload, err := decodeRolePolicyPayload(op.Payload)
	if err != nil {
		return err
	}
	conn, cfg, ad, viaConnector, err := e.mutationTarget(ctx, op.Kind, *op.ConnectionID)
	defer clear(cfg.AdminCredential.Secret)
	if err != nil {
		return err
	}
	if connections.TargetIdentity(conn) != payload.ExpectedTargetIdentity {
		return terminal(errors.New("database workflow target identity changed"))
	}
	if err := validatePostgresRuntimePins(conn, cfg, payload.ExpectedAdminIdentity,
		payload.ExpectedTargetIdentity, payload.ExpectedConfigIncarnation,
		payload.ExpectedCredentialIncarnation); err != nil {
		return err
	}
	spec := payload.Spec
	change := adapter.DesiredChange{Kind: adapter.ChangePostgresRolePolicyCreateDatabaseV2,
		Connection: cfg, RolePolicySpec: &spec,
		ExpectedAdminIdentity:    payload.ExpectedAdminIdentity,
		ExpectedTargetIdentity:   payload.ExpectedTargetIdentity,
		ExpectedDatabaseOID:      payload.ExpectedDatabaseOID,
		ExpectedDatabaseOwner:    payload.ExpectedDatabaseOwner,
		ExpectedDatabaseOwnerOID: payload.ExpectedDatabaseOwnerOID}
	if viaConnector {
		if err := e.requireActiveConnectorCapability(adapter.CapPostgresSuperuserDirectV1); err != nil {
			return err
		}
		preflight := op
		preflight.ID = uuid.NewSHA1(op.ID, []byte("read-only-preflight"))
		job, err := connectorMutationJobOfKind(preflight, conn, cfg, connector.ChangeRef{
			Kind: string(change.Kind), RolePolicySpec: &spec, Permission: change.Permission,
			ExpectedAdminIdentity:      change.ExpectedAdminIdentity,
			ExpectedTargetIdentity:     change.ExpectedTargetIdentity,
			ExpectedDatabaseOID:        change.ExpectedDatabaseOID,
			ExpectedDatabaseOwner:      change.ExpectedDatabaseOwner,
			ExpectedDatabaseOwnerOID:   change.ExpectedDatabaseOwnerOID,
			ExpectedCatalogFingerprint: payload.ExpectedCatalogFingerprint}, connector.JobPlan, time.Now())
		if err != nil {
			return err
		}
		result, err := e.connectorDispatch(ctx, job, connectorJobCredentials(cfg))
		if err != nil {
			return err
		}
		if result.Status != connector.JobSuccess {
			return fmt.Errorf("default role preflight: %s", result.Error)
		}
		return nil
	}
	_, err = ad.Plan(ctx, change)
	return err
}
