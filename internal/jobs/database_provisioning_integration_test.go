//go:build integration

package jobs_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/databaseprovisioning"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/postgresconfig"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

const workflowTarget = "postgres:system:7429012345678901234"

type databaseWorkflowDispatcher struct {
	mu                     sync.Mutex
	name                   string
	databaseCreated        bool
	databasePlanError      bool
	lostCreateResponse     bool
	failReadWrite          int
	policyPlanError        bool
	wrongDiscoveryOID      bool
	skipUserSchemas        bool
	policyDiscoveryBlocked bool
	extraUserSchema        bool
	discoveryCalls         int
	discoveryResults       map[string]connector.JobResult
	roles                  map[string]bool
	mutations              []string
	dedupKinds             map[string]string
}

func (d *databaseWorkflowDispatcher) ActiveConnectorSupports(capability adapter.Capability) bool {
	return capability == adapter.CapPostgresSuperuserDirectV1
}

func (d *databaseWorkflowDispatcher) Dispatch(_ context.Context, job connector.Job, creds connector.JobCredentials) (connector.JobResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if previous, ok := d.dedupKinds[job.IdempotencyKey]; ok && previous != string(job.Kind) {
		return connector.JobResult{}, errors.New("idempotency key reused across phases")
	}
	d.dedupKinds[job.IdempotencyKey] = string(job.Kind)
	if job.Kind == connector.JobDiscover {
		if cached, ok := d.discoveryResults[job.IdempotencyKey]; ok {
			return cached, nil
		}
		d.discoveryCalls++
		payload, err := connector.ParseDiscoverPayload(job.Payload)
		if err != nil {
			return connector.JobResult{}, err
		}
		catalog, err := postgresconfig.FromAttributes(payload.Attributes)
		if err != nil {
			return connector.JobResult{}, err
		}
		observedAt := time.Now()
		snap := &adapter.Snapshot{ObservedAt: observedAt, ServerVersion: "16.4", Topology: map[string]any{
			"system_identifier": "7429012345678901234", "postgres_role_policy_catalog_fingerprint": postgresconfig.CatalogFingerprint(catalog),
			"admin_credential_canonical_identity":  "grantor",
			"postgres_role_policy_apply_supported": true, "postgres_role_policy_create_supported": true,
			adapter.PostgresProvisioningAuthorityTopologyKey: adapter.ProvisioningAuthorityAssessment{
				Status: adapter.ProvisioningAuthorityConfirmed, Reason: adapter.ProvisioningAuthoritySuperuserConfirmed,
				ObservedAt: observedAt, ExpectedAdminIdentity: "grantor", ObservedAdminIdentity: "grantor",
				CredentialIncarnation: creds.AdminCredentialIncarnation,
				ConfigIncarnation:     payload.Connection.ConfigIncarnation, TargetIdentity: workflowTarget,
			}}}
		snap.Accounts = append(snap.Accounts, adapter.ObservedAccount{Kind: "group", EngineIdentity: "app_owner", Attributes: map[string]any{"role_oid": uint32(17)}})
		if d.databaseCreated {
			oid := uint32(54321)
			if d.wrongDiscoveryOID {
				oid++
			}
			snap.Resources = []adapter.ObservedResource{
				{Kind: "database", ExternalID: "db:" + d.name, Name: d.name, CanonicalPath: d.name, Attributes: map[string]any{"owner": "app_owner", "database_oid": oid, "owner_oid": uint32(17)}, Fingerprint: fmt.Sprintf("db-%d", oid)},
				{Kind: "schema", ExternalID: "schema:" + d.name + ".public", ParentExternalID: "db:" + d.name, Name: "public"},
				{Kind: "schema", ExternalID: "schema:" + d.name + ".grantor", ParentExternalID: "db:" + d.name, Name: "grantor"},
			}
			if d.skipUserSchemas {
				snap.Resources = []adapter.ObservedResource{snap.Resources[0], snap.Resources[2]}
			}
			if d.extraUserSchema {
				snap.Resources = append(snap.Resources, adapter.ObservedResource{Kind: "schema", ExternalID: "schema:" + d.name + ".later_schema", ParentExternalID: "db:" + d.name, Name: "later_schema"})
			}
		}
		for _, item := range catalog {
			spec := adapter.RolePolicySpec{Engine: "postgres", Key: item.Key, Name: item.Name, Description: item.Description,
				RoleName: item.RoleName, Database: item.Database, Schemas: item.Schemas, OwnerRoles: item.OwnerRoles, CreatorRoles: item.CreatorRoles, Profile: item.Profile}
			fingerprint := postgresconfig.Fingerprint(item)
			observed := "missing:" + fingerprint
			if d.roles[item.RoleName] {
				observed = fingerprint
				snap.Accounts = append(snap.Accounts, adapter.ObservedAccount{Kind: "group", EngineIdentity: item.RoleName})
			}
			snap.Permissions = append(snap.Permissions, adapter.ObservedPermission{ExternalID: "role:" + item.RoleName, Name: item.RoleName, AccountEngineIdentity: item.RoleName})
			blocked := ""
			if d.policyDiscoveryBlocked {
				blocked = "authority_probe_failed"
				snap.Topology["postgres_role_policy_apply_supported"] = false
			}
			snap.RolePolicies = append(snap.RolePolicies, adapter.ObservedRolePolicy{ExternalID: "role:" + item.RoleName, Spec: spec,
				ExpectedFingerprint: fingerprint, ObservedFingerprint: observed, Exact: d.roles[item.RoleName], ApplySupported: !d.policyDiscoveryBlocked, BlockedReason: blocked,
				Summary: map[string]any{"role": map[string]any{"exists": d.roles[item.RoleName], "safe": true}, "missing": []string{}, "extra": []string{}}})
		}
		raw, err := json.Marshal(snap)
		result := connector.JobResult{JobID: job.ID, Status: connector.JobSuccess, Result: raw}
		if err == nil {
			d.discoveryResults[job.IdempotencyKey] = result
		}
		return result, err
	}
	payload, err := connector.ParseMutationPayload(job.Payload)
	if err != nil {
		return connector.JobResult{}, err
	}
	change := payload.Change
	plan, _ := connector.MarshalSanitizedPlan(&adapter.Plan{Change: adapter.DesiredChange{Kind: adapter.ChangeKind(change.Kind)}, Steps: []adapter.PlanStep{{Kind: "test-apply"}}})
	if job.Kind == connector.JobPlan {
		if (change.Resource != nil && d.databasePlanError) || (change.RolePolicySpec != nil && d.policyPlanError) {
			return connector.JobResult{JobID: job.ID, Status: connector.JobFailed, Error: "preflight rejected", Plan: plan}, nil
		}
		return connector.JobResult{JobID: job.ID, Status: connector.JobSuccess, Plan: plan}, nil
	}
	if job.Kind != connector.JobApply {
		return connector.JobResult{}, fmt.Errorf("unexpected job kind %s", job.Kind)
	}
	verification := &adapter.Verification{Verified: true, Details: "exact"}
	switch adapter.ChangeKind(change.Kind) {
	case adapter.ChangePostgresDatabaseCreateV2:
		if change.Resource == nil || change.ExpectedTargetIdentity != workflowTarget {
			return connector.JobResult{}, errors.New("missing database fences")
		}
		d.databaseCreated = true
		d.mutations = append(d.mutations, "database")
		if d.lostCreateResponse {
			return connector.JobResult{}, errors.New("target created database; response lost")
		}
		verification.Observed = map[string]any{"database_name": d.name, "database_owner": "app_owner", "database_owner_oid": uint32(17), "database_oid": uint32(54321), "target_identity": workflowTarget}
	case adapter.ChangePostgresRolePolicyCreateDatabaseV2:
		if change.RolePolicySpec == nil || change.ExpectedDatabaseOID != 54321 || change.ExpectedDatabaseOwnerOID != 17 || change.ExpectedTargetIdentity != workflowTarget {
			return connector.JobResult{}, errors.New("missing role database fences")
		}
		profile := change.RolePolicySpec.Profile
		d.mutations = append(d.mutations, profile)
		if profile == "read_write" && d.failReadWrite > 0 {
			d.failReadWrite--
			return connector.JobResult{JobID: job.ID, Status: connector.JobFailed, Error: "temporary RW failure", Plan: plan}, nil
		}
		d.roles[change.RolePolicySpec.RoleName] = true
	default:
		return connector.JobResult{}, fmt.Errorf("unexpected target mutation %s", change.Kind)
	}
	result, err := connector.MarshalSanitizedResult(&adapter.Result{Steps: []adapter.StepResult{{Step: adapter.PlanStep{Kind: "test-apply"}, Status: adapter.StepApplied}}}, verification)
	return connector.JobResult{JobID: job.ID, Status: connector.JobSuccess, Plan: plan, Result: result}, err
}

type databaseWorkflowFixture struct {
	pool       *pgxpool.Pool
	conn       connections.Connection
	resource   inventory.Resource
	op         operations.Operation
	executor   *jobs.MainExecutor
	dispatcher *databaseWorkflowDispatcher
}

func newDatabaseWorkflowFixture(t *testing.T) databaseWorkflowFixture {
	t.Helper()
	ctx := context.Background()
	pool := pgtest.Pool(t)
	registerPostgresOnce.Do(func() { adapter.Register(postgres.Engine, func() adapter.Adapter { return postgres.New() }) })
	conn, err := connections.NewStore().Create(ctx, pool, connections.CreateParams{DisplayName: "database-workflow-" + uuid.NewString(),
		Engine: "postgres", Environment: "itest", Endpoints: []string{"isolated-postgres:5432"}, ExecutionMode: connections.ExecutionModeConnector,
		AdminCredentialMode: "existing_vault_ref", VaultAdminPath: testVaultPath})
	if err != nil {
		t.Fatal(err)
	}
	observedAt := time.Now().UTC().Truncate(time.Microsecond)
	topology, _ := json.Marshal(map[string]any{
		"system_identifier": "7429012345678901234", "admin_credential_canonical_identity": "grantor",
		"postgres_role_policy_catalog_fingerprint": postgresconfig.CatalogFingerprint(nil),
		adapter.PostgresProvisioningAuthorityTopologyKey: adapter.ProvisioningAuthorityAssessment{
			Status: adapter.ProvisioningAuthorityConfirmed, Reason: adapter.ProvisioningAuthoritySuperuserConfirmed,
			ObservedAt: observedAt, ExpectedAdminIdentity: "grantor", ObservedAdminIdentity: "grantor",
			CredentialIncarnation: 1, ConfigIncarnation: connections.ConfigIncarnation(conn), TargetIdentity: workflowTarget,
		},
	})
	capabilities, _ := json.Marshal([]string{string(adapter.CapPostgresSuperuserDirectV1),
		string(adapter.ResourceCapability("create", "database")), string(adapter.CapRolePolicyCreate)})
	if _, err := pool.Exec(ctx, `update connections set status='active',topology=$2,last_discovery_at=$3,capabilities=$4 where id=$1`,
		conn.ID, topology, observedAt, capabilities); err != nil {
		t.Fatal(err)
	}
	conn, err = connections.NewStore().Get(ctx, pool, conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	name := "db_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	resource, err := inventory.NewStore().CreatePlannedResource(ctx, pool, inventory.CreatePlannedResourceParams{ConnectionID: conn.ID,
		Kind: "database", ExternalID: "db:" + name, Name: name, CanonicalPath: name})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(jobs.DatabaseCreateWithRolesPayload{ResourceID: resource.ID, Name: name,
		Options: map[string]any{"owner": "app_owner"}, ExpectedTargetIdentity: workflowTarget,
		ExpectedAdminIdentity: "grantor", ExpectedConfigIncarnation: connections.ConfigIncarnation(conn),
		ExpectedCredentialIncarnation: 1, ExpectedDatabaseOwner: "app_owner", ExpectedDatabaseOwnerOID: 17,
		ExpectedCatalogFingerprint: postgresconfig.CatalogFingerprint(nil)})
	if err != nil {
		t.Fatal(err)
	}
	op, _, err := operations.NewStore().Create(ctx, pool, operations.CreateParams{Kind: jobs.KindPostgresDatabaseCreateWithRolesV2, ConnectionID: &conn.ID,
		ResourceID: &resource.ID, Payload: payload, ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	if err := databaseprovisioning.NewStore().Create(ctx, pool, op.ID, resource.ID, conn.ID); err != nil {
		t.Fatal(err)
	}
	d := &databaseWorkflowDispatcher{name: name, roles: map[string]bool{}, dedupKinds: map[string]string{}, discoveryResults: map[string]connector.JobResult{}}
	e := jobs.NewMainExecutor(jobs.DiscoveryDeps{Connections: connections.NewStore(), Inventory: inventory.NewStore(), Audit: audit.NewWriter(), Pool: pool,
		Vault: fakeVaultReader{username: "grantor", password: "secret"}}).WithConnector(jobs.ConnectorDeps{Dispatcher: d})
	return databaseWorkflowFixture{pool: pool, conn: conn, resource: resource, op: op, executor: e, dispatcher: d}
}

func (f databaseWorkflowFixture) row(t *testing.T) databaseprovisioning.Row {
	t.Helper()
	r, err := databaseprovisioning.NewStore().Get(context.Background(), f.pool, f.op.ID)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestDatabaseWorkflowResumesOnlyFailedReadWrite(t *testing.T) {
	f := newDatabaseWorkflowFixture(t)
	f.dispatcher.failReadWrite = 1
	ctx := context.Background()
	if err := f.executor.Execute(ctx, f.op); err == nil {
		t.Fatal("RW failure was ignored")
	} else {
		t.Logf("first attempt: %v", err)
	}
	row := f.row(t)
	if !row.DatabaseCreated || !row.ReadCreated || row.ReadWriteCreated || row.ErrorCode != "read_write_role_failed" {
		t.Fatalf("wrong partial result: %+v", row)
	}
	if err := f.executor.Execute(ctx, f.op); err != nil {
		t.Fatal(err)
	}
	row = f.row(t)
	if row.Phase != "complete" || !row.ReadWriteCreated {
		t.Fatalf("not completed: %+v", row)
	}
	if got := strings.Join(f.dispatcher.mutations, ","); got != "database,read,read_write,read_write" {
		t.Fatalf("unexpected repeated effects: %s", got)
	}
	children, err := operations.NewStore().ListByParent(ctx, f.pool, f.op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(children) != 5 {
		t.Fatalf("children=%d want5", len(children))
	}
	for _, child := range children {
		if child.Status != operations.StatusSuccess {
			t.Fatalf("child %s remains %s", child.Kind, child.Status)
		}
	}
	var bindings, receipts int
	if err := f.pool.QueryRow(ctx, `select count(*) from bindings b join accounts a on a.id=b.account_id where a.connection_id=$1`, f.conn.ID).Scan(&bindings); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(ctx, `select count(*) from role_policy_operation_completions c join operations o on o.id=c.operation_id where o.parent_id=$1`, f.op.ID).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if bindings != 0 || receipts != 2 {
		t.Fatalf("memberships=%d receipts=%d", bindings, receipts)
	}
}

func TestDatabaseWorkflowNeverUsesDiscoveryAsCreationReceipt(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(fmt.Sprint("lost_response_", lost), func(t *testing.T) {
			f := newDatabaseWorkflowFixture(t)
			ctx := context.Background()
			if lost {
				f.dispatcher.lostCreateResponse = true
				if err := f.executor.Execute(ctx, f.op); err == nil {
					t.Fatal("lost response was accepted")
				}
			}
			if _, err := f.pool.Exec(ctx, `update resources set status='observed',attributes='{"owner":"app_owner","owner_oid":17,"database_oid":54321}' where id=$1`, f.resource.ID); err != nil {
				t.Fatal(err)
			}
			if err := f.executor.Execute(ctx, f.op); err == nil {
				t.Fatal("observed database was treated as our creation receipt")
			}
			r := f.row(t)
			if r.DatabaseCreated || r.ReadCreated || r.ReadWriteCreated {
				t.Fatalf("invented receipt: %+v", r)
			}
			if lost && r.ErrorCode != "creation_outcome_unconfirmed" {
				t.Fatalf("error code=%q", r.ErrorCode)
			}
			for _, call := range f.dispatcher.mutations {
				if call != "database" {
					t.Fatalf("role changed without receipt: %s", call)
				}
			}
		})
	}
}

func TestDatabaseWorkflowLivePlanCanRetryWithoutDatabase(t *testing.T) {
	f := newDatabaseWorkflowFixture(t)
	f.dispatcher.databasePlanError = true
	ctx := context.Background()
	if err := f.executor.Execute(ctx, f.op); err == nil {
		t.Fatal("failed live Plan was accepted")
	}
	if r := f.row(t); r.DatabaseCreateStarted || len(f.dispatcher.mutations) > 0 {
		t.Fatalf("preflight crossed target boundary: %+v", r)
	}
	f.dispatcher.databasePlanError = false
	if err := f.executor.Execute(ctx, f.op); err != nil {
		t.Fatal(err)
	}
	if f.row(t).Phase != "complete" {
		t.Fatal("could not resume after live Plan recovered")
	}
}

func TestDatabaseWorkflowChecksBothPolicyPlansBeforeEither(t *testing.T) {
	f := newDatabaseWorkflowFixture(t)
	f.dispatcher.policyPlanError = true
	if err := f.executor.Execute(context.Background(), f.op); err == nil {
		t.Fatal("policy preflight failure ignored")
	}
	if got := strings.Join(f.dispatcher.mutations, ","); got != "database" {
		t.Fatalf("policy mutated before pair passed preflight: %s", got)
	}
}

func TestDatabaseWorkflowRejectsCatalogCollisionBeforeDatabase(t *testing.T) {
	f := newDatabaseWorkflowFixture(t)
	ctx := context.Background()
	item := postgresconfig.RolePolicyTemplate{Key: "existing", Name: "Existing", Description: "Do not change", RoleName: "rw_" + f.resource.Name,
		Database: "foreign", Schemas: []string{"public"}, OwnerRoles: []string{"other_owner"}, CreatorRoles: []string{"other_owner"}, Profile: "read_write"}
	raw, _ := json.Marshal(map[string]any{postgresconfig.AttributeRolePolicyTemplates: []postgresconfig.RolePolicyTemplate{item}})
	if _, err := f.pool.Exec(ctx, `update connections set discovery_config=$2 where id=$1`, f.conn.ID, raw); err != nil {
		t.Fatal(err)
	}
	if err := f.executor.Execute(ctx, f.op); err == nil {
		t.Fatal("collision accepted")
	}
	if f.row(t).DatabaseCreateStarted || len(f.dispatcher.mutations) > 0 {
		t.Fatal("database created despite catalog collision")
	}
}

func TestDatabaseWorkflowRefreshesSuccessfulDiscoveryBeforeCatalogRetry(t *testing.T) {
	f := newDatabaseWorkflowFixture(t)
	f.dispatcher.skipUserSchemas = true
	ctx := context.Background()
	if err := f.executor.Execute(ctx, f.op); err == nil {
		t.Fatal("missing schemas accepted")
	}
	if row := f.row(t); row.Phase != "database_created" || row.ErrorCode != "catalog_preparation_failed" || !row.DatabaseCreated {
		t.Fatalf("wrong preparation failure: %+v", row)
	}
	children, err := operations.NewStore().ListByParent(ctx, f.pool, f.op.ID)
	if err != nil {
		t.Fatal(err)
	}
	var firstDiscoveryID uuid.UUID
	for _, child := range children {
		if child.Kind == jobs.KindConnectionDiscover {
			if child.Status != operations.StatusSuccess {
				t.Fatalf("first discovery did not succeed: %+v", child)
			}
			firstDiscoveryID = child.ID
		}
	}
	if firstDiscoveryID == uuid.Nil {
		t.Fatal("missing discovery history child")
	}
	f.dispatcher.skipUserSchemas = false
	if err := f.executor.Execute(ctx, f.op); err != nil {
		t.Fatal(err)
	}
	if row := f.row(t); row.Phase != "complete" {
		t.Fatalf("catalog did not recover: %+v", row)
	}
	if got := strings.Join(f.dispatcher.mutations, ","); got != "database,read,read_write" {
		t.Fatalf("CREATE repeated: %s", got)
	}
	if f.dispatcher.discoveryCalls != 3 {
		t.Fatalf("discovery calls=%d, want first + fresh retry + policy discovery", f.dispatcher.discoveryCalls)
	}
	children, err = operations.NewStore().ListByParent(ctx, f.pool, f.op.ID)
	if err != nil || len(children) != 5 {
		t.Fatalf("children=%d err=%v", len(children), err)
	}
	if child, err := operations.NewStore().Get(ctx, f.pool, firstDiscoveryID); err != nil || child.Status != operations.StatusSuccess {
		t.Fatalf("discovery history identity changed: %+v %v", child, err)
	}
}

func TestDatabaseWorkflowRefreshesBlockedPolicyObservationWithoutChangingScope(t *testing.T) {
	f := newDatabaseWorkflowFixture(t)
	f.dispatcher.policyDiscoveryBlocked = true
	ctx := context.Background()
	if err := f.executor.Execute(ctx, f.op); err == nil {
		t.Fatal("unavailable policy authority accepted")
	}
	before := f.row(t)
	if before.Phase != "catalog_prepared" || before.ErrorCode != "policy_preparation_failed" || before.ReadCreated {
		t.Fatalf("wrong policy preparation failure: %+v", before)
	}
	children, err := operations.NewStore().ListByParent(ctx, f.pool, f.op.ID)
	if err != nil || len(children) != 3 {
		t.Fatalf("policy children reserved despite unavailable authority: %d %v", len(children), err)
	}
	f.dispatcher.policyDiscoveryBlocked = false
	f.dispatcher.extraUserSchema = true
	if err := f.executor.Execute(ctx, f.op); err != nil {
		t.Fatal(err)
	}
	after := f.row(t)
	if after.Phase != "complete" || string(after.Templates) != string(before.Templates) {
		t.Fatalf("retry changed frozen scope: before=%s after=%s phase=%s", before.Templates, after.Templates, after.Phase)
	}
	if got := strings.Join(f.dispatcher.mutations, ","); got != "database,read,read_write" {
		t.Fatalf("CREATE repeated: %s", got)
	}
	if f.dispatcher.discoveryCalls != 3 {
		t.Fatalf("policy discovery not refreshed: %d", f.dispatcher.discoveryCalls)
	}
}

func TestDatabaseWorkflowRejectsRecreatedDatabaseBeforeRoles(t *testing.T) {
	f := newDatabaseWorkflowFixture(t)
	f.dispatcher.wrongDiscoveryOID = true
	if err := f.executor.Execute(context.Background(), f.op); err == nil {
		t.Fatal("recreated database accepted")
	}
	if got := strings.Join(f.dispatcher.mutations, ","); got != "database" {
		t.Fatalf("roles on replaced database: %s", got)
	}
}

func TestDatabaseWorkflowReceiptSurvivesLostRootCommit(t *testing.T) {
	f := newDatabaseWorkflowFixture(t)
	var fault atomic.Bool
	fault.Store(true)
	f.executor.WithMutations(jobs.MutationDeps{BeforeDatabaseProvisioningOperationCommit: func(context.Context, operations.Operation) error {
		if fault.CompareAndSwap(true, false) {
			return errors.New("injected lost root commit")
		}
		return nil
	}})
	queue, err := jobs.New(f.pool, operations.NewStore(), f.executor, jobs.Config{Queue: testQueue(), WorkerCount: 1, MaxAttempts: 3, SnoozeOnLock: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := queue.EnqueueOperationTx(ctx, tx, f.op.ID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	startRiver(t, queue)
	waitForStatus(t, f.pool, operations.NewStore(), f.op.ID, operations.StatusSuccess, 60*time.Second)
	if fault.Load() {
		t.Fatal("root commit fault not exercised")
	}
	f.dispatcher.mu.Lock()
	got := strings.Join(f.dispatcher.mutations, ",")
	f.dispatcher.mu.Unlock()
	if got != "database,read,read_write" {
		t.Fatalf("receipt did not suppress target replay: %s", got)
	}
	var jobsCount int
	if err := f.pool.QueryRow(ctx, `select count(*) from river_job where args->>'operation_id' in (select id::text from operations where id=$1 or parent_id=$1)`, f.op.ID).Scan(&jobsCount); err != nil {
		t.Fatal(err)
	}
	if jobsCount != 1 {
		t.Fatalf("queued jobs=%d, expected only root", jobsCount)
	}
}

func TestDatabaseWorkflowReceiptDoesNotBlockConnectionDeletion(t *testing.T) {
	f := newDatabaseWorkflowFixture(t)
	ctx := context.Background()
	if err := f.executor.Execute(ctx, f.op); err != nil {
		t.Fatal(err)
	}
	if err := connections.NewStore().Delete(ctx, f.pool, f.conn.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := databaseprovisioning.NewStore().Get(ctx, f.pool, f.op.ID); !errors.Is(err, databaseprovisioning.ErrNotFound) {
		t.Fatalf("receipt survived deletion: %v", err)
	}
	if _, err := operations.NewStore().Get(ctx, f.pool, f.op.ID); err != nil {
		t.Fatalf("operation history lost: %v", err)
	}
}
