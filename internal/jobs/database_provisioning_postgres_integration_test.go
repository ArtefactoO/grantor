//go:build integration

package jobs_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/connector/conntest"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/connectorjobs"
	"github.com/ArtefactoO/grantor/internal/core/databaseprovisioning"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/rolepolicies"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

// This test crosses real root -> worker -> discovery -> catalog -> policy
// creation, both directly and through signed mTLS jobs + durable connector dedup.
// A legacy helper-shaped object is seeded only to prove that v2 ignores and
// never calls or drops it.
func TestDatabaseWorkflowPostgresEndToEnd(t *testing.T) {
	dsn := os.Getenv("GRANTOR_TEST_TARGET_PG_DSN")
	if dsn == "" {
		t.Skip("GRANTOR_TEST_TARGET_PG_DSN is not set")
	}
	cc, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	registerPostgresOnce.Do(func() { adapter.Register(postgres.Engine, func() adapter.Adapter { return postgres.New() }) })
	for _, tc := range []struct {
		mode, name         string
		failPolicyMetadata bool
	}{
		{mode: connections.ExecutionModeDirect, name: "direct"},
		{mode: connections.ExecutionModeConnector, name: "connector"},
		{mode: connections.ExecutionModeConnector, name: "connector_lost_policy_metadata_then_database_replaced", failPolicyMetadata: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mode := tc.mode
			ctx := t.Context()
			pool := pgtest.Pool(t)
			cluster, err := pgx.ConnectConfig(ctx, cc)
			if err != nil {
				t.Fatal(err)
			}
			defer cluster.Close(context.Background()) //nolint:errcheck
			suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
			template, owner, admin, name := "workflow_tpl_"+suffix, "workflow_owner_"+suffix, "workflow_admin_"+suffix, "workflow_db_"+suffix
			t.Cleanup(func() {
				cleanup, err := pgx.ConnectConfig(context.Background(), cc)
				if err != nil {
					t.Error(err)
					return
				}
				defer cleanup.Close(context.Background()) //nolint:errcheck
				for _, statement := range []string{
					"drop database if exists " + pgx.Identifier{name}.Sanitize() + " with (force)",
					"alter database " + pgx.Identifier{template}.Sanitize() + " is_template false",
					"drop database if exists " + pgx.Identifier{template}.Sanitize() + " with (force)",
					"drop role if exists " + pgx.Identifier{"r_" + name}.Sanitize(),
					"drop role if exists " + pgx.Identifier{"rw_" + name}.Sanitize(),
					"drop role if exists " + pgx.Identifier{admin}.Sanitize(),
					"drop role if exists " + pgx.Identifier{owner}.Sanitize(),
				} {
					if _, err := cleanup.Exec(context.Background(), statement); err != nil {
						t.Error(err)
					}
				}
			})
			for _, statement := range []string{
				"create role " + pgx.Identifier{owner}.Sanitize() + " nologin",
				"create role " + pgx.Identifier{admin}.Sanitize() + " login superuser password 'grantor'",
				"create database " + pgx.Identifier{template}.Sanitize() + " is_template true",
			} {
				if _, err := cluster.Exec(ctx, statement); err != nil {
					t.Fatal(err)
				}
			}
			// A loopback trust rule would hide credential-frame lifetime bugs:
			// prove this fixture actually rejects an incorrect admin password.
			authProbeConfig := cc.Copy()
			authProbeConfig.User, authProbeConfig.Password = admin, "invalid-workflow-auth-probe"
			if authProbe, err := pgx.ConnectConfig(ctx, authProbeConfig); err == nil {
				_ = authProbe.Close(ctx)
				t.Fatal("workflow E2E requires enforced password authentication; incorrect password was accepted")
			}
			preparedConfig := cc.Copy()
			preparedConfig.Database = template
			preparedConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
			prepared, err := pgx.ConnectConfig(ctx, preparedConfig)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := prepared.Exec(ctx, `create schema grantor;
				create function grantor.apply_role_policy_v1() returns void language plpgsql as $$
				begin raise exception 'legacy helper must never be called'; end $$`); err != nil {
				t.Fatal(err)
			}
			if err := prepared.Close(ctx); err != nil {
				t.Fatal(err)
			}

			config, _ := json.Marshal(map[string]any{"database": cc.Database, "database_create": map[string]any{"templates": []string{template}}})
			connStore, opStore, invStore := connections.NewStore(), operations.NewStore(), inventory.NewStore()
			conn, err := connStore.Create(ctx, pool, connections.CreateParams{DisplayName: "workflow-" + suffix, Engine: "postgres", Environment: "itest",
				Endpoints: []string{net.JoinHostPort(cc.Host, strconv.Itoa(int(cc.Port)))}, ExecutionMode: mode,
				TLSConfig: []byte(`{"mode":"disabled"}`), DiscoveryConfig: config, VaultAdminPath: testVaultPath})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, `update connections set status='discovering' where id=$1`, conn.ID); err != nil {
				t.Fatal(err)
			}
			executor := jobs.NewMainExecutor(jobs.DiscoveryDeps{Connections: connStore, Inventory: invStore, Audit: audit.NewWriter(), Pool: pool,
				Vault: fakeVaultReader{username: admin, password: "grantor"}})
			if mode == connections.ExecutionModeConnector {
				pair := conntest.GenTLS(t, "localhost", "connector-connp3")
				pub, priv, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				runtime := startConnp3Gateway(t, pair, connector.NewED25519Signer("gw", priv), connector.NewED25519Verifier("gw", pub), connectorjobs.NewStore(pool, 0), &connp3Hook{})
				runtime.startAgent()
				executor.WithConnector(jobs.ConnectorDeps{Dispatcher: runtime.srv})
			}
			discover, _, err := opStore.Create(ctx, pool, operations.CreateParams{Kind: jobs.KindConnectionDiscover, ConnectionID: &conn.ID, ActorType: "test", ActorID: t.Name()})
			if err != nil {
				t.Fatal(err)
			}
			if err := executor.Execute(ctx, discover); err != nil {
				t.Fatal(err)
			}
			conn, err = connStore.Get(ctx, pool, conn.ID)
			if err != nil {
				t.Fatal(err)
			}
			var ownerOID uint32
			if err := cluster.QueryRow(ctx, `select oid from pg_roles where rolname=$1`, owner).Scan(&ownerOID); err != nil {
				t.Fatal(err)
			}
			var topology map[string]any
			if err := json.Unmarshal(conn.Topology, &topology); err != nil {
				t.Fatal(err)
			}
			catalogFingerprint, _ := topology["postgres_role_policy_catalog_fingerprint"].(string)
			if catalogFingerprint == "" || ownerOID == 0 ||
				!slices.Contains(conn.Capabilities, string(adapter.CapPostgresSuperuserDirectV1)) {
				t.Fatalf("discovery did not confirm SUPERUSER direct authority: owner_oid=%d caps=%v topology=%v",
					ownerOID, conn.Capabilities, topology)
			}
			resource, err := invStore.CreatePlannedResource(ctx, pool, inventory.CreatePlannedResourceParams{ConnectionID: conn.ID, Kind: "database", ExternalID: "db:" + name, Name: name, CanonicalPath: name})
			if err != nil {
				t.Fatal(err)
			}
			payload, _ := json.Marshal(jobs.DatabaseCreateWithRolesPayload{ResourceID: resource.ID, Name: name,
				Options: map[string]any{"owner": owner, "template": template}, ExpectedTargetIdentity: connections.TargetIdentity(conn),
				ExpectedAdminIdentity: admin, ExpectedConfigIncarnation: connections.ConfigIncarnation(conn),
				ExpectedCredentialIncarnation: 1, ExpectedDatabaseOwner: owner, ExpectedDatabaseOwnerOID: ownerOID,
				ExpectedCatalogFingerprint: catalogFingerprint})
			queue, err := jobs.New(pool, opStore, executor, jobs.Config{Queue: testQueue(), WorkerCount: 1, MaxAttempts: 1})
			if err != nil {
				t.Fatal(err)
			}
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background()) //nolint:errcheck
			op, _, err := opStore.Create(ctx, tx, operations.CreateParams{Kind: jobs.KindPostgresDatabaseCreateWithRolesV2, ConnectionID: &conn.ID, ResourceID: &resource.ID, Payload: payload, ActorType: "test", ActorID: t.Name()})
			if err != nil {
				t.Fatal(err)
			}
			if err := databaseprovisioning.NewStore().Create(ctx, tx, op.ID, resource.ID, conn.ID); err != nil {
				t.Fatal(err)
			}
			var releaseMetadataFault func()
			rwChildID := uuid.NewSHA1(op.ID, []byte("database-with-roles:read_write"))
			if tc.failPolicyMetadata {
				releaseMetadataFault = rejectDatabaseWorkflowRoleCompletion(t, pool, rwChildID)
			}
			if err := queue.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			startRiver(t, queue)
			if tc.failPolicyMetadata {
				waitForStatus(t, pool, opStore, op.ID, operations.StatusFailed, 90*time.Second)
				waitForJobStates(t, pool, op.ID, []string{"discarded:1"}, 30*time.Second)
				row, err := databaseprovisioning.NewStore().Get(ctx, pool, op.ID)
				if err != nil || !row.DatabaseCreated || !row.ReadCreated || row.ReadWriteCreated {
					t.Fatalf("wrong partial receipt after metadata failure: %+v %v", row, err)
				}
				var cached, completed, targetRoles int
				if err := pool.QueryRow(ctx, `select count(*) from connector_job_dedup where job_id=$1`, rwChildID.String()).Scan(&cached); err != nil || cached != 1 {
					t.Fatalf("successful RW target response was not durably cached: count=%d err=%v", cached, err)
				}
				if err := cluster.QueryRow(ctx, `select count(*) from pg_roles where rolname=any($1)`, []string{"r_" + name, "rw_" + name}).Scan(&targetRoles); err != nil || targetRoles != 2 {
					t.Fatalf("target success fault boundary missing: roles=%d err=%v", targetRoles, err)
				}
				releaseMetadataFault()
				// This DBA-side replacement is the race under test. Grantor must
				// never publish the old cached verification on this new database.
				if _, err := cluster.Exec(ctx, "drop database "+pgx.Identifier{name}.Sanitize()+" with (force)"); err != nil {
					t.Fatal(err)
				}
				if _, err := cluster.Exec(ctx, "create database "+pgx.Identifier{name}.Sanitize()+" owner "+pgx.Identifier{owner}.Sanitize()+" template "+pgx.Identifier{template}.Sanitize()); err != nil {
					t.Fatal(err)
				}
				var replacementOID uint32
				if err := cluster.QueryRow(ctx, `select oid from pg_database where datname=$1`, name).Scan(&replacementOID); err != nil || replacementOID == row.DatabaseOID {
					t.Fatalf("replacement did not change OID: old=%d new=%d err=%v", row.DatabaseOID, replacementOID, err)
				}
				retryTx, err := pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer retryTx.Rollback(context.Background()) //nolint:errcheck
				if _, err := opStore.Transition(ctx, retryTx, op.ID, operations.StatusFailed, operations.StatusPending, operations.TransitionOpts{}); err != nil {
					t.Fatal(err)
				}
				if err := queue.EnqueueOperationTx(ctx, retryTx, op.ID); err != nil {
					t.Fatal(err)
				}
				if err := retryTx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				failed := waitForStatus(t, pool, opStore, op.ID, operations.StatusFailed, 90*time.Second)
				if !strings.Contains(failed.Error, "identity") {
					t.Fatalf("retry did not reject changed database identity: %s", failed.Error)
				}
				row, err = databaseprovisioning.NewStore().Get(ctx, pool, op.ID)
				if err != nil || row.ReadWriteCreated || row.Phase == "complete" {
					t.Fatalf("cached target success published after DB replacement: %+v %v", row, err)
				}
				if err := pool.QueryRow(ctx, `select count(*) from role_policy_operation_completions where operation_id=$1`, rwChildID).Scan(&completed); err != nil || completed != 0 {
					t.Fatalf("unexpected completion receipt: count=%d err=%v", completed, err)
				}
				policy, err := rolepolicies.NewStore().GetByKey(ctx, pool, conn.ID, row.ReadWritePolicyKey)
				if err != nil || policy.Status == rolepolicies.StatusSynced || policy.Exact {
					t.Fatalf("RW was falsely published synced: %+v %v", policy, err)
				}
				return
			}
			waitForStatus(t, pool, opStore, op.ID, operations.StatusSuccess, 90*time.Second)
			row, err := databaseprovisioning.NewStore().Get(ctx, pool, op.ID)
			if err != nil || row.Phase != "complete" || row.DatabaseOID == 0 {
				t.Fatalf("receipt=%+v err=%v", row, err)
			}
			// A fresh operation avoids connector cached discovery; exactness must
			// be re-observed, not inferred from the earlier completion receipts.
			discover, _, err = opStore.Create(ctx, pool, operations.CreateParams{Kind: jobs.KindConnectionDiscover, ConnectionID: &conn.ID, ActorType: "test", ActorID: t.Name()})
			if err != nil {
				t.Fatal(err)
			}
			if err := executor.Execute(ctx, discover); err != nil {
				t.Fatal(err)
			}
			policies, err := rolepolicies.NewStore().List(ctx, pool, conn.ID)
			if err != nil {
				t.Fatal(err)
			}
			if len(policies) != 2 {
				t.Fatalf("policies=%d", len(policies))
			}
			for _, policy := range policies {
				if !policy.Managed || !policy.Exact || policy.Status != rolepolicies.StatusSynced || len(policy.DesiredSpec.OwnerRoles) != 1 || policy.DesiredSpec.OwnerRoles[0] != owner {
					t.Fatalf("policy not synced: %+v", policy)
				}
			}
			createdConfig := cc.Copy()
			createdConfig.Database = name
			created, err := pgx.ConnectConfig(ctx, createdConfig)
			if err != nil {
				t.Fatal(err)
			}
			var legacyObject int
			if err := created.QueryRow(ctx, `select count(*) from pg_proc p join pg_namespace n on n.oid=p.pronamespace
				where n.nspname='grantor' and p.proname='apply_role_policy_v1'`).Scan(&legacyObject); err != nil {
				t.Fatal(err)
			}
			_ = created.Close(ctx)
			if legacyObject != 1 {
				t.Fatalf("legacy helper-shaped object was called or dropped: count=%d", legacyObject)
			}
			var memberCount int
			if err := cluster.QueryRow(ctx, `select count(*) from pg_auth_members m join pg_roles r on r.oid=m.roleid join pg_roles u on u.oid=m.member
				where r.rolname=any($1) and u.rolname<>$2`, []string{"r_" + name, "rw_" + name}, admin).Scan(&memberCount); err != nil || memberCount != 0 {
				t.Fatalf("automatic user memberships=%d err=%v", memberCount, err)
			}
		})
	}
}

// A scoped PostgreSQL trigger injects the actual metadata transaction failure,
// after target Apply/Verify and gateway durable dedup have already succeeded.
func rejectDatabaseWorkflowRoleCompletion(t *testing.T, pool *pgxpool.Pool, childID uuid.UUID) func() {
	t.Helper()
	name := "workflow_metadata_fault_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	identifier := pgx.Identifier{name}.Sanitize()
	ctx := context.Background()
	function := fmt.Sprintf(`create function %s() returns trigger language plpgsql as $$
		begin if new.operation_id='%s'::uuid then raise exception 'injected database workflow metadata failure'; end if;
		return new; end $$`, identifier, childID.String())
	if _, err := pool.Exec(ctx, function); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "create trigger "+identifier+" before insert on role_policy_operation_completions for each row execute function "+identifier+"()"); err != nil {
		t.Fatal(err)
	}
	release := func() {
		if _, err := pool.Exec(ctx, "drop trigger if exists "+identifier+" on role_policy_operation_completions"); err != nil {
			t.Error(err)
		}
		if _, err := pool.Exec(ctx, "drop function if exists "+identifier+"()"); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(release)
	return release
}
