package agent_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/fake"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/connector/agent"
	"github.com/ArtefactoO/grantor/internal/connector/gateway"
)

type databaseLifecycleAdapter struct {
	adapter.Adapter
	supported, authority               bool
	seen                               chan adapter.DesiredChange
	planCalls, applyCalls, verifyCalls atomic.Int64
}

func (a *databaseLifecycleAdapter) Manifest() adapter.Manifest {
	m := a.Adapter.Manifest()
	m.Capabilities = nil
	if a.supported {
		m.Capabilities = []adapter.Capability{adapter.ResourceCapability("create", "database"), adapter.CapRolePolicyCreate}
	}
	if a.authority {
		m.Capabilities = append(m.Capabilities, adapter.CapPostgresSuperuserDirectV1)
	}
	return m
}

func (a *databaseLifecycleAdapter) Plan(_ context.Context, c adapter.DesiredChange) (*adapter.Plan, error) {
	a.planCalls.Add(1)
	a.seen <- c
	return &adapter.Plan{Change: c, Steps: []adapter.PlanStep{{Kind: "database-lifecycle"}}}, nil
}

func (a *databaseLifecycleAdapter) Apply(_ context.Context, p adapter.Plan) (*adapter.Result, error) {
	a.applyCalls.Add(1)
	return &adapter.Result{Steps: []adapter.StepResult{{Step: p.Steps[0], Status: adapter.StepApplied}}}, nil
}

func (a *databaseLifecycleAdapter) Verify(_ context.Context, p adapter.Plan) (*adapter.Verification, error) {
	a.verifyCalls.Add(1)
	v := &adapter.Verification{Verified: true}
	if p.Change.Kind == adapter.ChangePostgresDatabaseCreateV2 {
		v.Observed = map[string]any{"database_name": p.Change.Resource.Name, "database_owner": "orders_owner",
			"database_owner_oid": uint32(17001), "database_oid": uint32(456), "target_identity": p.Change.ExpectedTargetIdentity}
	}
	return v, nil
}

func databaseMutationJob(t *testing.T, id string, change connector.ChangeRef) connector.Job {
	t.Helper()
	kind := adapter.ChangeKind(change.Kind)
	if adapter.IsPostgresSuperuserDirectChange(kind) {
		if change.ExpectedAdminIdentity == "" {
			change.ExpectedAdminIdentity = "grantor_admin"
		}
		switch kind {
		case adapter.ChangePostgresDatabaseCreateV2:
			if change.Resource != nil {
				if change.Resource.Attributes == nil {
					change.Resource.Attributes = map[string]any{}
				}
				owner, _ := change.Resource.Attributes["owner"].(string)
				if owner == "" {
					owner = "orders_owner"
					change.Resource.Attributes["owner"] = owner
				}
				change.ExpectedDatabaseOwner = owner
				change.ExpectedDatabaseOwnerOID = 17001
			}
		case adapter.ChangePostgresRolePolicyApplyV2,
			adapter.ChangePostgresRolePolicyVerifyV2,
			adapter.ChangePostgresRolePolicyAdoptV2,
			adapter.ChangePostgresRolePolicyRepairV2,
			adapter.ChangePostgresRolePolicyCreateV2,
			adapter.ChangePostgresRolePolicyCreateDatabaseV2:
			change.ExpectedDatabaseOwner = "orders_owner"
			change.ExpectedDatabaseOwnerOID = 17001
			change.ExpectedCatalogFingerprint = strings.Repeat("b", 64)
		}
	}
	job := mutationJob(t, id, id, change)
	payload, err := (connector.MutationPayload{Connection: connector.ConnectionRef{
		ID: job.ConnectionID, Engine: "postgres", Endpoints: []string{"postgres:5432"},
		ConfigIncarnation: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}, Change: change}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	job.Engine = "postgres"
	job.Payload = payload
	return job
}

func TestPostgresV2ConnectorRequiresConfiguredAuthorityCapabilityBeforePlan(t *testing.T) {
	for _, kind := range []adapter.ChangeKind{
		adapter.ChangePostgresAccountCreateV2, adapter.ChangePostgresAccountRestoreV2,
		adapter.ChangePostgresRoleCreateV2, adapter.ChangePostgresDatabaseCreateV2,
		adapter.ChangePostgresRolePolicyApplyV2, adapter.ChangePostgresRolePolicyVerifyV2,
		adapter.ChangePostgresRolePolicyAdoptV2, adapter.ChangePostgresRolePolicyRepairV2,
		adapter.ChangePostgresRolePolicyCreateV2, adapter.ChangePostgresRolePolicyCreateDatabaseV2,
	} {
		t.Run(string(kind), func(t *testing.T) {
			shared := fake.New()
			ad := &databaseLifecycleAdapter{Adapter: shared, supported: true, seen: make(chan adapter.DesiredChange, 1)}
			rt := newRuntimeWith(t, pairs(t)[0], gateway.Config{}, agent.Config{},
				func(string) (adapter.Adapter, error) { return ad, nil }, runtime{fake: shared})
			change := connector.ChangeRef{Kind: string(kind), ExpectedTargetIdentity: "postgres:system:123"}
			switch kind {
			case adapter.ChangePostgresAccountCreateV2, adapter.ChangePostgresAccountRestoreV2:
				change.Account = connector.AccountRef{Kind: "login", EngineIdentity: "service"}
			case adapter.ChangePostgresRoleCreateV2:
				change.Account = connector.AccountRef{Kind: "group", EngineIdentity: "r_orders"}
			case adapter.ChangePostgresDatabaseCreateV2:
				change.Resource = &adapter.ResourceSpec{Kind: "database", Name: "orders"}
			default:
				change.RolePolicySpec = &adapter.RolePolicySpec{Engine: "postgres", Key: "orders-read", Name: "Orders read",
					RoleName: "r_orders", Database: "orders", Schemas: []string{"public"},
					OwnerRoles: []string{"orders_owner"}, CreatorRoles: []string{"orders_owner"}, Profile: "read"}
				change.ExpectedDatabaseOID = 456
				if kind != adapter.ChangePostgresRolePolicyCreateDatabaseV2 {
					change.Permission = "role:r_orders"
				}
			}
			job := databaseMutationJob(t, "postgres-v2-no-authority-"+string(kind), change)
			creds := adminCreds()
			creds.AdminCredentialIncarnation = 7
			res, err := rt.srv.Dispatch(t.Context(), job, creds)
			if !errors.Is(err, gateway.ErrCapabilityUnavailable) || res.Status != "" ||
				ad.planCalls.Load() != 0 || ad.applyCalls.Load() != 0 || ad.verifyCalls.Load() != 0 {
				t.Fatalf("v2 request crossed authority capability fence: %+v err=%v", res, err)
			}
		})
	}
}

func TestMutationIdentityMismatchFailsBeforeAdapterResolution(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*connector.Job)
	}{
		{
			name: "connection",
			mutate: func(job *connector.Job) {
				job.ConnectionID = "other-connection"
			},
		},
		{
			name: "engine",
			mutate: func(job *connector.Job) {
				job.Engine = "mongodb"
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shared := fake.New()
			ad := &databaseLifecycleAdapter{
				Adapter: shared, supported: true, authority: true,
				seen: make(chan adapter.DesiredChange, 1),
			}
			var adapterResolutions atomic.Int64
			rt := newRuntimeWith(t, pairs(t)[0], gateway.Config{}, agent.Config{
				Capabilities: []adapter.Capability{adapter.CapPostgresSuperuserDirectV1},
			},
				func(string) (adapter.Adapter, error) {
					adapterResolutions.Add(1)
					return ad, nil
				}, runtime{fake: shared})
			job := databaseMutationJob(t, "postgres-v2-identity-mismatch", connector.ChangeRef{
				Kind:                   string(adapter.ChangePostgresDatabaseCreateV2),
				ExpectedTargetIdentity: "postgres:system:123",
				Resource:               &adapter.ResourceSpec{Kind: "database", Name: "orders"},
			})
			tc.mutate(&job)
			creds := adminCreds()
			defer creds.Zero()
			res, err := rt.srv.Dispatch(t.Context(), job, creds)
			if err != nil || res.Status != connector.JobFailed || !strings.Contains(res.Error, "does not match") {
				t.Fatalf("identity mismatch result=%+v err=%v", res, err)
			}
			if adapterResolutions.Load() != 0 || ad.planCalls.Load() != 0 ||
				ad.applyCalls.Load() != 0 || ad.verifyCalls.Load() != 0 {
				t.Fatalf("identity mismatch crossed target boundary: resolutions=%d plan=%d apply=%d verify=%d",
					adapterResolutions.Load(), ad.planCalls.Load(), ad.applyCalls.Load(), ad.verifyCalls.Load())
			}
		})
	}
}

func TestLegacyPostgresCreationKindsFailBeforeAdapter(t *testing.T) {
	for _, kind := range []adapter.ChangeKind{
		adapter.ChangeAccountCreate, adapter.ChangeAccountRestore,
		adapter.ChangeRoleCreate, adapter.ChangeResourceCreate,
		adapter.ChangeRolePolicyApply, adapter.ChangeRolePolicyVerify,
		adapter.ChangeRolePolicyCreate, adapter.ChangeRolePolicyCreateDatabase,
	} {
		t.Run(string(kind), func(t *testing.T) {
			shared := fake.New()
			ad := &databaseLifecycleAdapter{Adapter: shared, supported: true, authority: true, seen: make(chan adapter.DesiredChange, 1)}
			rt := newRuntimeWith(t, pairs(t)[0], gateway.Config{}, agent.Config{},
				func(string) (adapter.Adapter, error) { return ad, nil }, runtime{fake: shared})
			change := connector.ChangeRef{Kind: string(kind)}
			switch kind {
			case adapter.ChangeAccountCreate, adapter.ChangeAccountRestore:
				change.Account = connector.AccountRef{Kind: "login", EngineIdentity: "service_app"}
			case adapter.ChangeRoleCreate:
				change.Account = connector.AccountRef{Kind: "group", EngineIdentity: "r_app"}
			case adapter.ChangeResourceCreate:
				change.Resource = &adapter.ResourceSpec{Kind: "database", Name: "app"}
			case adapter.ChangeRolePolicyApply, adapter.ChangeRolePolicyVerify, adapter.ChangeRolePolicyCreate:
				change.Permission = "role:r_app"
				fallthrough
			case adapter.ChangeRolePolicyCreateDatabase:
				change.RolePolicySpec = &adapter.RolePolicySpec{Engine: "postgres", RoleName: "r_app", Database: "app"}
				change.ExpectedTargetIdentity = "postgres:system:123"
				if kind == adapter.ChangeRolePolicyCreateDatabase {
					change.ExpectedDatabaseOID = 456
				}
			}
			job := databaseMutationJob(t, "legacy-postgres", change)
			if kind == adapter.ChangeRolePolicyVerify {
				job.Kind = connector.JobVerify
			}
			res, err := rt.srv.Dispatch(t.Context(), job, adminCreds())
			if err != nil || res.Status != connector.JobFailed ||
				!strings.Contains(res.Error, "history-only") || ad.planCalls.Load() != 0 {
				t.Fatalf("legacy PostgreSQL kind reached adapter: %+v err=%v", res, err)
			}
		})
	}
}

func TestDatabaseLifecycleConnectorRoundTrip(t *testing.T) {
	for _, kind := range []adapter.ChangeKind{adapter.ChangePostgresDatabaseCreateV2, adapter.ChangePostgresRolePolicyCreateDatabaseV2} {
		t.Run(string(kind), func(t *testing.T) {
			shared := fake.New()
			ad := &databaseLifecycleAdapter{Adapter: shared, supported: true, authority: true, seen: make(chan adapter.DesiredChange, 5)}
			rt := newRuntimeWith(t, pairs(t)[0], gateway.Config{}, agent.Config{
				Capabilities: []adapter.Capability{adapter.CapPostgresSuperuserDirectV1},
			}, func(string) (adapter.Adapter, error) { return ad, nil }, runtime{fake: shared})
			change := connector.ChangeRef{Kind: string(kind), ExpectedTargetIdentity: "postgres:system:123"}
			if kind == adapter.ChangePostgresDatabaseCreateV2 {
				change.Resource = &adapter.ResourceSpec{Kind: "database", Name: "orders", Attributes: map[string]any{"owner": "orders_owner"}}
			} else {
				change.RolePolicySpec = &adapter.RolePolicySpec{Engine: "postgres", Database: "orders", RoleName: "r_orders"}
				change.ExpectedDatabaseOID = 456
			}
			planJob := databaseMutationJob(t, "db-plan", change)
			planJob.Kind = connector.JobPlan
			planned, err := rt.srv.Dispatch(t.Context(), planJob, adminCreds())
			if err != nil || planned.Status != connector.JobSuccess || ad.applyCalls.Load() != 0 {
				t.Fatalf("plan-only database request=%+v err=%v", planned, err)
			}
			job := databaseMutationJob(t, "db-apply", change)
			res, err := rt.srv.Dispatch(t.Context(), job, adminCreds())
			if err != nil || res.Status != connector.JobSuccess {
				t.Fatalf("database request=%+v err=%v", res, err)
			}
			for i := 0; i < 2; i++ {
				got := <-ad.seen
				if got.Kind != kind || got.ExpectedTargetIdentity != change.ExpectedTargetIdentity || got.ExpectedDatabaseOID != change.ExpectedDatabaseOID {
					t.Fatalf("dropped lifecycle identity: %+v", got)
				}
				if kind == adapter.ChangePostgresDatabaseCreateV2 && (got.Resource == nil || got.Resource.Attributes["owner"] != "orders_owner") {
					t.Fatalf("dropped resource contract: %+v", got)
				}
			}
			parsed, err := connector.ParseSanitizedResult(res.Result)
			if err != nil || parsed.Verification == nil || !parsed.Verification.Verified {
				t.Fatalf("verification=%+v err=%v", parsed, err)
			}
			if kind == adapter.ChangePostgresDatabaseCreateV2 && parsed.Verification.Observed["database_oid"] != uint32(456) {
				t.Fatalf("creation proof lost: %+v", parsed.Verification)
			}
			duplicate, err := rt.srv.Dispatch(t.Context(), job, adminCreds())
			if err != nil || duplicate.Status != connector.JobSuccess || ad.planCalls.Load() != 2 || ad.applyCalls.Load() != 1 || ad.verifyCalls.Load() != 1 {
				t.Fatalf("dedup repeated target mutation: %+v err=%v", duplicate, err)
			}
		})
	}
}

func TestDatabaseLifecycleConnectorRejectsBeforePlan(t *testing.T) {
	for _, kind := range []adapter.ChangeKind{adapter.ChangePostgresDatabaseCreateV2, adapter.ChangePostgresRolePolicyCreateDatabaseV2} {
		for _, mode := range []string{"missing_capability", "account_credential", "account_version", "job_engine", "unknown_kind"} {
			t.Run(fmt.Sprintf("%s/%s", kind, mode), func(t *testing.T) {
				shared := fake.New()
				ad := &databaseLifecycleAdapter{Adapter: shared, supported: mode != "missing_capability", authority: mode != "missing_capability", seen: make(chan adapter.DesiredChange, 5)}
				rt := newRuntimeWith(t, pairs(t)[0], gateway.Config{}, agent.Config{
					Capabilities: []adapter.Capability{adapter.CapPostgresSuperuserDirectV1},
				}, func(string) (adapter.Adapter, error) { return ad, nil }, runtime{fake: shared})
				change := connector.ChangeRef{Kind: string(kind), ExpectedTargetIdentity: "postgres:system:123"}
				if kind == adapter.ChangePostgresDatabaseCreateV2 {
					change.Resource = &adapter.ResourceSpec{Kind: "database", Name: "orders"}
				} else {
					change.RolePolicySpec = &adapter.RolePolicySpec{Engine: "postgres"}
					change.ExpectedDatabaseOID = 456
				}
				if mode == "unknown_kind" {
					change.Kind = "postgres.role.policy.create_database.v3"
				}
				job := databaseMutationJob(t, "bad-db", change)
				if mode == "job_engine" {
					job.Engine = "mongodb"
				}
				creds := adminCreds()
				defer creds.Zero()
				if mode == "account_credential" {
					creds.Account = &adapter.Credential{Kind: "password", Secret: []byte("unexpected")}
				}
				if mode == "account_version" {
					creds.AccountVaultVersion = 1
				}
				res, err := rt.srv.Dispatch(t.Context(), job, creds)
				if mode == "unknown_kind" {
					if err == nil || res.Status != "" || ad.planCalls.Load() != 0 || ad.applyCalls.Load() != 0 || ad.verifyCalls.Load() != 0 {
						t.Fatalf("unknown kind crossed gateway allowlist: %+v err=%v", res, err)
					}
					return
				}
				if err != nil || res.Status != connector.JobFailed || ad.planCalls.Load() != 0 || ad.applyCalls.Load() != 0 || ad.verifyCalls.Load() != 0 {
					t.Fatalf("unsafe database request reached target: %+v err=%v", res, err)
				}
			})
		}
	}
}
