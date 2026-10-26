package agent_test

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/fake"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/connector/agent"
	"github.com/ArtefactoO/grantor/internal/connector/gateway"
)

type roleCreateCalls struct {
	plan   atomic.Int64
	apply  atomic.Int64
	verify atomic.Int64
	rotate atomic.Int64
}

type roleCreateAdapter struct {
	adapter.Adapter
	calls     *roleCreateCalls
	supported bool
}

func (a roleCreateAdapter) Manifest() adapter.Manifest {
	m := a.Adapter.Manifest()
	if !a.supported {
		capabilities := make([]adapter.Capability, 0, len(m.Capabilities))
		for _, capability := range m.Capabilities {
			if capability != adapter.CapRoleCreate {
				capabilities = append(capabilities, capability)
			}
		}
		m.Capabilities = capabilities
	}
	return m
}

func (a roleCreateAdapter) Plan(ctx context.Context, change adapter.DesiredChange) (*adapter.Plan, error) {
	a.calls.plan.Add(1)
	return a.Adapter.Plan(ctx, change)
}

func (a roleCreateAdapter) Apply(ctx context.Context, plan adapter.Plan) (*adapter.Result, error) {
	a.calls.apply.Add(1)
	return a.Adapter.Apply(ctx, plan)
}

func (a roleCreateAdapter) Verify(ctx context.Context, plan adapter.Plan) (*adapter.Verification, error) {
	a.calls.verify.Add(1)
	return a.Adapter.Verify(ctx, plan)
}

func (a roleCreateAdapter) RotateCredential(ctx context.Context, cfg adapter.Connection,
	account adapter.Account, credential adapter.Credential) error {
	a.calls.rotate.Add(1)
	return a.Adapter.RotateCredential(ctx, cfg, account, credential)
}

func TestRoleCreateRoundTrip(t *testing.T) {
	for _, pair := range pairs(t) {
		t.Run(pair.name, func(t *testing.T) {
			shared := fake.New()
			calls := &roleCreateCalls{}
			rt := newRuntimeWith(t, pair, gateway.Config{}, agent.Config{}, func(string) (adapter.Adapter, error) {
				return roleCreateAdapter{Adapter: shared, calls: calls, supported: true}, nil
			}, runtime{fake: shared})
			change := connector.ChangeRef{
				Kind:    string(adapter.ChangeRoleCreate),
				Account: connector.AccountRef{Kind: "group", EngineIdentity: "rw_database"},
			}
			planJob := mutationJob(t, "role-plan", "role-plan", change)
			planJob.Kind = connector.JobPlan
			planned, err := rt.srv.Dispatch(context.Background(), planJob, adminCreds())
			if err != nil || planned.Status != connector.JobSuccess {
				t.Fatalf("plan role.create = status:%q error:%q dispatch:%v", planned.Status, planned.Error, err)
			}
			if calls.plan.Load() != 1 || calls.apply.Load() != 0 || calls.verify.Load() != 0 {
				t.Fatal("plan-only role.create reached a mutating adapter method")
			}
			roleCreateObserved(t, shared, change.Account.EngineIdentity, false)

			job := mutationJob(t, "role-apply", "role-apply", change)
			applied, err := rt.srv.Dispatch(context.Background(), job, adminCreds())
			if err != nil || applied.Status != connector.JobSuccess {
				t.Fatalf("apply role.create = status:%q error:%q dispatch:%v", applied.Status, applied.Error, err)
			}
			parsed, err := connector.ParseSanitizedResult(applied.Result)
			if err != nil || parsed.Verification == nil || !parsed.Verification.Verified {
				t.Fatalf("role.create verification = %+v, error:%v", parsed.Verification, err)
			}
			if calls.plan.Load() != 2 || calls.apply.Load() != 1 || calls.verify.Load() != 1 || calls.rotate.Load() != 0 {
				t.Fatal("role.create must execute Plan/Apply/Verify once without rotating credentials")
			}
			roleCreateObserved(t, shared, change.Account.EngineIdentity, true)

			duplicate, err := rt.srv.Dispatch(context.Background(), job, adminCreds())
			if err != nil || duplicate.Status != connector.JobSuccess {
				t.Fatalf("dedup role.create = status:%q error:%q dispatch:%v", duplicate.Status, duplicate.Error, err)
			}
			if calls.plan.Load() != 2 || calls.apply.Load() != 1 || calls.verify.Load() != 1 {
				t.Fatal("successful role.create redelivery executed the adapter twice")
			}

			conflict, err := rt.srv.Dispatch(context.Background(),
				mutationJob(t, "role-conflict", "role-conflict", change), adminCreds())
			if err != nil || conflict.Status != connector.JobFailed || !strings.Contains(conflict.Error, "already exists") {
				t.Fatalf("existing role = status:%q error:%q dispatch:%v", conflict.Status, conflict.Error, err)
			}
			if calls.apply.Load() != 1 || calls.verify.Load() != 1 || calls.rotate.Load() != 0 {
				t.Fatal("role.create touched an already existing role")
			}
		})
	}
}

func TestRoleCreateRejectsUnsupportedCapabilityAndCredentialsBeforePlan(t *testing.T) {
	for _, tc := range []struct {
		name      string
		supported bool
		account   bool
		version   int
	}{
		{name: "capability missing"},
		{name: "account credential", supported: true, account: true},
		{name: "account credential version", supported: true, version: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shared := fake.New()
			calls := &roleCreateCalls{}
			rt := newRuntimeWith(t, pairs(t)[0], gateway.Config{}, agent.Config{}, func(string) (adapter.Adapter, error) {
				return roleCreateAdapter{Adapter: shared, calls: calls, supported: tc.supported}, nil
			}, runtime{fake: shared})
			creds := adminCreds()
			defer creds.Zero()
			if tc.account {
				creds.Account = &adapter.Credential{Kind: "password", Username: "rw_database", Secret: []byte("unexpected-role-secret")}
			}
			creds.AccountVaultVersion = tc.version
			job := mutationJob(t, "invalid-role", "invalid-role", connector.ChangeRef{
				Kind:    string(adapter.ChangeRoleCreate),
				Account: connector.AccountRef{Kind: "group", EngineIdentity: "rw_database"},
			})
			res, err := rt.srv.Dispatch(context.Background(), job, creds)
			if err != nil || res.Status != connector.JobFailed {
				t.Fatalf("invalid role.create = status:%q error:%q dispatch:%v", res.Status, res.Error, err)
			}
			if calls.plan.Load() != 0 || calls.apply.Load() != 0 || calls.verify.Load() != 0 || calls.rotate.Load() != 0 {
				t.Fatal("invalid role.create reached the adapter before validation")
			}
			roleCreateObserved(t, shared, "rw_database", false)
		})
	}
}

func roleCreateObserved(t *testing.T, target *fake.Fake, identity string, want bool) {
	t.Helper()
	snapshot, err := target.Discover(context.Background(), adapter.Connection{})
	if err != nil {
		t.Fatalf("discover role.create result: %v", err)
	}
	accountFound, permissionFound := false, false
	for _, account := range snapshot.Accounts {
		if account.EngineIdentity == identity {
			accountFound = account.Kind == "group"
		}
	}
	for _, permission := range snapshot.Permissions {
		if permission.ExternalID == "role:"+identity {
			permissionFound = permission.Assignable
		}
	}
	if accountFound != want || permissionFound != want {
		t.Fatalf("role.create account/permission observed = %v/%v, want %v", accountFound, permissionFound, want)
	}
}
