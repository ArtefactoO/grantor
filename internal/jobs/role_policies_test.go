package jobs

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/rolepolicies"
)

func testRolePolicySpec() adapter.RolePolicySpec {
	return adapter.RolePolicySpec{
		Engine: "postgres", Key: "app-read", Name: "Application read",
		Description: "Read app", RoleName: "r_app", Database: "app",
		Schemas: []string{"public"}, OwnerRoles: []string{"app_owner"},
		CreatorRoles: []string{"app_migrator"}, Profile: "read",
	}
}

func TestDecodeRolePolicyPayloadPinsFullIntent(t *testing.T) {
	want := RolePolicyPayload{
		RolePolicyID: uuid.New(), Action: rolepolicies.ActionRepair,
		ExpectedVersion: 7, ObservedFingerprint: "actual-fp",
		ExpectedFingerprint:    "expected-fp",
		ExpectedTargetIdentity: "postgres:system:7429012345678901234",
		ExternalID:             "role:r_app",
		Spec:                   testRolePolicySpec(),
	}
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeRolePolicyPayload(raw)
	if err != nil {
		t.Fatalf("decodeRolePolicyPayload: %v", err)
	}
	if got.RolePolicyID != want.RolePolicyID || got.ExpectedVersion != want.ExpectedVersion ||
		got.Spec.RoleName != want.Spec.RoleName || got.Spec.CreatorRoles[0] != "app_migrator" {
		t.Fatalf("decoded payload = %+v", got)
	}
	for _, invalid := range [][]byte{
		[]byte(`{}`),
		[]byte(`{"role_policy_id":"` + uuid.NewString() + `","action":"drop","expected_version":1,"observed_fingerprint":"a","expected_fingerprint":"b","external_id":"role:r"}`),
	} {
		if _, err := decodeRolePolicyPayload(invalid); err == nil {
			t.Fatalf("invalid payload accepted: %s", invalid)
		}
	}
}

type verifyOnlyAdapter struct {
	adapter.Adapter
	applyCalls int
}

func (a *verifyOnlyAdapter) Plan(_ context.Context, change adapter.DesiredChange) (*adapter.Plan, error) {
	return &adapter.Plan{Change: change, Steps: []adapter.PlanStep{{
		Kind: "role.policy.verify", Description: "Verify fixed role policy",
	}}}, nil
}

func (a *verifyOnlyAdapter) Apply(_ context.Context, _ adapter.Plan) (*adapter.Result, error) {
	a.applyCalls++
	return &adapter.Result{}, nil
}

func (a *verifyOnlyAdapter) Verify(_ context.Context, _ adapter.Plan) (*adapter.Verification, error) {
	return &adapter.Verification{Verified: true}, nil
}

func TestAdoptDirectPathNeverCallsApply(t *testing.T) {
	ad := &verifyOnlyAdapter{}
	executor := NewMainExecutor(DiscoveryDeps{})
	spec := testRolePolicySpec()
	verification, err := executor.planVerifyRolePolicy(t.Context(), uuid.New(), ad, adapter.DesiredChange{
		Kind: adapter.ChangeRolePolicyVerify, Permission: "role:r_app", RolePolicySpec: &spec,
		ExpectedTargetIdentity: "postgres:system:7429012345678901234",
	})
	if err != nil || verification == nil || !verification.Verified {
		t.Fatalf("planVerifyRolePolicy = %+v, %v", verification, err)
	}
	if ad.applyCalls != 0 {
		t.Fatalf("adopt called Apply %d times", ad.applyCalls)
	}
}

func TestConnectorRolePolicyAdoptUsesJobVerify(t *testing.T) {
	spec := testRolePolicySpec()
	op := operations.Operation{ID: uuid.New(), Kind: KindRolePolicyAdopt}
	conn := connections.Connection{
		ID: uuid.New(), Engine: "postgres", ExecutionMode: connections.ExecutionModeConnector,
	}
	cfg := adapter.Connection{ID: conn.ID.String(), Engine: "postgres"}
	job, err := connectorMutationJobOfKind(op, conn, cfg, connector.ChangeRef{
		Kind: string(adapter.ChangeRolePolicyVerify), Permission: "role:r_app",
		RolePolicySpec:         &spec,
		ExpectedTargetIdentity: "postgres:system:7429012345678901234",
	}, connector.JobVerify, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("connectorMutationJobOfKind: %v", err)
	}
	if job.Kind != connector.JobVerify {
		t.Fatalf("job kind = %q, want %q", job.Kind, connector.JobVerify)
	}
	payload, err := connector.ParseMutationPayload(job.Payload)
	if err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	if payload.Change.RolePolicySpec == nil || payload.Change.RolePolicySpec.RoleName != "r_app" {
		t.Fatalf("payload role policy = %+v", payload.Change.RolePolicySpec)
	}
	if payload.Change.ExpectedTargetIdentity != "postgres:system:7429012345678901234" {
		t.Fatalf("payload target identity = %q", payload.Change.ExpectedTargetIdentity)
	}
}

func TestConnectorRolePolicyCreateKeepsClosedChangeKind(t *testing.T) {
	spec := testRolePolicySpec()
	op := operations.Operation{ID: uuid.New(), Kind: KindRolePolicyCreate}
	conn := connections.Connection{
		ID: uuid.New(), Engine: "postgres", ExecutionMode: connections.ExecutionModeConnector,
	}
	job, err := connectorMutationJobOfKind(op, conn, adapter.Connection{Engine: "postgres"}, connector.ChangeRef{
		Kind: string(adapter.ChangeRolePolicyCreate), Permission: "role:r_app", RolePolicySpec: &spec,
		ExpectedTargetIdentity: "postgres:system:7429012345678901234",
	}, connector.JobApply, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := connector.ParseMutationPayload(job.Payload)
	if err != nil || payload.Change.Kind != string(adapter.ChangeRolePolicyCreate) {
		t.Fatalf("create-only changed into an ordinary Apply: %+v, %v", payload.Change, err)
	}
	if rolePolicyActionForKind(KindRolePolicyCreate) != rolepolicies.ActionCreate ||
		rolePolicySuccessAuditAction(rolepolicies.ActionCreate) != "role_policy.created" {
		t.Fatal("create-only lifecycle is not registered")
	}
}
