package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/fake"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
)

var registerManagedLinkProofTestAdapter sync.Once

func TestManagedLinkProofAdapterUsesLocalEngineForConnector(t *testing.T) {
	const engine = "jobs-managed-link-proof-test"
	registerManagedLinkProofTestAdapter.Do(func() {
		adapter.Register(engine, func() adapter.Adapter { return fake.New() })
	})

	// mutationTarget возвращает nil adapter для connector routing. Guard обязан
	// разрешить capability по локальному adapter того же engine, не меняя
	// семантику mutationTarget и не обращаясь к target.
	got, err := managedLinkProofAdapter(engine, nil, true)
	if err != nil {
		t.Fatalf("managedLinkProofAdapter(connector): %v", err)
	}
	if !adapter.SupportsCredentialProof(got) {
		t.Fatal("connector proof adapter does not expose credential proof")
	}

	direct := fake.New()
	got, err = managedLinkProofAdapter(engine, direct, false)
	if err != nil {
		t.Fatalf("managedLinkProofAdapter(direct): %v", err)
	}
	if got != direct {
		t.Fatal("direct proof adapter was replaced instead of reused")
	}

	if _, err := managedLinkProofAdapter("jobs-managed-link-proof-missing", nil, true); err == nil {
		t.Fatal("unknown connector engine: err = nil, want error")
	}
}

func TestAccessPayloadRoundTrip(t *testing.T) {
	in := AccessPayload{BindingID: uuid.New(), ExpectedAccountLifecycleVersion: 7, Confirmed: true}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, err := decodeAccessPayload(raw)
	if err != nil {
		t.Fatalf("decodeAccessPayload: %v", err)
	}
	if !reflect.DeepEqual(out, in) {
		t.Errorf("round trip = %+v, want %+v", out, in)
	}

	// confirmed опционален и по умолчанию false.
	out, err = decodeAccessPayload([]byte(`{"binding_id":"` + in.BindingID.String() + `"}`))
	if err != nil {
		t.Fatalf("decodeAccessPayload without confirmed: %v", err)
	}
	if out.Confirmed {
		t.Error("confirmed = true, want false by default")
	}
}

func TestDecodeAccessPayloadErrors(t *testing.T) {
	if _, err := decodeAccessPayload([]byte(`{broken`)); err == nil {
		t.Error("broken json: err = nil, want error")
	}
	if _, err := decodeAccessPayload([]byte(`{}`)); err == nil {
		t.Error("missing binding_id: err = nil, want error")
	}
}

func TestAccessReplacePayloadAndStateGuards(t *testing.T) {
	opID := uuid.New()
	fromID := uuid.New()
	toID := uuid.New()
	payload := AccessReplacePayload{
		BindingID: uuid.New(), FromPermissionDefinitionID: fromID,
		ToPermissionDefinitionID: toID, AssignmentKey: "rabbitmq:vhost:etl",
		ExpectedBindingVersion: 8, ExpectedAccountLifecycleVersion: 3, Confirmed: true,
		PermissionAttributes:         map[string]any{"template_key": "etl", "write": "^etl$"},
		ReverseOfOperationID:         uuid.New(),
		ConvergePermissionAttributes: map[string]any{"template_key": "old", "write": "^old$"},
		ExpectedTargetIdentity:       "rabbitmq:cluster:rabbit@prod",
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	decoded, err := decodeAccessReplacePayload(raw)
	if err != nil {
		t.Fatalf("decodeAccessReplacePayload: %v", err)
	}
	if !reflect.DeepEqual(decoded, payload) {
		t.Fatalf("round trip = %+v, want %+v", decoded, payload)
	}

	desired := inventory.BindingPresent
	pending := inventory.Binding{
		ID: payload.BindingID, PermissionDefinitionID: toID,
		AssignmentKey: payload.AssignmentKey, Version: payload.ExpectedBindingVersion,
		TransitionOperationID: &opID, DesiredState: &desired,
	}
	state, err := classifyAccessReplacement(opID, payload, pending)
	if err != nil || state != accessReplacementPending {
		t.Fatalf("pending state = %v, %v", state, err)
	}

	completed := pending
	completed.Version++
	completed.TransitionOperationID = nil
	completed.ObservedPermissionDefinitionID = &toID
	completed.ObservedState = inventory.BindingPresent
	completed.ObservedEffective = true
	completed.Status = inventory.BindingStatusSynced
	state, err = classifyAccessReplacement(opID, payload, completed)
	if err != nil || state != accessReplacementCompleted {
		t.Fatalf("completed state = %v, %v", state, err)
	}

	stale := pending
	otherOperation := uuid.New()
	stale.TransitionOperationID = &otherOperation
	if _, err := classifyAccessReplacement(opID, payload, stale); err == nil {
		t.Fatal("stale transition owner: err = nil")
	}
}

func TestDecodeAccessReplacePayloadRejectsUnpinnedIntent(t *testing.T) {
	valid := AccessReplacePayload{
		BindingID: uuid.New(), FromPermissionDefinitionID: uuid.New(),
		ToPermissionDefinitionID: uuid.New(), AssignmentKey: "slot", ExpectedBindingVersion: 1,
	}
	cases := []AccessReplacePayload{
		{},
		{BindingID: valid.BindingID},
		{BindingID: valid.BindingID, FromPermissionDefinitionID: valid.FromPermissionDefinitionID},
		{BindingID: valid.BindingID, FromPermissionDefinitionID: valid.FromPermissionDefinitionID,
			ToPermissionDefinitionID: valid.FromPermissionDefinitionID, AssignmentKey: "slot", ExpectedBindingVersion: 1},
		{BindingID: valid.BindingID, FromPermissionDefinitionID: valid.FromPermissionDefinitionID,
			ToPermissionDefinitionID: valid.ToPermissionDefinitionID, ExpectedBindingVersion: 1},
	}
	for i, input := range cases {
		raw, err := json.Marshal(input)
		if err != nil {
			t.Fatalf("case %d marshal: %v", i, err)
		}
		if _, err := decodeAccessReplacePayload(raw); err == nil {
			t.Errorf("case %d: err = nil", i)
		}
	}
}

func TestAccountPayloadRoundTrip(t *testing.T) {
	in := AccountPayload{
		AccountID: uuid.New(), ExpectedStatus: inventory.AccountDeleted,
		ExpectedLifecycleVersion: 4, CredentialMode: inventory.CredentialModeProvided,
		CredentialVaultVersion: 9,
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// shared_credential_path опционален: пустое значение omitempty опускает.
	if strings.Contains(string(raw), "shared_credential_path") {
		t.Errorf("empty shared_credential_path must be omitted: %s", raw)
	}
	out, err := decodeAccountPayload(raw)
	if err != nil {
		t.Fatalf("decodeAccountPayload: %v", err)
	}
	if out != in {
		t.Errorf("round trip = %+v, want %+v", out, in)
	}

	// Payload с общим секретом принципала: путь сохраняется через round trip.
	shared := AccountPayload{
		AccountID:            uuid.New(),
		SharedCredentialPath: "principals/" + uuid.NewString() + "/environments/prod/credential",
	}
	raw, err = json.Marshal(shared)
	if err != nil {
		t.Fatalf("marshal shared: %v", err)
	}
	out, err = decodeAccountPayload(raw)
	if err != nil {
		t.Fatalf("decodeAccountPayload shared: %v", err)
	}
	if out != shared {
		t.Errorf("shared round trip = %+v, want %+v", out, shared)
	}

	// Adopt-payload: флаг сохраняется через round trip, а у обычного
	// payload omitempty опускает его.
	if strings.Contains(string(raw), `"adopt"`) {
		t.Errorf("false adopt must be omitted: %s", raw)
	}
	adopt := AccountPayload{AccountID: uuid.New(), Adopt: true}
	raw, err = json.Marshal(adopt)
	if err != nil {
		t.Fatalf("marshal adopt: %v", err)
	}
	// adopt mode=password не несёт adopt_generate: omitempty опускает его,
	// поэтому payload идентичен прежнему побайтово.
	if strings.Contains(string(raw), "adopt_generate") {
		t.Errorf("false adopt_generate must be omitted: %s", raw)
	}
	out, err = decodeAccountPayload(raw)
	if err != nil {
		t.Fatalf("decodeAccountPayload adopt: %v", err)
	}
	if out != adopt {
		t.Errorf("adopt round trip = %+v, want %+v", out, adopt)
	}

	// adopt mode=generate: оба флага сохраняются через round trip.
	adoptGen := AccountPayload{AccountID: uuid.New(), Adopt: true, AdoptGenerate: true}
	raw, err = json.Marshal(adoptGen)
	if err != nil {
		t.Fatalf("marshal adopt generate: %v", err)
	}
	out, err = decodeAccountPayload(raw)
	if err != nil {
		t.Fatalf("decodeAccountPayload adopt generate: %v", err)
	}
	if out != adoptGen {
		t.Errorf("adopt generate round trip = %+v, want %+v", out, adoptGen)
	}

	if _, err := decodeAccountPayload([]byte(`{}`)); err == nil {
		t.Error("missing account_id: err = nil, want error")
	}
	if _, err := decodeAccountPayload([]byte(`null`)); err == nil {
		t.Error("null payload: err = nil, want error")
	}
}

// TestRotateCredentialSource фиксирует выбор источника пароля
// credential.rotate: общий секрет принципала имеет приоритет над adopt,
// adopt mode=password читает предзаписанную версию, adopt mode=generate и
// обычная ротация генерируют.
func TestRotateCredentialSource(t *testing.T) {
	id := uuid.New()
	cases := []struct {
		name    string
		payload AccountPayload
		want    rotateSource
	}{
		{"per-account rotate", AccountPayload{AccountID: id}, rotateSourceGenerate},
		{"shared principal secret", AccountPayload{AccountID: id, SharedCredentialPath: "principals/p/environments/prod/credential"}, rotateSourceShared},
		{"adopt password", AccountPayload{AccountID: id, Adopt: true}, rotateSourceAdopt},
		{"adopt generate", AccountPayload{AccountID: id, Adopt: true, AdoptGenerate: true}, rotateSourceGenerate},
		{"shared wins over adopt", AccountPayload{AccountID: id, Adopt: true, SharedCredentialPath: "principals/p/environments/prod/credential"}, rotateSourceShared},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rotateCredentialSource(tc.payload); got != tc.want {
				t.Errorf("rotateCredentialSource(%+v) = %q, want %q", tc.payload, got, tc.want)
			}
		})
	}
}

func TestAccountLifecycleExpectationCreateIsNeverMistakenForApplied(t *testing.T) {
	account := inventory.Account{
		ID: uuid.New(), Status: inventory.AccountActive, LifecycleVersion: 1,
	}
	expected, alreadyApplied, err := accountLifecycleExpectation(account, AccountPayload{
		AccountID: account.ID, ExpectedStatus: inventory.AccountActive, ExpectedLifecycleVersion: 1,
	}, adapter.ChangeAccountCreate)
	if err != nil {
		t.Fatalf("accountLifecycleExpectation(create): %v", err)
	}
	if expected != inventory.AccountActive || alreadyApplied {
		t.Fatalf("create expectation = (%q, %v), want (active, false)", expected, alreadyApplied)
	}

	// Restore имеет отличимое финальное состояние и после атомарной metadata-
	// активации может безопасно завершить retry без повторной записи metadata.
	restored := account
	restored.LifecycleVersion = 2
	_, alreadyApplied, err = accountLifecycleExpectation(restored, AccountPayload{
		AccountID: restored.ID, ExpectedStatus: inventory.AccountDeleted, ExpectedLifecycleVersion: 2,
	}, adapter.ChangeAccountRestore)
	if err != nil || !alreadyApplied {
		t.Fatalf("accountLifecycleExpectation(restored retry) = (%v, %v), want (nil, true)", err, alreadyApplied)
	}

	if _, _, err = accountLifecycleExpectation(restored, AccountPayload{
		AccountID: restored.ID, ExpectedStatus: inventory.AccountActive, ExpectedLifecycleVersion: 1,
	}, adapter.ChangeAccountDelete); !errors.Is(err, inventory.ErrAccountLifecycleConflict) {
		t.Fatalf("stale lifecycle error = %v, want ErrAccountLifecycleConflict", err)
	}
}

func TestExecuteMutationInvalidPayload(t *testing.T) {
	// Ошибка разбора payload возвращается до обращений к базе, поэтому
	// пустых deps достаточно.
	e := NewMainExecutor(DiscoveryDeps{})
	for _, kind := range []string{KindAccessGrant, KindAccessRevoke} {
		err := e.Execute(context.Background(), operations.Operation{
			ID: uuid.New(), Kind: kind, Payload: []byte(`{}`),
		})
		if err == nil || !strings.Contains(err.Error(), "binding_id") {
			t.Errorf("Execute(%s) error = %v, want mention of binding_id", kind, err)
		}
	}
	for _, kind := range []string{KindAccountCreate, KindAccountDisable, KindAccountEnable, KindAccountDelete, KindAccountRestore, KindCredentialRotate} {
		err := e.Execute(context.Background(), operations.Operation{
			ID: uuid.New(), Kind: kind, Payload: []byte(`{}`),
		})
		if err == nil || !strings.Contains(err.Error(), "account_id") {
			t.Errorf("Execute(%s) error = %v, want mention of account_id", kind, err)
		}
	}
}

func TestMarshalPlanSanitized(t *testing.T) {
	secret := []byte("target-password-value")
	plan := &adapter.Plan{
		Change: adapter.DesiredChange{
			Kind:       adapter.ChangeAccountCreate,
			Account:    adapter.Account{Kind: "login", EngineIdentity: "svc_payments"},
			Credential: &adapter.Credential{Kind: "password", Username: "svc_payments", Secret: secret},
			Connection: adapter.Connection{
				AdminCredential: adapter.Credential{Username: "admin", Secret: []byte("admin-password-value")},
			},
		},
		Steps: []adapter.PlanStep{{Kind: "account.create", Description: "create role svc_payments"}},
	}

	raw, err := marshalPlan(plan)
	if err != nil {
		t.Fatalf("marshalPlan: %v", err)
	}
	got := string(raw)
	// Секреты (в том числе в base64-представлении []byte) в план не
	// попадают никогда.
	for _, leak := range []string{"target-password-value", "admin-password-value", "credential", "secret"} {
		if strings.Contains(got, leak) {
			t.Errorf("plan json contains %q: %s", leak, got)
		}
	}
	if !strings.Contains(got, "svc_payments") || !strings.Contains(got, "account.create") {
		t.Errorf("plan json misses expected fields: %s", got)
	}
}

func TestMarshalResult(t *testing.T) {
	res := &adapter.Result{Steps: []adapter.StepResult{
		{Step: adapter.PlanStep{Kind: "grant"}, Status: adapter.StepApplied},
		{Step: adapter.PlanStep{Kind: "noop"}, Status: adapter.StepSkipped},
	}}
	raw, err := marshalResult(res, &adapter.Verification{Verified: true, Details: "binding present"})
	if err != nil {
		t.Fatalf("marshalResult: %v", err)
	}
	var out connector.SanitizedResult
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if len(out.Steps) != 2 || out.Steps[0].Status != "applied" || out.Steps[1].Status != "skipped" {
		t.Errorf("unexpected steps: %+v", out.Steps)
	}
	if out.Verification == nil || !out.Verification.Verified {
		t.Errorf("unexpected verification: %+v", out.Verification)
	}
}

func TestOperationArtifactsLifecycle(t *testing.T) {
	e := NewMainExecutor(DiscoveryDeps{})
	id := uuid.New()

	if a := e.TakeOperationArtifacts(id); a.Plan != nil || a.Result != nil {
		t.Errorf("artifacts of unknown operation = %+v, want zero", a)
	}

	e.setPlanArtifact(id, []byte(`{"p":1}`))
	e.setResultArtifact(id, []byte(`{"r":1}`))
	a := e.TakeOperationArtifacts(id)
	if string(a.Plan) != `{"p":1}` || string(a.Result) != `{"r":1}` {
		t.Errorf("artifacts = %+v, want stored plan/result", a)
	}
	// Take забирает артефакты ровно один раз.
	if a := e.TakeOperationArtifacts(id); a.Plan != nil || a.Result != nil {
		t.Errorf("artifacts after take = %+v, want zero", a)
	}
}

func TestReconstructRestoreArtifacts(t *testing.T) {
	e := NewMainExecutor(DiscoveryDeps{})
	id := uuid.New()
	acct := inventory.Account{ID: uuid.New(), Kind: "login", EngineIdentity: "svc_recovered"}
	op := operations.Operation{ID: id, Kind: KindAccountRestore}

	if err := e.reconstructRestoreArtifacts(op, acct); err != nil {
		t.Fatalf("reconstructRestoreArtifacts: %v", err)
	}
	artifacts := e.TakeOperationArtifacts(id)
	if len(artifacts.Plan) == 0 || len(artifacts.Result) == 0 {
		t.Fatalf("reconstructed artifacts are empty: plan=%d result=%d", len(artifacts.Plan), len(artifacts.Result))
	}
	var plan connector.SanitizedPlan
	if err := json.Unmarshal(artifacts.Plan, &plan); err != nil {
		t.Fatalf("unmarshal reconstructed plan: %v", err)
	}
	if plan.Change.Kind != string(adapter.ChangeAccountRestore) || plan.Change.Account != acct.EngineIdentity ||
		len(plan.Steps) != 1 || plan.Steps[0].Kind != "restore-account-recovered" {
		t.Errorf("reconstructed plan = %+v", plan)
	}
	var result connector.SanitizedResult
	if err := json.Unmarshal(artifacts.Result, &result); err != nil {
		t.Fatalf("unmarshal reconstructed result: %v", err)
	}
	if len(result.Steps) != 1 || result.Steps[0].Status != string(adapter.StepSkipped) ||
		result.Verification == nil || !result.Verification.Verified {
		t.Errorf("reconstructed result = %+v", result)
	}
}
