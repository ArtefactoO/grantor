package connector_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/connector"
)

// samplePlan — план с секретом в DesiredChange: sanitized-проекция обязана его
// потерять.
func samplePlan() *adapter.Plan {
	return &adapter.Plan{
		Change: adapter.DesiredChange{
			Kind:       adapter.ChangeGrant,
			Account:    adapter.Account{Kind: "login", EngineIdentity: "svc-1"},
			Permission: "role:readers",
			Scope:      "db:app",
			Credential: &adapter.Credential{Kind: "password", Username: "svc-1", Secret: []byte("s3cr3t-canary")},
			Connection: adapter.Connection{
				AdminCredential: adapter.Credential{Kind: "password", Username: "admin", Secret: []byte("admin-canary")},
			},
		},
		Steps: []adapter.PlanStep{
			{Kind: "grant", Description: "grant role:readers -> svc-1", Attributes: map[string]any{"role": "readers"}},
		},
	}
}

// TestMarshalSanitizedPlanFormat — форма плана совпадает с форматом
// operations.plan этапа 1b (change/steps с теми же ключами), а секреты из
// DesiredChange в него не попадают.
func TestMarshalSanitizedPlanFormat(t *testing.T) {
	raw, err := connector.MarshalSanitizedPlan(samplePlan())
	if err != nil {
		t.Fatalf("MarshalSanitizedPlan: %v", err)
	}
	for _, canary := range []string{"s3cr3t-canary", "admin-canary"} {
		if strings.Contains(string(raw), canary) {
			t.Fatalf("sanitized plan leaked secret %q: %s", canary, raw)
		}
	}

	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal sanitized plan: %v", err)
	}
	change, ok := doc["change"].(map[string]any)
	if !ok {
		t.Fatalf("plan has no change object: %s", raw)
	}
	if change["kind"] != "grant" || change["account"] != "svc-1" ||
		change["permission"] != "role:readers" || change["scope"] != "db:app" {
		t.Errorf("change fields mismatch: %v", change)
	}
	steps, ok := doc["steps"].([]any)
	if !ok || len(steps) != 1 {
		t.Fatalf("plan steps mismatch: %s", raw)
	}
	step := steps[0].(map[string]any)
	if step["kind"] != "grant" || step["description"] == "" {
		t.Errorf("step fields mismatch: %v", step)
	}
}

// TestMarshalSanitizedResultRoundTrip — результат с verification
// сериализуется в формат operations.result и разбирается обратно
// ParseSanitizedResult.
func TestMarshalSanitizedResultRoundTrip(t *testing.T) {
	res := &adapter.Result{
		Steps: []adapter.StepResult{
			{Step: adapter.PlanStep{Kind: "grant"}, Status: adapter.StepApplied},
			{Step: adapter.PlanStep{Kind: "noop"}, Status: adapter.StepSkipped},
		},
	}
	ver := &adapter.Verification{Verified: true, Details: "verified: binding present"}

	raw, err := connector.MarshalSanitizedResult(res, ver)
	if err != nil {
		t.Fatalf("MarshalSanitizedResult: %v", err)
	}
	parsed, err := connector.ParseSanitizedResult(raw)
	if err != nil {
		t.Fatalf("ParseSanitizedResult: %v", err)
	}
	if len(parsed.Steps) != 2 ||
		parsed.Steps[0].Kind != "grant" || parsed.Steps[0].Status != string(adapter.StepApplied) ||
		parsed.Steps[1].Status != string(adapter.StepSkipped) {
		t.Errorf("steps round-trip mismatch: %+v", parsed.Steps)
	}
	if parsed.Verification == nil || !parsed.Verification.Verified ||
		parsed.Verification.Details != ver.Details {
		t.Errorf("verification round-trip mismatch: %+v", parsed.Verification)
	}

	// Без verification поле отсутствует в JSON (omitempty), как в этапе 1b.
	raw, err = connector.MarshalSanitizedResult(res, nil)
	if err != nil {
		t.Fatalf("MarshalSanitizedResult(nil ver): %v", err)
	}
	if strings.Contains(string(raw), "verification") {
		t.Errorf("nil verification must be omitted: %s", raw)
	}
}

func TestSanitizedDatabaseProofPinsOwnerIncarnation(t *testing.T) {
	verification := &adapter.Verification{Verified: true, Observed: map[string]any{
		"database_name": "app", "database_owner": "app_owner",
		"database_oid": uint32(42), "database_owner_oid": uint32(17),
		"target_identity": "postgres:system:123",
	}}
	raw, err := connector.MarshalSanitizedResult(&adapter.Result{}, verification)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := connector.ParseSanitizedResult(raw)
	if err != nil || parsed.Verification == nil ||
		parsed.Verification.Observed["database_owner_oid"] != uint32(17) {
		t.Fatalf("database proof lost owner incarnation: %+v / %v", parsed, err)
	}
	delete(verification.Observed, "database_owner_oid")
	if _, err := connector.MarshalSanitizedResult(&adapter.Result{}, verification); err == nil {
		t.Fatal("database proof without owner OID was accepted")
	}
}

func TestSanitizedRolePolicyProofUsesClosedShape(t *testing.T) {
	proof := map[string]any{
		"expected_fingerprint": strings.Repeat("a", 64),
		"observed_fingerprint": strings.Repeat("b", 64),
		"target_identity":      "postgres:system:123", "database": "app",
		"database_oid": uint32(42), "database_owner": "app_owner",
		"database_owner_oid": uint32(17), "admin_identity": "grantor",
	}
	raw, err := connector.MarshalSanitizedResult(&adapter.Result{},
		&adapter.Verification{Verified: true, Observed: proof})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := connector.ParseSanitizedResult(raw)
	if err != nil || parsed.Verification == nil ||
		parsed.Verification.Observed["expected_fingerprint"] != proof["expected_fingerprint"] {
		t.Fatalf("role-policy proof did not round-trip: %+v / %v", parsed, err)
	}
	proof["sql"] = "grant all"
	if _, err := connector.MarshalSanitizedResult(&adapter.Result{},
		&adapter.Verification{Verified: true, Observed: proof}); err == nil {
		t.Fatal("role-policy proof accepted an unknown field")
	}
}

func TestParseSanitizedResultInvalid(t *testing.T) {
	if _, err := connector.ParseSanitizedResult(nil); err == nil {
		t.Error("ParseSanitizedResult(nil) must fail")
	}
	if _, err := connector.ParseSanitizedResult([]byte(`{bad`)); err == nil {
		t.Error("ParseSanitizedResult(invalid) must fail")
	}
}

func TestRotateOutcomeRoundTrip(t *testing.T) {
	raw, err := connector.RotateOutcome{Rotated: true, VaultVersion: 5}.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	// Формат совпадает с result-артефактом direct-пути.
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc["rotated"] != true || doc["vault_version"] != float64(5) {
		t.Errorf("outcome JSON mismatch: %v", doc)
	}
	got, err := connector.ParseRotateOutcome(raw)
	if err != nil {
		t.Fatalf("ParseRotateOutcome: %v", err)
	}
	if !got.Rotated || got.VaultVersion != 5 {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	if _, err := connector.ParseRotateOutcome(nil); err == nil {
		t.Error("ParseRotateOutcome(nil) must fail")
	}
}

func TestAdminCredentialOutcomeRoundTripIsSecretFree(t *testing.T) {
	snapshot := &adapter.Snapshot{
		ServerVersion: "16.4",
		Topology:      map[string]any{"system_identifier": "7429012345678901234"},
	}
	outcome := connector.AdminCredentialOutcome{
		Mode: connector.AdminCredentialModeRotate, Epoch: 9,
		CandidateUsername: "grantor_admin", StagedVaultVersion: 12,
		Proof: adapter.AdminCredentialProof{
			CanonicalIdentity: "grantor_admin", AuthorityFingerprint: "authority-fingerprint",
			TargetIdentity: "postgres:system:7429012345678901234",
		},
		AlreadyApplied: true, Snapshot: snapshot,
	}
	raw, err := outcome.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(raw), "candidate-secret-canary") || strings.Contains(string(raw), "old-secret-canary") {
		t.Fatalf("admin credential outcome leaked credential material: %s", raw)
	}
	got, err := connector.ParseAdminCredentialOutcome(raw)
	if err != nil {
		t.Fatalf("ParseAdminCredentialOutcome: %v", err)
	}
	if got.Mode != outcome.Mode || got.Epoch != 9 || got.StagedVaultVersion != 12 ||
		!got.AlreadyApplied || got.Snapshot == nil || got.Snapshot.ServerVersion != "16.4" ||
		got.Proof.CanonicalIdentity != "grantor_admin" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}

	bad := outcome
	bad.Snapshot = nil
	if _, err := bad.Marshal(); err == nil {
		t.Fatal("Marshal accepted outcome without a full snapshot")
	}
	if _, err := connector.ParseAdminCredentialOutcome(nil); err == nil {
		t.Fatal("ParseAdminCredentialOutcome(nil) must fail")
	}
}
