package jobs

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
)

func TestCredentialVerificationRejectsIncompleteIntentAndNilDependencies(t *testing.T) {
	id := uuid.New()
	p := CredentialVerifyPayload{AccountID: id, RequestID: uuid.New(), Status: inventory.AccountActive, LifecycleVersion: 1,
		CanonicalVersion: 1, ConfigIncarnation: "fixture-config", TargetIdentity: "fixture-target", EngineIdentity: "fixture-login", CredentialPath: "accounts/" + id.String() + "/credential"}
	if !p.valid() {
		t.Fatal("valid verification intent rejected")
	}
	for _, mutate := range []func(*CredentialVerifyPayload){
		func(p *CredentialVerifyPayload) { p.Status = inventory.AccountDisabled },
		func(p *CredentialVerifyPayload) { p.LifecycleVersion = 0 },
		func(p *CredentialVerifyPayload) { p.TargetIdentity = "" },
		func(p *CredentialVerifyPayload) { p.CredentialPath = "" },
		func(p *CredentialVerifyPayload) { p.CanonicalVersion = 0 },
		func(p *CredentialVerifyPayload) { p.Reconcile = true },
		func(p *CredentialVerifyPayload) { p.ProofVersion = 1 },
	} {
		candidate := p
		mutate(&candidate)
		if candidate.valid() {
			t.Fatal("incomplete verification intent was accepted")
		}
	}
	connectionID := uuid.New()
	raw, _ := json.Marshal(p)
	op := operations.Operation{ID: uuid.New(), Kind: KindCredentialVerify, AccountID: &id, ConnectionID: &connectionID, Payload: raw}
	err := (&MainExecutor{}).executeCredentialVerify(t.Context(), op)
	if err == nil || !strings.Contains(err.Error(), "dependencies unavailable") {
		t.Fatalf("missing dependencies must be retryable, got %v", err)
	}
	via, err := connectorRoute(connections.ExecutionModeConnector, KindCredentialVerify, true)
	if err != nil || !via {
		t.Fatal("verification did not remain on the connector route")
	}
}

func TestCredentialVerificationPinsOwnershipPrincipalIdentityAndPath(t *testing.T) {
	id, principal := uuid.New(), uuid.New()
	p := CredentialVerifyPayload{AccountID: id, RequestID: uuid.New(), Status: inventory.AccountActive, LifecycleVersion: 1,
		CanonicalVersion: 1, ConfigIncarnation: "fixture-config", TargetIdentity: "fixture-target", EngineIdentity: "fixture-login", CredentialPath: "accounts/" + id.String() + "/credential", PrincipalID: principal}
	a := inventory.Account{ID: id, PrincipalID: &principal, Status: inventory.AccountActive, LifecycleVersion: 1,
		Kind: "login", Ownership: inventory.OwnershipManaged, EngineIdentity: p.EngineIdentity, VaultPath: p.CredentialPath}
	if err := p.checkAccount(a); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*inventory.Account){
		func(a *inventory.Account) { a.PrincipalID = nil },
		func(a *inventory.Account) { a.Ownership = inventory.OwnershipUnmanaged },
		func(a *inventory.Account) { a.EngineIdentity = "foreign-login" },
		func(a *inventory.Account) { a.VaultPath = "principals/foreign/environments/test/credential" },
		func(a *inventory.Account) { a.AuthenticationScope = "foreign-scope" },
		func(a *inventory.Account) { a.LifecycleVersion++ },
	} {
		candidate := a
		mutate(&candidate)
		if err := p.checkAccount(candidate); err == nil {
			t.Fatal("changed account intent was accepted")
		}
	}
}
