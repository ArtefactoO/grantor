package connector

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

func creationPayloadFixture(stage string) AccountCreationPayload {
	p := AccountCreationPayload{Stage: stage, AccountID: "account-id", Request: MutationPayload{
		Connection: ConnectionRef{ID: "connection-id", Engine: "postgres", ConfigIncarnation: "config-1"},
		Attributes: map[string]any{"database": "postgres"},
		Change: ChangeRef{Kind: string(adapter.ChangePostgresAccountCreateV2),
			Account:               AccountRef{Kind: "login", EngineIdentity: "created_login"},
			ExpectedAdminIdentity: "grantor", ExpectedTargetIdentity: "postgres:system:42"},
	}}
	if stage == "verify" {
		p.Proof = &adapter.AccountCreationProof{EngineIdentity: "created_login", RoleOID: 123, TargetIdentity: "postgres:system:42"}
	}
	return p
}

func mustCreationJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestAccountCreationPayloadRequiresClosedStageSchema(t *testing.T) {
	for _, stage := range []string{"preflight", "create", "verify"} {
		if _, err := ParseAccountCreationPayload(mustCreationJSON(t, creationPayloadFixture(stage))); err != nil {
			t.Fatalf("valid %s payload: %v", stage, err)
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(*AccountCreationPayload)
	}{
		{"unknown stage", func(p *AccountCreationPayload) { p.Stage = "sql" }},
		{"missing account ID", func(p *AccountCreationPayload) { p.AccountID = "" }},
		{"missing connection ID", func(p *AccountCreationPayload) { p.Request.Connection.ID = "" }},
		{"foreign engine", func(p *AccountCreationPayload) { p.Request.Connection.Engine = "mysql" }},
		{"legacy kind", func(p *AccountCreationPayload) { p.Request.Change.Kind = string(adapter.ChangeAccountCreate) }},
		{"restore kind", func(p *AccountCreationPayload) {
			p.Request.Change.Kind = string(adapter.ChangePostgresAccountRestoreV2)
		}},
		{"group identity", func(p *AccountCreationPayload) { p.Request.Change.Account.Kind = "group" }},
		{"missing admin pin", func(p *AccountCreationPayload) { p.Request.Change.ExpectedAdminIdentity = "" }},
		{"missing target pin", func(p *AccountCreationPayload) { p.Request.Change.ExpectedTargetIdentity = "" }},
		{"missing config pin", func(p *AccountCreationPayload) { p.Request.Connection.ConfigIncarnation = "" }},
		{"SQL attributes", func(p *AccountCreationPayload) { p.Request.Change.Attributes = map[string]any{"sql": "select 1"} }},
		{"SQL connection attributes", func(p *AccountCreationPayload) { p.Request.Attributes["sql"] = "select 1" }},
		{"proof on create", func(p *AccountCreationPayload) { p.Stage = "create" }},
		{"proof on preflight", func(p *AccountCreationPayload) { p.Stage = "preflight" }},
		{"missing verification proof", func(p *AccountCreationPayload) { p.Proof = nil }},
		{"zero verification OID", func(p *AccountCreationPayload) { p.Proof.RoleOID = 0 }},
		{"foreign verification identity", func(p *AccountCreationPayload) { p.Proof.EngineIdentity = "foreign_login" }},
		{"foreign verification target", func(p *AccountCreationPayload) { p.Proof.TargetIdentity = "postgres:system:999" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := creationPayloadFixture("verify")
			tc.mutate(&payload)
			if _, err := ParseAccountCreationPayload(mustCreationJSON(t, payload)); err == nil {
				t.Fatal("unsafe account creation payload was accepted")
			}
		})
	}
}

func TestAccountCreationPayloadRejectsUnknownFieldsAtEveryBoundary(t *testing.T) {
	for _, location := range []string{"root", "request", "connection", "change", "account", "proof"} {
		t.Run(location, func(t *testing.T) {
			raw := mustCreationJSON(t, creationPayloadFixture("verify"))
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			request := doc["request"].(map[string]any)
			var target map[string]any
			switch location {
			case "root":
				target = doc
			case "request":
				target = request
			case "connection", "change":
				target = request[location].(map[string]any)
			case "account":
				target = request["change"].(map[string]any)["account"].(map[string]any)
			case "proof":
				target = doc["proof"].(map[string]any)
			}
			target["sql"] = "unknown-field-canary"
			if _, err := ParseAccountCreationPayload(mustCreationJSON(t, doc)); err == nil || strings.Contains(err.Error(), "unknown-field-canary") {
				t.Fatal("unknown command field was accepted or copied into an error")
			}
		})
	}
	valid := mustCreationJSON(t, creationPayloadFixture("create"))
	if _, err := ParseAccountCreationPayload(append(valid, []byte(` {"sql":"select 1"}`)...)); err == nil {
		t.Fatal("trailing account creation command was accepted")
	}
}

func TestAccountCreationOutcomeRequiresExactStageShape(t *testing.T) {
	proof := &adapter.AccountCreationProof{EngineIdentity: "created_login", RoleOID: 123, TargetIdentity: "postgres:system:42"}
	for _, stage := range []string{"preflight", "create", "verify"} {
		out := AccountCreationOutcome{Stage: stage, AccountID: "account-id", VaultVersion: 7, Confirmed: true}
		if stage != "preflight" {
			out.Proof = proof
		}
		if _, err := ParseAccountCreationOutcome(mustCreationJSON(t, out)); err != nil {
			t.Fatalf("valid %s outcome: %v", stage, err)
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(*AccountCreationOutcome)
	}{
		{"unconfirmed", func(o *AccountCreationOutcome) { o.Confirmed = false }},
		{"unknown stage", func(o *AccountCreationOutcome) { o.Stage = "rotate" }},
		{"empty stage", func(o *AccountCreationOutcome) { o.Stage = "" }},
		{"missing account", func(o *AccountCreationOutcome) { o.AccountID = "" }},
		{"missing Vault version", func(o *AccountCreationOutcome) { o.VaultVersion = 0 }},
		{"negative Vault version", func(o *AccountCreationOutcome) { o.VaultVersion = -1 }},
		{"missing create proof", func(o *AccountCreationOutcome) { o.Proof = nil }},
		{"missing verify proof", func(o *AccountCreationOutcome) { o.Stage = "verify"; o.Proof = nil }},
		{"proof on preflight", func(o *AccountCreationOutcome) { o.Stage = "preflight" }},
		{"zero proof OID", func(o *AccountCreationOutcome) { o.Proof.RoleOID = 0 }},
		{"empty proof identity", func(o *AccountCreationOutcome) { o.Proof.EngineIdentity = "" }},
		{"empty proof target", func(o *AccountCreationOutcome) { o.Proof.TargetIdentity = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copyProof := *proof
			out := AccountCreationOutcome{Stage: "create", AccountID: "account-id", VaultVersion: 7, Confirmed: true, Proof: &copyProof}
			tc.mutate(&out)
			if _, err := ParseAccountCreationOutcome(mustCreationJSON(t, out)); err == nil {
				t.Fatal("ambiguous stage outcome was accepted")
			}
		})
	}
	var doc map[string]any
	if err := json.Unmarshal(mustCreationJSON(t, AccountCreationOutcome{Stage: "create", AccountID: "account-id", VaultVersion: 7, Confirmed: true, Proof: proof}), &doc); err != nil {
		t.Fatal(err)
	}
	doc["secret"] = "outcome-secret-canary"
	if _, err := ParseAccountCreationOutcome(mustCreationJSON(t, doc)); err == nil || strings.Contains(err.Error(), "outcome-secret-canary") {
		t.Fatal("outcome accepted or exposed an unknown secret field")
	}
}
