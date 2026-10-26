package connector

import (
	"encoding/json"
	"errors"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

const JobAccountCreation JobKind = "job.postgres_account_creation.v1"

// Each stage has a closed schema. Credentials/version travel only in the
// bound credentials frame. A receipt is non-secret identity evidence.
type AccountCreationPayload struct {
	Stage     string                        `json:"stage"`
	AccountID string                        `json:"account_id"`
	Request   MutationPayload               `json:"request"`
	Proof     *adapter.AccountCreationProof `json:"proof,omitempty"`
}

func ParseAccountCreationPayload(raw json.RawMessage) (AccountCreationPayload, error) {
	var p AccountCreationPayload
	if err := decodeCredentialProof(raw, &p); err != nil {
		return p, errors.New("connector: invalid account creation payload")
	}
	request, err := json.Marshal(p.Request)
	if err != nil {
		return p, err
	}
	if _, err = ParseMutationPayload(request); err != nil {
		return p, err
	}
	if p.AccountID == "" || p.Request.Change.Kind != string(adapter.ChangePostgresAccountCreateV2) ||
		p.Request.Connection.ID == "" {
		return p, errors.New("connector: account creation requires a pinned PostgreSQL LOGIN")
	}
	switch p.Stage {
	case "preflight", "create":
		if p.Proof != nil {
			return p, errors.New("connector: creation stage cannot carry an existing receipt")
		}
	case "verify":
		if p.Proof == nil || p.Proof.RoleOID == 0 ||
			p.Proof.EngineIdentity != p.Request.Change.Account.EngineIdentity ||
			p.Proof.TargetIdentity != p.Request.Change.ExpectedTargetIdentity {
			return p, errors.New("connector: verification requires an exact creation receipt")
		}
	default:
		return p, errors.New("connector: unknown account creation stage")
	}
	return p, nil
}

type AccountCreationOutcome struct {
	Stage        string                        `json:"stage"`
	AccountID    string                        `json:"account_id"`
	VaultVersion int                           `json:"vault_version"`
	Confirmed    bool                          `json:"confirmed"`
	Proof        *adapter.AccountCreationProof `json:"proof,omitempty"`
}

func ParseAccountCreationOutcome(raw json.RawMessage) (AccountCreationOutcome, error) {
	var p AccountCreationOutcome
	if err := decodeCredentialProof(raw, &p); err != nil || !p.Confirmed || p.AccountID == "" || p.VaultVersion <= 0 {
		return p, errors.New("connector: account creation stage is not confirmed")
	}
	switch p.Stage {
	case "preflight":
		if p.Proof != nil {
			return p, errors.New("connector: preflight cannot confirm a created role")
		}
	case "create", "verify":
		if p.Proof == nil || p.Proof.RoleOID == 0 || p.Proof.EngineIdentity == "" || p.Proof.TargetIdentity == "" {
			return p, errors.New("connector: stage requires a complete creation proof")
		}
	default:
		return p, errors.New("connector: unknown account creation outcome stage")
	}
	return p, nil
}
