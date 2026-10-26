package connector

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// CapCredentialProofV1 advertises the standalone, read-only proof job. The
// adapter's credential.prove capability alone also exists in older agents
// that can only prove a password after rotating it.
const CapCredentialProofV1 Capability = "connector.credential_prove.v1"

// CredentialProofPayload carries identity and configuration only. The exact
// staged password/version travels exclusively in the bound credentials frame.
type CredentialProofPayload struct {
	Connection ConnectionRef  `json:"connection"`
	TLS        TLSRef         `json:"tls,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
	Account    AccountRef     `json:"account"`
	AccountID  string         `json:"account_id"`
}

func ParseCredentialProofPayload(raw json.RawMessage) (CredentialProofPayload, error) {
	var p CredentialProofPayload
	if err := decodeCredentialProof(raw, &p); err != nil {
		return p, errors.New("connector: invalid credential proof payload")
	}
	if p.Connection.ID == "" || p.Connection.Engine == "" || p.AccountID == "" ||
		p.Account.Kind != "login" || p.Account.EngineIdentity == "" {
		return p, errors.New("connector: credential proof requires a connection and login identity")
	}
	return p, nil
}

// CredentialProofOutcome is a closed acknowledgement, never an adapter result
// or error string. Workers check every field before promoting the staged secret.
type CredentialProofOutcome struct {
	Verified       bool   `json:"verified"`
	AccountID      string `json:"account_id"`
	EngineIdentity string `json:"engine_identity"`
	VaultVersion   int    `json:"vault_version"`
}

func ParseCredentialProofOutcome(raw json.RawMessage) (CredentialProofOutcome, error) {
	var p CredentialProofOutcome
	if err := decodeCredentialProof(raw, &p); err != nil || !p.Verified ||
		p.AccountID == "" || p.EngineIdentity == "" || p.VaultVersion <= 0 {
		return p, errors.New("connector: credential proof is not confirmed")
	}
	return p, nil
}

func decodeCredentialProof(raw json.RawMessage, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("unexpected trailing proof data")
	}
	return nil
}
