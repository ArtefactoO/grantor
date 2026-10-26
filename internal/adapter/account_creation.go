package adapter

import "context"

// CapPostgresAccountCreationV1 advertises the proof-carrying PostgreSQL LOGIN
// creation contract. It must also be negotiated by a connector before the
// control plane sends credentials for any of its stages.
const CapPostgresAccountCreationV1 Capability = "postgres.account_creation.v1"

// AccountCreationProof identifies the role committed by this creation call.
// It carries neither credentials nor their derivatives. A lost commit response
// cannot be reconstructed from a later role lookup: that role may be foreign.
type AccountCreationProof struct {
	EngineIdentity string `json:"engine_identity"`
	RoleOID        uint32 `json:"role_oid"`
	TargetIdentity string `json:"target_identity"`
}

// AccountCreationProvisioner separates the read-only admission probe, the
// single target mutation and its resumable credential proof. Create must reject
// an existing identity; Verify must never create, adopt or rotate an account.
// Preflight cannot fence an external HBA change between it and Verify.
type AccountCreationProvisioner interface {
	PreflightAccountCreation(context.Context, DesiredChange) error
	CreateAccountWithProof(context.Context, DesiredChange) (*AccountCreationProof, error)
	VerifyCreatedAccount(context.Context, DesiredChange, AccountCreationProof) error
}
