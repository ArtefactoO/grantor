package credentials

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
)

var ErrCredentialVersionConflict = errors.New("credentials: canonical credential version changed")

// CredentialMetadata retains the KV version after soft deletion: CAS must use
// that version, while verification receipts must not describe deleted data.
func (s *Service) CredentialMetadata(ctx context.Context, path string) (version int, present bool, err error) {
	if s == nil || s.vault == nil {
		return 0, false, ErrVaultNotConfigured
	}
	if path == "" {
		return 0, false, errors.New("credentials: canonical path is absent")
	}
	m, err := s.vault.Metadata(ctx, path)
	if errors.Is(err, vault.ErrNotFound) {
		return 0, false, nil
	}
	if err != nil || m == nil {
		return 0, false, errors.New("credentials: canonical metadata unavailable")
	}
	v, ok := m.Versions[m.CurrentVersion]
	return m.CurrentVersion, ok && !v.Destroyed && v.DeletionTime == nil, nil
}

func (s *Service) CredentialVersion(ctx context.Context, path string) (int, error) {
	version, _, err := s.CredentialMetadata(ctx, path)
	return version, err
}

// VerificationPathAllowed restricts proof to the account's own credential or
// its current principal's shared credential in this connection environment.
func VerificationPathAllowed(accountID uuid.UUID, principalID *uuid.UUID, environment, path string, reconcile bool) bool {
	if accountID == uuid.Nil {
		return false
	}
	own, err := vault.AccountCredentialPath(accountID.String())
	if err == nil && path == own {
		return true
	}
	if reconcile || principalID == nil || *principalID == uuid.Nil {
		return false
	}
	shared, err := vault.PrincipalEnvironmentCredentialPath(principalID.String(), environment)
	return err == nil && path == shared
}

func verificationProofPath(accountID, operationID uuid.UUID) string {
	return fmt.Sprintf("accounts/%s/verification-proofs/%s", accountID, operationID)
}

func validVerificationCredential(accountID, operationID uuid.UUID, username string, password []byte) bool {
	return accountID != uuid.Nil && operationID != uuid.Nil && username != "" && len(password) > 0 && len(password) <= 4096
}

func (s *Service) PutVerificationProof(ctx context.Context, accountID, operationID uuid.UUID, username string, password []byte) (int, error) {
	if s == nil || s.vault == nil {
		return 0, ErrVaultNotConfigured
	}
	if !validVerificationCredential(accountID, operationID, username, password) {
		return 0, errors.New("credentials: invalid verification proof")
	}
	path := verificationProofPath(accountID, operationID)
	v, err := s.vault.PutCAS(ctx, path, map[string]any{"username": username, "password": string(password), "verification_operation_id": operationID.String()}, 0)
	if err == nil {
		return v, nil
	}
	d, current, readErr := s.vault.Get(ctx, path)
	if readErr != nil {
		return 0, errors.New("credentials: verification staging outcome unavailable")
	}
	if current == 1 && verificationValueMatches(d, operationID, username, password) {
		return current, nil
	}
	return 0, ErrCredentialVersionConflict
}

func (s *Service) GetVerificationProof(ctx context.Context, accountID, operationID uuid.UUID, version int) (string, []byte, error) {
	if s == nil || s.vault == nil {
		return "", nil, ErrVaultNotConfigured
	}
	if version != 1 || accountID == uuid.Nil || operationID == uuid.Nil {
		return "", nil, errors.New("credentials: invalid verification proof")
	}
	d, err := s.vault.GetVersion(ctx, verificationProofPath(accountID, operationID), version)
	if err != nil {
		return "", nil, errors.New("credentials: verification proof unavailable")
	}
	u, _ := d["username"].(string)
	p, _ := d["password"].(string)
	marker, _ := d["verification_operation_id"].(string)
	if !validVerificationCredential(accountID, operationID, u, []byte(p)) || marker != operationID.String() {
		return "", nil, errors.New("credentials: invalid verification proof")
	}
	return u, []byte(p), nil
}

func (s *Service) DeleteVerificationProof(ctx context.Context, accountID, operationID uuid.UUID) error {
	if s == nil || s.vault == nil {
		return ErrVaultNotConfigured
	}
	if accountID == uuid.Nil || operationID == uuid.Nil {
		return errors.New("credentials: invalid verification proof")
	}
	if err := s.vault.DeleteMetadata(ctx, verificationProofPath(accountID, operationID)); err != nil && !errors.Is(err, vault.ErrNotFound) {
		return errors.New("credentials: verification proof cleanup unavailable")
	}
	return nil
}

// A lost Vault response is resolved by the operation marker and exact value.
// An unrelated write, even with the same password, never satisfies this CAS.
func (s *Service) ReconcileAccountCredentialCAS(ctx context.Context, accountID, operationID uuid.UUID, username string, password []byte, expected int) (int, error) {
	if s == nil || s.vault == nil {
		return 0, ErrVaultNotConfigured
	}
	if expected < 0 || !validVerificationCredential(accountID, operationID, username, password) {
		return 0, errors.New("credentials: invalid credential reconciliation")
	}
	path, err := vault.AccountCredentialPath(accountID.String())
	if err != nil {
		return 0, errors.New("credentials: invalid credential reconciliation")
	}
	v, err := s.vault.PutCAS(ctx, path, map[string]any{"username": username, "password": string(password), "verification_operation_id": operationID.String()}, expected)
	if err == nil {
		return v, nil
	}
	d, current, readErr := s.vault.Get(ctx, path)
	if readErr == nil && current == expected+1 && verificationValueMatches(d, operationID, username, password) {
		return current, nil
	}
	// Metadata distinguishes a competing soft-delete/destroy from an absent
	// value without reading or replacing any unrelated secret.
	current, metadataErr := s.CredentialVersion(ctx, path)
	if metadataErr != nil {
		return 0, errors.New("credentials: reconciliation outcome unavailable")
	}
	if current != expected {
		return 0, ErrCredentialVersionConflict
	}
	return 0, errors.New("credentials: reconciliation unavailable")
}

func verificationValueMatches(data map[string]any, operationID uuid.UUID, username string, password []byte) bool {
	u, _ := data["username"].(string)
	p, _ := data["password"].(string)
	marker, _ := data["verification_operation_id"].(string)
	return marker == operationID.String() && u == username && subtle.ConstantTimeCompare([]byte(p), password) == 1
}
