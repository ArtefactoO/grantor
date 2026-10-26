package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
)

type verificationKV struct {
	mu                sync.Mutex
	version           int
	data              map[string]any
	deleted           bool
	loseWriteResponse bool
	secretError       string
}

func verificationTestService(t *testing.T, state *verificationKV) *Service {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/metadata/") {
			if r.Method == http.MethodDelete {
				state.version, state.data = 0, nil
				w.WriteHeader(http.StatusNoContent)
				return
			}
			if state.version == 0 {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			deletion := ""
			if state.deleted {
				deletion = time.Now().UTC().Format(time.RFC3339Nano)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"current_version": state.version,
				"versions": map[int]any{state.version: map[string]any{"created_time": time.Now().UTC().Format(time.RFC3339Nano), "deletion_time": deletion, "destroyed": false}}}})
			return
		}
		if r.Method == http.MethodGet {
			if state.version == 0 || state.deleted {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": state.data, "metadata": map[string]any{"version": state.version}}})
			return
		}
		var body struct {
			Data    map[string]any `json:"data"`
			Options struct {
				CAS int `json:"cas"`
			} `json:"options"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Options.CAS != state.version {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"CAS rejected " + state.secretError}})
			return
		}
		state.version++
		state.data, state.deleted = body.Data, false
		if state.loseWriteResponse {
			state.loseWriteResponse = false
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"lost acknowledgement " + state.secretError}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"version": state.version}})
	}))
	t.Cleanup(server.Close)
	client, err := vault.New(vault.Config{Address: server.URL, Token: "disposable-verification-test", Mount: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	return NewService(client, nil)
}

func TestVerificationMetadataDistinguishesSoftDeleteFromAbsent(t *testing.T) {
	state := &verificationKV{}
	s := verificationTestService(t, state)
	v, present, err := s.CredentialMetadata(t.Context(), "accounts/test/credential")
	if err != nil || v != 0 || present {
		t.Fatal("absent metadata must require CAS zero")
	}
	state.version, state.deleted = 7, true
	v, present, err = s.CredentialMetadata(t.Context(), "accounts/test/credential")
	if err != nil || v != 7 || present {
		t.Fatal("soft-deleted metadata must retain CAS version without claiming a credential")
	}
	version, err := s.ReconcileAccountCredentialCAS(t.Context(), uuid.New(), uuid.New(), "fixture-login", []byte("fixture-current-password"), 7)
	if err != nil || version != 8 {
		t.Fatalf("soft-deleted canonical reconciliation failed: version=%d err=%v", version, err)
	}
}

func TestVerificationReconcileCASAcceptsOnlyItsExactLostWrite(t *testing.T) {
	accountID, operationID := uuid.New(), uuid.New()
	password := []byte("fixture-current-password")
	for _, scenario := range []string{"absent", "lost_ack", "same_password_foreign_operation", "own_marker_other_value", "stale_version"} {
		t.Run(scenario, func(t *testing.T) {
			state := &verificationKV{secretError: string(password)}
			expected := 0
			wantConflict := false
			switch scenario {
			case "lost_ack":
				state.loseWriteResponse = true
			case "same_password_foreign_operation":
				state.version = 1
				state.data = map[string]any{"username": "fixture-login", "password": string(password), "verification_operation_id": uuid.NewString()}
				wantConflict = true
			case "own_marker_other_value":
				state.version = 1
				state.data = map[string]any{"username": "fixture-login", "password": "foreign-fixture-password", "verification_operation_id": operationID.String()}
				wantConflict = true
			case "stale_version":
				state.version = 3
				state.data = map[string]any{"username": "fixture-login", "password": "foreign-fixture-password"}
				expected, wantConflict = 1, true
			}
			s := verificationTestService(t, state)
			beforeVersion := state.version
			version, err := s.ReconcileAccountCredentialCAS(t.Context(), accountID, operationID, "fixture-login", password, expected)
			if wantConflict {
				if !errors.Is(err, ErrCredentialVersionConflict) || state.version != beforeVersion {
					t.Fatalf("competing canonical value was accepted or overwritten: version=%d err=%v", version, err)
				}
			} else if err != nil || version != expected+1 {
				t.Fatalf("own write did not resolve: version=%d err=%v", version, err)
			}
			if err != nil && strings.Contains(err.Error(), string(password)) {
				t.Fatal("Vault response leaked a credential")
			}
			if !wantConflict {
				replay, err := s.ReconcileAccountCredentialCAS(t.Context(), accountID, operationID, "fixture-login", password, expected)
				if err != nil || replay != version || state.version != version {
					t.Fatalf("CAS retry wrote a second version: version=%d err=%v", replay, err)
				}
			}
		})
	}
}

func TestVerificationProofPinsOperationIdentityAndExactValue(t *testing.T) {
	accountID, operationID := uuid.New(), uuid.New()
	state := &verificationKV{loseWriteResponse: true}
	s := verificationTestService(t, state)
	password := []byte("fixture-current-password")
	v, err := s.PutVerificationProof(t.Context(), accountID, operationID, "fixture-login", password)
	if err != nil || v != 1 {
		t.Fatal("lost stage response did not recover its own write")
	}
	username, candidate, err := s.GetVerificationProof(t.Context(), accountID, operationID, v)
	defer clear(candidate)
	if err != nil || username != "fixture-login" || string(candidate) != string(password) {
		t.Fatal("could not read the pinned proof")
	}
	if _, _, err := s.GetVerificationProof(t.Context(), accountID, uuid.New(), v); err == nil {
		t.Fatal("a proof marker for another operation was accepted")
	}
	if _, err := s.PutVerificationProof(t.Context(), accountID, operationID, "fixture-login", []byte("different-fixture-password")); !errors.Is(err, ErrCredentialVersionConflict) {
		t.Fatal("stage retry replaced or accepted a different candidate")
	}
	if state.version != 1 {
		t.Fatal("stage retry wrote another version")
	}
	if err := s.DeleteVerificationProof(t.Context(), accountID, operationID); err != nil || state.version != 0 {
		t.Fatal("operation proof was not deleted")
	}
}

func TestVerificationNilDependenciesAndInvalidIDs(t *testing.T) {
	var s *Service
	ctx := context.Background()
	if _, err := s.CredentialVersion(ctx, "canonical"); !errors.Is(err, ErrVaultNotConfigured) {
		t.Fatal(err)
	}
	if _, err := s.PutVerificationProof(ctx, uuid.New(), uuid.New(), "fixture", []byte("fixture-password")); !errors.Is(err, ErrVaultNotConfigured) {
		t.Fatal(err)
	}
	if _, _, err := s.GetVerificationProof(ctx, uuid.New(), uuid.New(), 1); !errors.Is(err, ErrVaultNotConfigured) {
		t.Fatal(err)
	}
	if err := s.DeleteVerificationProof(ctx, uuid.New(), uuid.New()); !errors.Is(err, ErrVaultNotConfigured) {
		t.Fatal(err)
	}
	if _, err := s.ReconcileAccountCredentialCAS(ctx, uuid.New(), uuid.New(), "fixture", []byte("fixture-password"), 0); !errors.Is(err, ErrVaultNotConfigured) {
		t.Fatal(err)
	}
	s = verificationTestService(t, &verificationKV{})
	if _, err := s.ReconcileAccountCredentialCAS(ctx, uuid.Nil, uuid.New(), "fixture", []byte("fixture-password"), 0); err == nil {
		t.Fatal("nil account UUID was accepted")
	}
}

func TestVerificationCredentialScopeUsesExactAccountPrincipalAndEnvironment(t *testing.T) {
	account, principal := uuid.New(), uuid.New()
	own := "accounts/" + account.String() + "/credential"
	shared := "principals/" + principal.String() + "/environments/itest/credential"
	for _, test := range []struct {
		path, environment  string
		principal          *uuid.UUID
		reconcile, allowed bool
	}{
		{own, "itest", nil, true, true},
		{shared, "itest", &principal, false, true},
		{shared, "itest", &principal, true, false},
		{shared, "foreign-environment", &principal, false, false},
		{shared, "itest", nil, false, false},
		{"accounts/" + uuid.NewString() + "/credential", "itest", &principal, false, false},
		{"connections/fixture/admin", "itest", &principal, false, false},
	} {
		if got := VerificationPathAllowed(account, test.principal, test.environment, test.path, test.reconcile); got != test.allowed {
			t.Fatal("credential proof accepted a path outside its exact ownership scope")
		}
	}
}
