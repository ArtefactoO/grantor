//go:build integration

package credentials

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
)

type verificationPolicyFixture struct {
	address string
	mount   string
	root    string
	client  *http.Client
	vault   *vault.Client
}

func newVerificationPolicyFixture(t *testing.T) *verificationPolicyFixture {
	t.Helper()
	address, root := os.Getenv("GRANTOR_TEST_VAULT_ADDR"), os.Getenv("GRANTOR_TEST_VAULT_TOKEN")
	if address == "" || root == "" {
		t.Skip("set GRANTOR_TEST_VAULT_ADDR and GRANTOR_TEST_VAULT_TOKEN for restricted-policy integration tests")
	}
	mount := os.Getenv("GRANTOR_TEST_VAULT_MOUNT")
	if mount == "" {
		mount = "secret"
	}
	client, err := vault.New(vault.Config{Address: address, Token: root, Mount: mount})
	if err != nil {
		t.Fatal("could not configure the disposable Vault fixture")
	}
	return &verificationPolicyFixture{address: strings.TrimRight(address, "/"), mount: mount, root: root,
		client: &http.Client{Timeout: 10 * time.Second}, vault: client}
}

// Never include response bodies or headers in test failures: token issuance
// and credential reads use this same helper.
func (f *verificationPolicyFixture) request(ctx context.Context, token, method, path string, body any) (int, []byte, error) {
	var input io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return 0, nil, errors.New("fixture request encoding failed")
		}
		defer clear(data)
		input = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, f.address+"/v1/"+path, input)
	if err != nil {
		return 0, nil, errors.New("fixture request creation failed")
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")
	response, err := f.client.Do(req)
	if err != nil {
		return 0, nil, errors.New("fixture Vault request failed")
	}
	defer response.Body.Close() //nolint:errcheck
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return response.StatusCode, nil, errors.New("fixture Vault response unavailable")
	}
	return response.StatusCode, data, nil
}

func (f *verificationPolicyFixture) requireRequest(t *testing.T, token, method, path string, body any, want int) []byte {
	t.Helper()
	status, response, err := f.request(t.Context(), token, method, path, body)
	if err != nil || status != want {
		clear(response)
		t.Fatalf("disposable Vault %s %s: HTTP %d, want %d", method, path, status, want)
	}
	return response
}

func verificationRestrictedPolicy(mount string, worker bool) string {
	proofCaps := `"create", "read"`
	if worker {
		proofCaps = `"read"`
	}
	return fmt.Sprintf(`
path "%[1]s/data/accounts/+/verification-proofs/+" {
  capabilities = [%[2]s]
}
path "%[1]s/metadata/accounts/+/verification-proofs/+" {
  capabilities = ["delete"]
}
path "%[1]s/data/accounts/+/credential" {
  capabilities = ["create", "update", "read"]
}
path "%[1]s/metadata/accounts/+/credential" {
  capabilities = ["read"]
}
path "%[1]s/data/principals/+/environments/+/credential" {
  capabilities = ["read"]
}
path "%[1]s/metadata/principals/+/environments/+/credential" {
  capabilities = ["read"]
}
`, mount, proofCaps)
}

func (f *verificationPolicyFixture) restrictedToken(t *testing.T, worker bool) (string, *vault.Client) {
	t.Helper()
	name := "grantor-verification-policy-test-" + uuid.NewString()
	policyPath := "sys/policies/acl/" + name
	response := f.requireRequest(t, f.root, http.MethodPut, policyPath, map[string]any{"policy": verificationRestrictedPolicy(f.mount, worker)}, http.StatusNoContent)
	clear(response)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		status, response, err := f.request(ctx, f.root, http.MethodDelete, policyPath, nil)
		clear(response)
		if err != nil || status != http.StatusNoContent {
			t.Error("could not delete the disposable test policy")
		}
	})
	response = f.requireRequest(t, f.root, http.MethodPost, "auth/token/create", map[string]any{
		"policies": []string{name}, "no_default_policy": true, "ttl": "5m", "explicit_max_ttl": "5m", "renewable": false,
	}, http.StatusOK)
	defer clear(response)
	var issued struct {
		Auth struct {
			Token string `json:"client_token"`
		} `json:"auth"`
	}
	if json.Unmarshal(response, &issued) != nil || issued.Auth.Token == "" {
		t.Fatal("Vault did not issue the restricted fixture token")
	}
	token := issued.Auth.Token
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		status, response, err := f.request(ctx, f.root, http.MethodPost, "auth/token/revoke", map[string]any{"token": token})
		clear(response)
		if err != nil || status != http.StatusNoContent {
			t.Error("could not revoke the disposable fixture token")
		}
	})
	client, err := vault.New(vault.Config{Address: f.address, Token: token, Mount: f.mount})
	if err != nil {
		t.Fatal("could not configure the restricted fixture client")
	}
	return token, client
}

func (f *verificationPolicyFixture) trackSecret(t *testing.T, path string) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := f.vault.DeleteMetadata(ctx, path); err != nil {
			t.Error("could not delete a disposable fixture secret")
		}
	})
}

func TestVerificationRestrictedVaultPoliciesCoverStageRetryProofCASAndCleanup(t *testing.T) {
	f := newVerificationPolicyFixture(t)
	apiToken, apiVault := f.restrictedToken(t, false)
	workerToken, workerVault := f.restrictedToken(t, true)
	apiService, workerService := NewService(apiVault, nil), NewService(workerVault, nil)
	account, operation := uuid.New(), uuid.New()
	proofPath := verificationProofPath(account, operation)
	f.trackSecret(t, proofPath)
	password := []byte("disposable-verification-policy-password-" + uuid.NewString())
	defer clear(password)
	username := "verification-policy-login"

	version, err := apiService.PutVerificationProof(t.Context(), account, operation, username, password)
	if err != nil || version != 1 {
		t.Fatal("API create+read policy could not stage its first proof")
	}
	// The second CAS0 is forbidden without update. PutVerificationProof must
	// recover the immutable first version using read alone.
	replay, err := apiService.PutVerificationProof(t.Context(), account, operation, username, password)
	if err != nil || replay != 1 {
		t.Fatal("API stage retry required update instead of its exact readback")
	}
	if _, err := apiService.PutVerificationProof(t.Context(), account, operation, username, []byte("disposable-different-candidate")); !errors.Is(err, ErrCredentialVersionConflict) {
		t.Fatal("API stage retry accepted a different candidate")
	}
	data, current, err := f.vault.Get(t.Context(), proofPath)
	if err != nil || current != 1 || data["password"] != string(password) {
		t.Fatal("API stage retry replaced the staged proof")
	}

	for _, token := range []string{apiToken, workerToken} {
		response := f.requireRequest(t, token, http.MethodGet, f.mount+"/metadata/"+proofPath, nil, http.StatusForbidden)
		clear(response)
		response = f.requireRequest(t, token, http.MethodDelete, f.mount+"/data/"+proofPath, nil, http.StatusForbidden)
		clear(response)
		response = f.requireRequest(t, token, http.MethodPost, f.mount+"/data/"+proofPath,
			map[string]any{"data": map[string]any{"password": "disposable-unapproved-overwrite"}, "options": map[string]any{"cas": 1}}, http.StatusForbidden)
		clear(response)
	}
	gotUsername, candidate, err := workerService.GetVerificationProof(t.Context(), account, operation, 1)
	if err != nil || gotUsername != username || !bytes.Equal(candidate, password) {
		clear(candidate)
		t.Fatal("worker read-only proof policy could not read the pinned candidate")
	}
	clear(candidate)
	otherOperation := uuid.New()
	otherProof := verificationProofPath(account, otherOperation)
	f.trackSecret(t, otherProof)
	response := f.requireRequest(t, workerToken, http.MethodPost, f.mount+"/data/"+otherProof,
		map[string]any{"data": map[string]any{"password": "disposable-unapproved-create"}, "options": map[string]any{"cas": 0}}, http.StatusForbidden)
	clear(response)

	canonical, _ := vault.AccountCredentialPath(account.String())
	f.trackSecret(t, canonical)
	if _, err := f.vault.Put(t.Context(), canonical, map[string]any{"username": username, "password": "disposable-old-canonical"}); err != nil {
		t.Fatal("could not create the isolated canonical fixture")
	}
	if metadataVersion, present, err := apiService.CredentialMetadata(t.Context(), canonical); err != nil || !present || metadataVersion != 1 {
		t.Fatal("API canonical metadata-read policy could not pin its expected version")
	}
	version, err = workerService.ReconcileAccountCredentialCAS(t.Context(), account, operation, username, password, 1)
	if err != nil || version != 2 {
		t.Fatal("worker policy could not perform canonical CAS")
	}
	version, err = workerService.ReconcileAccountCredentialCAS(t.Context(), account, operation, username, password, 1)
	if err != nil || version != 2 {
		t.Fatal("worker policy could not recover its own canonical CAS by exact readback")
	}
	if _, err := f.vault.Put(t.Context(), canonical, map[string]any{"username": username, "password": string(password), "verification_operation_id": uuid.NewString()}); err != nil {
		t.Fatal("could not create a competing fixture write")
	}
	if _, err := workerService.ReconcileAccountCredentialCAS(t.Context(), account, operation, username, password, 1); !errors.Is(err, ErrCredentialVersionConflict) {
		t.Fatal("restricted worker adopted a competing same-value canonical write")
	}
	if _, current, err := f.vault.Get(t.Context(), canonical); err != nil || current != 3 {
		t.Fatal("canonical CAS conflict modified the competing version")
	}

	absentAccount := uuid.New()
	absentPath, _ := vault.AccountCredentialPath(absentAccount.String())
	f.trackSecret(t, absentPath)
	if version, present, err := apiService.CredentialMetadata(t.Context(), absentPath); err != nil || present || version != 0 {
		t.Fatal("restricted API could not distinguish an absent canonical path")
	}
	if version, err := workerService.ReconcileAccountCredentialCAS(t.Context(), absentAccount, uuid.New(), username, password, 0); err != nil || version != 1 {
		t.Fatal("worker create capability could not reconcile an absent canonical path")
	}

	principal := uuid.New()
	shared, _ := vault.PrincipalEnvironmentCredentialPath(principal.String(), "verification-policy-test")
	f.trackSecret(t, shared)
	if _, err := f.vault.Put(t.Context(), shared, map[string]any{"password": string(password)}); err != nil {
		t.Fatal("could not create the isolated shared credential")
	}
	for _, service := range []*Service{apiService, workerService} {
		if version, present, err := service.CredentialMetadata(t.Context(), shared); err != nil || !present || version != 1 {
			t.Fatal("shared metadata-read policy did not admit the current principal/environment version")
		}
	}
	gotUsername, candidate, err = workerService.GetAccountCredentialVersion(t.Context(), shared, username, 1)
	if err != nil || gotUsername != username || !bytes.Equal(candidate, password) {
		clear(candidate)
		t.Fatal("shared read policy could not read the pinned password-only credential")
	}
	clear(candidate)

	if err := workerService.DeleteVerificationProof(t.Context(), account, operation); err != nil {
		t.Fatal("worker metadata-delete policy could not clean its completed proof")
	}
	if err := workerService.DeleteVerificationProof(t.Context(), account, operation); err != nil {
		t.Fatal("worker cleanup required metadata-read or failed on retry")
	}
	if _, err := f.vault.Metadata(t.Context(), proofPath); !errors.Is(err, vault.ErrNotFound) {
		t.Fatal("worker cleanup retained proof metadata")
	}
	if _, err := apiService.PutVerificationProof(t.Context(), account, otherOperation, username, password); err != nil {
		t.Fatal("API could not create the rollback fixture proof")
	}
	if err := apiService.DeleteVerificationProof(t.Context(), account, otherOperation); err != nil {
		t.Fatal("API metadata-delete policy could not clean its rolled-back proof")
	}
	if _, err := f.vault.Metadata(t.Context(), otherProof); !errors.Is(err, vault.ErrNotFound) {
		t.Fatal("API rollback cleanup retained proof metadata")
	}
}

func TestVerificationRestrictedVaultPoliciesDenyForeignNamespaces(t *testing.T) {
	f := newVerificationPolicyFixture(t)
	apiToken, _ := f.restrictedToken(t, false)
	workerToken, _ := f.restrictedToken(t, true)
	id := uuid.NewString()
	for _, path := range []string{
		"connections/" + id + "/admin",
		"connections/" + id + "/admin-changes/" + uuid.NewString(),
		"onboarding/sources/" + id,
		"arbitrary/" + id,
		"accounts/" + id + "/verification-proofs/" + uuid.NewString() + "/extra",
		"principals/" + id + "/admin",
	} {
		f.trackSecret(t, path)
		if _, err := f.vault.Put(t.Context(), path, map[string]any{"password": "disposable-foreign-secret"}); err != nil {
			t.Fatal("could not create a foreign-namespace fixture")
		}
		for _, token := range []string{apiToken, workerToken} {
			for _, request := range []struct{ method, prefix string }{
				{http.MethodGet, "data/"}, {http.MethodGet, "metadata/"}, {http.MethodDelete, "metadata/"},
			} {
				response := f.requireRequest(t, token, request.method, f.mount+"/"+request.prefix+path, nil, http.StatusForbidden)
				clear(response)
			}
			response := f.requireRequest(t, token, http.MethodPost, f.mount+"/data/"+path,
				map[string]any{"data": map[string]any{"password": "disposable-unapproved-foreign-write"}}, http.StatusForbidden)
			clear(response)
		}
	}
}
