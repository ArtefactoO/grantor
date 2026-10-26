//go:build integration

package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/credentials"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

type managedLinkResponse struct {
	AccountID   uuid.UUID `json:"account_id"`
	PrincipalID uuid.UUID `json:"principal_id"`
	Environment string    `json:"environment"`
	OperationID uuid.UUID `json:"operation_id"`
}

func TestIntegrationManagedLinkGeneratedAndIdempotent(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	operator := session(auth.RoleOperator)
	conn := activeFakeConnection(t, env.pool)
	principal := createPrincipalRow(t, env.pool, "managed-link-generated")
	acct := findAccount(t, env.pool, conn.ID, "svc-a")
	path := "/api/v1/accounts/" + acct.ID.String() + "/link-and-manage"

	// Без credential первый shared secret создать нельзя.
	resp := env.do(t, http.MethodPost, path, map[string]any{"principal_id": principal.ID}, &operator, true)
	requireStatus(t, resp, http.StatusBadRequest)

	body := map[string]any{"principal_id": principal.ID, "credential": map[string]any{"mode": "generated"}}
	resp = env.do(t, http.MethodPost, path, body, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var out managedLinkResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.AccountID != acct.ID || out.PrincipalID != principal.ID || out.Environment != conn.Environment || out.OperationID == uuid.Nil {
		t.Fatalf("unexpected response: %+v", out)
	}

	// До worker account остаётся unmanaged/unlinked и не получает Vault ref.
	still, err := inventory.NewStore().GetAccount(t.Context(), env.pool, acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	if still.Ownership != inventory.OwnershipUnmanaged || still.PrincipalID != nil || still.VaultPath != "" || still.CredentialMode != nil {
		t.Fatalf("metadata changed before worker success: %+v", still)
	}
	op, err := operations.NewStore().Get(t.Context(), env.pool, out.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	var payload jobs.AccountPayload
	if err := json.Unmarshal(op.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.ManagedLinkPrincipalID == nil || *payload.ManagedLinkPrincipalID != principal.ID || payload.SharedCredentialPath == "" {
		t.Fatalf("unexpected operation payload: %s", op.Payload)
	}
	if strings.Contains(string(op.Payload), "password") {
		t.Fatalf("password field leaked into operation payload: %s", op.Payload)
	}
	var auditedPrincipalName string
	if err := env.pool.QueryRow(t.Context(), `
		select metadata->>'principal_display_name'
		from audit_events
		where operation_id = $1 and action = 'account.managed_link_requested'
	`, out.OperationID).Scan(&auditedPrincipalName); err != nil {
		t.Fatal(err)
	}
	if auditedPrincipalName != principal.DisplayName {
		t.Fatalf("audit principal_display_name = %q, want %q", auditedPrincipalName, principal.DisplayName)
	}

	// Повтор с тем же lifecycle возвращает ту же operation и полный 202 contract.
	resp = env.do(t, http.MethodPost, path, body, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var again managedLinkResponse
	if err := json.NewDecoder(resp.Body).Decode(&again); err != nil {
		t.Fatal(err)
	}
	if again != out {
		t.Fatalf("idempotent response = %+v, want %+v", again, out)
	}
}

func TestIntegrationManagedLinkReusesExistingCredentialWithoutChoice(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	operator := session(auth.RoleOperator)
	conn := activeFakeConnection(t, env.pool)
	principal := createPrincipalRow(t, env.pool, "managed-link-existing")
	acct := findAccount(t, env.pool, conn.ID, "svc-a")
	const existing = "existing-shared-secret-marker"
	credSvc := credentials.NewService(vaultClient, nil)
	sharedPath, created, err := credSvc.EnsurePrincipalCredential(t.Context(), principal.ID, conn.Environment, func() ([]byte, error) {
		return []byte(existing), nil
	})
	if err != nil || !created {
		t.Fatalf("prepare shared credential: created=%v err=%v", created, err)
	}

	resp := env.do(t, http.MethodPost, "/api/v1/accounts/"+acct.ID.String()+"/link-and-manage",
		map[string]any{"principal_id": principal.ID}, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	data, _, err := vaultClient.Get(t.Context(), sharedPath)
	if err != nil {
		t.Fatal(err)
	}
	if data["password"] != existing {
		t.Fatalf("existing shared credential was overwritten")
	}
}

func TestIntegrationManagedLinkProvidedDoesNotPersistPassword(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	operator := session(auth.RoleOperator)
	conn := activeFakeConnection(t, env.pool)
	principal := createPrincipalRow(t, env.pool, "managed-link-provided")
	acct := findAccount(t, env.pool, conn.ID, "svc-a")
	const password = "provided-secret-marker-123"
	body := map[string]any{"principal_id": principal.ID, "credential": map[string]any{"mode": "provided", "password": password}}
	resp := env.do(t, http.MethodPost, "/api/v1/accounts/"+acct.ID.String()+"/link-and-manage", body, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var out managedLinkResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	op, err := operations.NewStore().Get(t.Context(), env.pool, out.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(op.Payload), password) {
		t.Fatal("provided password leaked into operation payload")
	}
	var auditLeak bool
	if err := env.pool.QueryRow(t.Context(), `select exists(select 1 from audit_events where metadata::text like '%' || $1 || '%')`, password).Scan(&auditLeak); err != nil {
		t.Fatal(err)
	}
	if auditLeak {
		t.Fatal("provided password leaked into audit")
	}
}

func TestIntegrationManagedLinkRejectsHiddenRelinkAndGenericAdopt(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	operator := session(auth.RoleOperator)
	conn := activeFakeConnection(t, env.pool)
	first := createPrincipalRow(t, env.pool, "managed-link-first")
	second := createPrincipalRow(t, env.pool, "managed-link-second")
	acct := findAccount(t, env.pool, conn.ID, "svc-a")
	if _, err := inventory.NewStore().LinkAccountPrincipal(t.Context(), env.pool, acct.ID, &first.ID); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/accounts/" + acct.ID.String()
	resp := env.do(t, http.MethodPost, path+"/link-and-manage", map[string]any{
		"principal_id": second.ID, "credential": map[string]any{"mode": "generated"},
	}, &operator, true)
	requireStatus(t, resp, http.StatusConflict)
	resp = env.do(t, http.MethodPost, path+"/adopt", map[string]any{"mode": "generate"}, &operator, true)
	requireStatus(t, resp, http.StatusConflict)
}
