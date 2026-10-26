//go:build integration

package api_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/connectionregistration"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/policy"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
)

type onboardingReceipt struct {
	ID           uuid.UUID `json:"id"`
	ConnectionID uuid.UUID `json:"connection_id"`
	OperationID  uuid.UUID `json:"operation_id"`
	Phase        string    `json:"phase"`
	Status       string    `json:"status"`
	Replayed     bool      `json:"replayed"`
}

func issueOnboardingServiceToken(t *testing.T, env *testEnv, principalID, environment string, permission, scope bool) string {
	t.Helper()
	admin := session(auth.RoleAdmin)
	if scope {
		requireStatus(t, env.do(t, http.MethodPost, "/api/v1/scope-policies", map[string]any{"subject_kind": policy.SubjectPrincipal, "subject": principalID, "environment": environment}, &admin, true), http.StatusCreated)
	}
	body := map[string]any{"name": "onboarding-fixture"}
	if permission {
		body["permissions"] = []string{"connections:create"}
	}
	resp := env.do(t, http.MethodPost, "/api/v1/principals/"+principalID+"/tokens", body, &admin, true)
	requireStatus(t, resp, http.StatusCreated)
	var issued struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(readBody(t, resp), &issued); err != nil {
		t.Fatal(err)
	}
	return issued.Token
}

func createOnboardingSource(t *testing.T, env *testEnv, principalID, environment string) uuid.UUID {
	t.Helper()
	admin := session(auth.RoleAdmin)
	resp := env.do(t, http.MethodPost, "/api/v1/connection-credential-sources", map[string]any{"name": "fixture", "owner_type": "service", "owner_id": principalID, "environment": environment, "username": "fixture-admin", "password": "synthetic-onboarding-fixture", "engine": "fake", "endpoints": []string{"10.42.0.1:5432"}}, &admin, true)
	requireStatus(t, resp, http.StatusCreated)
	raw := readBody(t, resp)
	if strings.Contains(string(raw), "synthetic-onboarding-fixture") || strings.Contains(string(raw), "fixture-admin") {
		t.Fatal("source response contains credential values")
	}
	var source struct {
		ID      uuid.UUID `json:"id"`
		Version int       `json:"version"`
	}
	if err := json.Unmarshal(raw, &source); err != nil || source.Version != 1 {
		t.Fatalf("invalid source metadata err=%v version=%d", err, source.Version)
	}
	return source.ID
}

func onboardingRequest(environment string, sourceID uuid.UUID) map[string]any {
	return map[string]any{"registration_key": "cluster:" + uuid.NewString(), "request_id": uuid.NewString(), "display_name": "fixture-cluster", "engine": "fake", "environment": environment, "endpoints": []string{"10.42.0.1:5432"}, "credential_source_id": sourceID, "credential_source_version": 1}
}

func readOnboardingReceipt(t *testing.T, resp *http.Response) onboardingReceipt {
	t.Helper()
	var receipt onboardingReceipt
	if err := json.Unmarshal(readBody(t, resp), &receipt); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func TestIntegrationConnectionRegistrationAuthenticatedScopedReplay(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newScopeTestEnv(t, vaultClient, policy.EnforcementEnforce)
	admin := session(auth.RoleAdmin)
	principalID := createPrincipal(t, env, admin, "service")
	environment := "registration-" + uuid.NewString()
	token := issueOnboardingServiceToken(t, env, principalID, environment, true, true)
	sourceID := createOnboardingSource(t, env, principalID, environment)
	body := onboardingRequest(environment, sourceID)
	resp := env.doBearer(t, http.MethodPost, "/api/v1/connection-registrations", body, token)
	requireStatus(t, resp, http.StatusAccepted)
	first := readOnboardingReceipt(t, resp)
	if first.Phase != "registered" || first.Status != "pending" || first.ID == uuid.Nil || first.ConnectionID == uuid.Nil || first.OperationID == uuid.Nil {
		t.Fatal("registration reported invalid receipt or premature readiness")
	}
	conn, err := connections.NewStore().Get(t.Context(), env.pool, first.ConnectionID)
	if err != nil {
		t.Fatal(err)
	}
	if conn.Status != connections.StatusDiscovering || conn.LastDiscoveryAt != nil {
		t.Fatal("registration pretended discovery completed")
	}
	resp = env.doBearer(t, http.MethodPost, "/api/v1/connection-registrations", body, token)
	requireStatus(t, resp, http.StatusAccepted)
	replay := readOnboardingReceipt(t, resp)
	if !replay.Replayed || replay.ID != first.ID || replay.ConnectionID != first.ConnectionID || replay.OperationID != first.OperationID {
		t.Fatal("request replay changed durable identities")
	}
	body["request_id"] = uuid.NewString()
	resp = env.doBearer(t, http.MethodPost, "/api/v1/connection-registrations", body, token)
	requireStatus(t, resp, http.StatusAccepted)
	alias := readOnboardingReceipt(t, resp)
	if alias.ID != first.ID {
		t.Fatal("stable registration key created duplicate")
	}
	body["display_name"] = "changed"
	requireStatus(t, env.doBearer(t, http.MethodPost, "/api/v1/connection-registrations", body, token), http.StatusConflict)
	body["display_name"] = "fixture-cluster"
	body["credential_source_version"] = 2
	requireStatus(t, env.doBearer(t, http.MethodPost, "/api/v1/connection-registrations", body, token), http.StatusConflict)
	body["credential_source_version"] = 1
	path, _ := vault.ConnectionAdminPath(first.ConnectionID.String())
	stored, version, err := vaultClient.Get(t.Context(), path)
	if err != nil || version != 1 || stored["username"] != "fixture-admin" {
		t.Fatal("canonical credential was not pinned once")
	}
	requireStatus(t, env.doBearer(t, http.MethodGet, "/api/v1/connection-registrations/"+first.ID.String(), nil, token), http.StatusOK)
	for _, table := range []string{"connection_registrations", "operations", "audit_events"} {
		var leaked bool
		if err := env.pool.QueryRow(t.Context(), `select exists(select 1 from `+table+` x where to_jsonb(x)::text like '%synthetic-onboarding-fixture%')`).Scan(&leaked); err != nil {
			t.Fatal(err)
		}
		if leaked {
			t.Fatalf("credential leaked into %s", table)
		}
	}
	// Revoking a source does not rotate or delete the canonical credential of
	// a completed connection, and lost-response replay remains read-only.
	requireStatus(t, env.do(t, http.MethodDelete, "/api/v1/connection-credential-sources/"+sourceID.String(), nil, &admin, true), http.StatusOK)
	requireStatus(t, env.doBearer(t, http.MethodPost, "/api/v1/connection-registrations", body, token), http.StatusAccepted)
	if _, _, err := vaultClient.Get(t.Context(), path); err != nil {
		t.Fatal("source revocation removed canonical credential")
	}
	requireStatus(t, env.doBearer(t, http.MethodDelete, "/api/v1/connection-registrations/"+first.ID.String(), nil, token), http.StatusConflict)
	otherPrincipal := createPrincipal(t, env, admin, "service")
	otherToken := issueOnboardingServiceToken(t, env, otherPrincipal, environment, true, true)
	requireStatus(t, env.doBearer(t, http.MethodGet, "/api/v1/connection-registrations/"+first.ID.String(), nil, otherToken), http.StatusForbidden)
	requireStatus(t, env.doBearer(t, http.MethodDelete, "/api/v1/connection-registrations/"+first.ID.String(), nil, otherToken), http.StatusForbidden)
}

func TestIntegrationConnectionRegistrationPermissionAndSourceIsolation(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	admin := session(auth.RoleAdmin)
	principalID := createPrincipal(t, env, admin, "service")
	environment := "isolated-" + uuid.NewString()
	sourceID := createOnboardingSource(t, env, principalID, environment)
	// Machine onboarding is scope-enforced even when the old dev flag is off.
	noScope := issueOnboardingServiceToken(t, env, principalID, environment, true, false)
	body := onboardingRequest(environment, sourceID)
	requireStatus(t, env.doBearer(t, http.MethodPost, "/api/v1/connection-registrations", body, noScope), http.StatusForbidden)
	noPermission := issueOnboardingServiceToken(t, env, principalID, environment, false, true)
	requireStatus(t, env.doBearer(t, http.MethodPost, "/api/v1/connection-registrations", body, noPermission), http.StatusForbidden)
	requireStatus(t, env.doBearer(t, http.MethodPost, "/api/v1/connections", body, noScope), http.StatusForbidden)
	otherPrincipal := createPrincipal(t, env, admin, "service")
	otherToken := issueOnboardingServiceToken(t, env, otherPrincipal, environment, true, true)
	requireStatus(t, env.doBearer(t, http.MethodPost, "/api/v1/connection-registrations", body, otherToken), http.StatusForbidden)
	// The original owner cannot redirect the approved credential to a new
	// target, change its transport or substitute execution/discovery settings.
	for _, change := range []map[string]any{
		{"endpoints": []string{"10.42.0.2:5432"}},
		{"execution_mode": "connector"},
		{"tls_config": map[string]any{"mode": "require"}},
		{"discovery_config": map[string]any{"database": "other"}},
	} {
		changed := onboardingRequest(environment, sourceID)
		for field, value := range change {
			changed[field] = value
		}
		requireStatus(t, env.doBearer(t, http.MethodPost, "/api/v1/connection-registrations", changed, noScope), http.StatusForbidden)
	}
	body["vault_admin_path"] = "principals/foreign/credential"
	requireStatus(t, env.doBearer(t, http.MethodPost, "/api/v1/connection-registrations", body, otherToken), http.StatusBadRequest)
	requireStatus(t, env.doBearer(t, http.MethodPost, "/api/v1/connection-credential-sources", nil, otherToken), http.StatusForbidden)
	requireStatus(t, env.do(t, http.MethodPost, "/api/v1/connection-registrations", body, &admin, true), http.StatusForbidden)
}

func TestIntegrationConnectionRegistrationVaultFailureCancellation(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newScopeTestEnv(t, vaultClient, policy.EnforcementEnforce)
	admin := session(auth.RoleAdmin)
	principalID := createPrincipal(t, env, admin, "service")
	environment := "cancel-" + uuid.NewString()
	token := issueOnboardingServiceToken(t, env, principalID, environment, true, true)
	sourceID := createOnboardingSource(t, env, principalID, environment)
	if err := vaultClient.DestroyVersions(t.Context(), connectionregistration.SourcePath(sourceID), []int{1}); err != nil {
		t.Fatal(err)
	}
	body := onboardingRequest(environment, sourceID)
	resp := env.doBearer(t, http.MethodPost, "/api/v1/connection-registrations", body, token)
	requireStatus(t, resp, http.StatusBadGateway)
	var failure struct {
		RegistrationID uuid.UUID `json:"registration_id"`
	}
	if err := json.Unmarshal(readBody(t, resp), &failure); err != nil || failure.RegistrationID == uuid.Nil {
		t.Fatal("Vault failure lost durable registration identity")
	}
	resp = env.doBearer(t, http.MethodDelete, "/api/v1/connection-registrations/"+failure.RegistrationID.String(), nil, token)
	requireStatus(t, resp, http.StatusOK)
	cancelled := readOnboardingReceipt(t, resp)
	if cancelled.Phase != "cancelled" {
		t.Fatal("cancelled receipt is not durable")
	}
	requireStatus(t, env.doBearer(t, http.MethodDelete, "/api/v1/connection-registrations/"+failure.RegistrationID.String(), nil, token), http.StatusOK)
	requireStatus(t, env.doBearer(t, http.MethodPost, "/api/v1/connection-registrations", body, token), http.StatusConflict)
	var exists bool
	if err := env.pool.QueryRow(t.Context(), `select exists(select 1 from connections where id=$1)`, cancelled.ConnectionID).Scan(&exists); err != nil || exists {
		t.Fatal("cancelled registration created a connection")
	}
}

func TestIntegrationConcurrentConnectionRegistrationHasOneConnection(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newScopeTestEnv(t, vaultClient, policy.EnforcementEnforce)
	admin := session(auth.RoleAdmin)
	principalID := createPrincipal(t, env, admin, "service")
	environment := "race-" + uuid.NewString()
	token := issueOnboardingServiceToken(t, env, principalID, environment, true, true)
	sourceID := createOnboardingSource(t, env, principalID, environment)
	body := onboardingRequest(environment, sourceID)
	results := make(chan onboardingReceipt, 4)
	var group sync.WaitGroup
	for range 4 {
		group.Go(func() {
			resp := env.doBearer(t, http.MethodPost, "/api/v1/connection-registrations", body, token)
			requireStatus(t, resp, http.StatusAccepted)
			results <- readOnboardingReceipt(t, resp)
		})
	}
	group.Wait()
	close(results)
	var first onboardingReceipt
	for r := range results {
		if first.ID == uuid.Nil {
			first = r
		}
		if first.ID != r.ID || first.ConnectionID != r.ConnectionID || first.OperationID != r.OperationID {
			t.Fatal("concurrent HTTP retries created duplicate identities")
		}
	}
	var count int
	if err := env.pool.QueryRow(t.Context(), `select count(*) from operations where connection_id=$1`, first.ConnectionID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("discovery operations count=%d err=%v", count, err)
	}
}

func TestIntegrationConnectionRegistrationRecoversLostVaultAcknowledgement(t *testing.T) {
	// The real KV write succeeds, but its acknowledgement is replaced with a
	// transport failure. Recovery must prove the existing value in memory and
	// must not create a second version or another registration.
	_ = newTestVault(t)
	upstream, err := url.Parse(os.Getenv("GRANTOR_TEST_VAULT_ADDR"))
	if err != nil {
		t.Fatal("invalid test Vault address")
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	var discarded atomic.Bool
	proxy.ModifyResponse = func(resp *http.Response) error {
		if resp.StatusCode == http.StatusOK && resp.Request.Method != http.MethodGet &&
			strings.Contains(resp.Request.URL.Path, "/data/connections/") && discarded.CompareAndSwap(false, true) {
			if err := resp.Body.Close(); err != nil {
				return err
			}
			body := `{"errors":["synthetic lost acknowledgement"]}`
			resp.StatusCode = http.StatusBadGateway
			resp.Status = "502 Bad Gateway"
			resp.Body = io.NopCloser(strings.NewReader(body))
			resp.ContentLength = int64(len(body))
			resp.Header.Del("Content-Length")
		}
		return nil
	}
	server := httptest.NewServer(proxy)
	t.Cleanup(server.Close)
	mount := os.Getenv("GRANTOR_TEST_VAULT_MOUNT")
	if mount == "" {
		mount = "secret"
	}
	vaultClient, err := vault.New(vault.Config{Address: server.URL, Token: os.Getenv("GRANTOR_TEST_VAULT_TOKEN"), Mount: mount})
	if err != nil {
		t.Fatal("create proxied test Vault client")
	}
	env := newScopeTestEnv(t, vaultClient, policy.EnforcementEnforce)
	admin := session(auth.RoleAdmin)
	principalID := createPrincipal(t, env, admin, "service")
	environment := "lost-vault-ack-" + uuid.NewString()
	token := issueOnboardingServiceToken(t, env, principalID, environment, true, true)
	sourceID := createOnboardingSource(t, env, principalID, environment)
	resp := env.doBearer(t, http.MethodPost, "/api/v1/connection-registrations", onboardingRequest(environment, sourceID), token)
	requireStatus(t, resp, http.StatusAccepted)
	receipt := readOnboardingReceipt(t, resp)
	if !discarded.Load() {
		t.Fatal("test did not discard a successful Vault acknowledgement")
	}
	path, _ := vault.ConnectionAdminPath(receipt.ConnectionID.String())
	_, version, err := vaultClient.Get(t.Context(), path)
	if err != nil || version != 1 {
		t.Fatalf("lost acknowledgement created another canonical version: version=%d", version)
	}
}

func TestIntegrationConnectionRegistrationRecoversAfterMetadataRollback(t *testing.T) {
	vaultClient := newTestVault(t)
	dispatcher := &countingDispatcher{err: errors.New("synthetic enqueue failure")}
	env := buildTestEnv(t, testEnvOpts{vault: vaultClient, enforcement: policy.EnforcementEnforce, dispatcher: dispatcher})
	admin := session(auth.RoleAdmin)
	principalID := createPrincipal(t, env, admin, "service")
	environment := "rollback-" + uuid.NewString()
	token := issueOnboardingServiceToken(t, env, principalID, environment, true, true)
	sourceID := createOnboardingSource(t, env, principalID, environment)
	body := onboardingRequest(environment, sourceID)
	requireStatus(t, env.doBearer(t, http.MethodPost, "/api/v1/connection-registrations", body, token), http.StatusInternalServerError)
	store := connectionregistration.NewStore()
	regs, err := store.List(t.Context(), env.pool, connectionregistration.Owner{Type: "service", ID: uuid.MustParse(principalID)}, 10, 0)
	if err != nil || len(regs) != 1 || regs[0].Phase != "preparing" {
		t.Fatal("metadata failure lost the recoverable reservation")
	}
	reserved := regs[0]
	if _, err := connections.NewStore().Get(t.Context(), env.pool, reserved.ConnectionID); !errors.Is(err, connections.ErrNotFound) {
		t.Fatal("connection committed without a discovery job")
	}
	if _, err := operations.NewStore().Get(t.Context(), env.pool, reserved.OperationID); !errors.Is(err, operations.ErrNotFound) {
		t.Fatal("operation committed without its enqueue")
	}
	path, _ := vault.ConnectionAdminPath(reserved.ConnectionID.String())
	if _, version, err := vaultClient.Get(t.Context(), path); err != nil || version != 1 {
		t.Fatal("durably addressed canonical credential is missing after rollback")
	}
	dispatcher.err = nil
	resp := env.doBearer(t, http.MethodPost, "/api/v1/connection-registrations", body, token)
	requireStatus(t, resp, http.StatusAccepted)
	receipt := readOnboardingReceipt(t, resp)
	if receipt.ID != reserved.ID || receipt.ConnectionID != reserved.ConnectionID || receipt.OperationID != reserved.OperationID || !receipt.Replayed {
		t.Fatal("retry replaced reserved identities after metadata rollback")
	}
	if _, version, err := vaultClient.Get(t.Context(), path); err != nil || version != 1 {
		t.Fatal("retry replaced the canonical credential after metadata rollback")
	}
}

func TestIntegrationConnectionRegistrationAdminCleanupAfterOwnerDisabled(t *testing.T) {
	vaultClient := newTestVault(t)
	env := buildTestEnv(t, testEnvOpts{vault: vaultClient, enforcement: policy.EnforcementEnforce, dispatcher: &countingDispatcher{err: errors.New("synthetic enqueue failure")}})
	admin := session(auth.RoleAdmin)
	principalID := createPrincipal(t, env, admin, "service")
	environment := "disabled-cleanup-" + uuid.NewString()
	token := issueOnboardingServiceToken(t, env, principalID, environment, true, true)
	sourceID := createOnboardingSource(t, env, principalID, environment)
	requireStatus(t, env.doBearer(t, http.MethodPost, "/api/v1/connection-registrations", onboardingRequest(environment, sourceID), token), http.StatusInternalServerError)
	regs, err := connectionregistration.NewStore().List(t.Context(), env.pool, connectionregistration.Owner{Type: "service", ID: uuid.MustParse(principalID)}, 10, 0)
	if err != nil || len(regs) != 1 {
		t.Fatal("missing pending registration")
	}
	reserved := regs[0]
	requireStatus(t, env.do(t, http.MethodPost, "/api/v1/principals/"+principalID+"/disable", nil, &admin, true), http.StatusOK)
	requireStatus(t, env.doBearer(t, http.MethodDelete, "/api/v1/connection-registrations/"+reserved.ID.String(), nil, token), http.StatusUnauthorized)
	requireStatus(t, env.do(t, http.MethodGet, "/api/v1/connection-registrations/"+reserved.ID.String(), nil, &admin, false), http.StatusOK)
	requireStatus(t, env.do(t, http.MethodGet, "/api/v1/connection-registrations", nil, &admin, false), http.StatusOK)
	requireStatus(t, env.do(t, http.MethodGet, "/api/v1/connection-credential-sources", nil, &admin, false), http.StatusOK)
	resp := env.do(t, http.MethodDelete, "/api/v1/connection-registrations/"+reserved.ID.String(), nil, &admin, true)
	requireStatus(t, resp, http.StatusOK)
	if receipt := readOnboardingReceipt(t, resp); receipt.Phase != "cancelled" {
		t.Fatal("admin did not finish disabled owner's cleanup")
	}
	path, _ := vault.ConnectionAdminPath(reserved.ConnectionID.String())
	if _, _, err := vaultClient.Get(t.Context(), path); !errors.Is(err, vault.ErrNotFound) {
		t.Fatal("admin cancellation left reserved canonical credential")
	}
	requireStatus(t, env.do(t, http.MethodDelete, "/api/v1/connection-credential-sources/"+sourceID.String(), nil, &admin, true), http.StatusOK)
	if _, _, err := vaultClient.Get(t.Context(), connectionregistration.SourcePath(sourceID)); !errors.Is(err, vault.ErrNotFound) {
		t.Fatal("disabled owner's source could not be cleaned up")
	}
}

func TestIntegrationConnectionRegistrationAdminAPIKeyCannotManageForeignReceipts(t *testing.T) {
	env, _, issuer := newPersonalAPIKeyEnv(t)
	admin := auth.Session{Issuer: issuer, Subject: "admin-" + uuid.NewString(), Username: "admin", Email: "admin@example.test", Role: auth.RoleAdmin, AuthenticatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour)}
	resp := env.do(t, http.MethodPost, "/api/v1/me/api-keys", map[string]any{"name": "admin-fixture", "role": "admin", "expires_at": time.Now().Add(10 * time.Minute)}, &admin, true)
	requireStatus(t, resp, http.StatusCreated)
	var key struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(readBody(t, resp), &key); err != nil {
		t.Fatal(err)
	}
	store := connectionregistration.NewStore()
	foreignOwner := connectionregistration.Owner{Type: "service", ID: uuid.New()}
	source, err := store.CreateSource(t.Context(), env.pool, connectionregistration.Source{ID: uuid.New(), Name: "foreign-source", Owner: foreignOwner, Environment: "foreign", TargetSpec: []byte(`{"engine":"fake"}`)})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := env.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context()) //nolint:errcheck
	if err := store.LockOwner(t.Context(), tx, foreignOwner); err != nil {
		t.Fatal(err)
	}
	reg, _, err := store.Reserve(t.Context(), tx, connectionregistration.ReserveParams{Owner: foreignOwner, RequestID: uuid.New(), RegistrationKey: "foreign", Environment: "foreign", Spec: []byte(`{"engine":"fake"}`), CredentialSourceID: source.ID, CredentialSourceVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		requireStatus(t, env.doBearer(t, method, "/api/v1/connection-registrations/"+reg.ID.String(), nil, key.Token), http.StatusForbidden)
	}
	requireStatus(t, env.doBearer(t, http.MethodDelete, "/api/v1/connection-credential-sources/"+source.ID.String(), nil, key.Token), http.StatusForbidden)
	// The same administrator may inspect/cancel through their interactive
	// session; a delegated key does not inherit this cross-owner maintenance.
	requireStatus(t, env.do(t, http.MethodGet, "/api/v1/connection-registrations/"+reg.ID.String(), nil, &admin, false), http.StatusOK)
	requireStatus(t, env.do(t, http.MethodDelete, "/api/v1/connection-registrations/"+reg.ID.String(), nil, &admin, true), http.StatusAccepted)
}

func TestIntegrationConnectionRegistrationCurrentScopePrecedesProjectionAndPagination(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newScopeTestEnv(t, vaultClient, policy.EnforcementEnforce)
	admin := session(auth.RoleAdmin)
	principalID := createPrincipal(t, env, admin, "service")
	environment := "receipt-scope-" + uuid.NewString()
	foreignEnvironment := "receipt-foreign-" + uuid.NewString()
	token := issueOnboardingServiceToken(t, env, principalID, environment, true, true)
	sourceID := createOnboardingSource(t, env, principalID, environment)
	bodies := make([]map[string]any, 3)
	receipts := make([]onboardingReceipt, 3)
	for i := range receipts {
		bodies[i] = onboardingRequest(environment, sourceID)
		resp := env.doBearer(t, http.MethodPost, "/api/v1/connection-registrations", bodies[i], token)
		requireStatus(t, resp, http.StatusAccepted)
		receipts[i] = readOnboardingReceipt(t, resp)
	}
	for _, receipt := range receipts[1:] {
		active, err := connections.NewStore().Transition(t.Context(), env.pool, receipt.ConnectionID, connections.StatusDiscovering, connections.StatusActive)
		if err != nil {
			t.Fatal(err)
		}
		// The interactive admin legitimately reclassifies the connection.
		// Its immutable registration still records the original environment.
		requireStatus(t, env.do(t, http.MethodPatch, "/api/v1/connections/"+receipt.ConnectionID.String(), map[string]any{"updated_at": active.UpdatedAt, "environment": foreignEnvironment}, &admin, true), http.StatusAccepted)
	}
	for i, receipt := range receipts[1:] {
		resp := env.doBearer(t, http.MethodGet, "/api/v1/connection-registrations/"+receipt.ID.String(), nil, token)
		requireStatus(t, resp, http.StatusForbidden)
		if strings.Contains(string(readBody(t, resp)), receipt.OperationID.String()) {
			t.Fatal("foreign current operation leaked through historical registration")
		}
		requireStatus(t, env.doBearer(t, http.MethodPost, "/api/v1/connection-registrations", bodies[i+1], token), http.StatusForbidden)
		requireStatus(t, env.do(t, http.MethodGet, "/api/v1/connection-registrations/"+receipt.ID.String(), nil, &admin, false), http.StatusOK)
	}
	resp := env.doBearer(t, http.MethodGet, "/api/v1/connection-registrations?limit=1", nil, token)
	requireStatus(t, resp, http.StatusOK)
	var page struct {
		Registrations []onboardingReceipt `json:"registrations"`
	}
	if err := json.Unmarshal(readBody(t, resp), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Registrations) != 1 || page.Registrations[0].ID != receipts[0].ID {
		t.Fatal("hidden current environments crowded out the visible receipt before pagination")
	}
	resp = env.doBearer(t, http.MethodGet, "/api/v1/connection-registrations?limit=1&offset=1", nil, token)
	requireStatus(t, resp, http.StatusOK)
	if err := json.Unmarshal(readBody(t, resp), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Registrations) != 0 {
		t.Fatal("offset was applied before registration authorization")
	}
	// A foreign child must also hide the root's aggregate outcome while its
	// own connection and original registration environment remain allowed.
	createOperationDetailScopeFixture(t, env, &receipts[1].ConnectionID, &receipts[0].OperationID, "scope.fixture.child", "foreign-registration-child")
	requireStatus(t, env.doBearer(t, http.MethodGet, "/api/v1/connection-registrations/"+receipts[0].ID.String(), nil, token), http.StatusForbidden)
	resp = env.doBearer(t, http.MethodGet, "/api/v1/connection-registrations?limit=1", nil, token)
	requireStatus(t, resp, http.StatusOK)
	if err := json.Unmarshal(readBody(t, resp), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Registrations) != 0 {
		t.Fatal("registered operation child outside scope appeared in the list")
	}
}
