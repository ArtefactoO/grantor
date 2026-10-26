//go:build integration

package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/fake"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/admincredentials"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/policy"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
)

const adminCredentialAPIEngine = "admin-credential-api-test"

var registerAdminCredentialAPIOnce sync.Once

type adminCredentialAPIAdapter struct{ adapter.Adapter }

func newAdminCredentialAPIAdapter() adapter.Adapter {
	return &adminCredentialAPIAdapter{Adapter: fake.New()}
}

func (a *adminCredentialAPIAdapter) Manifest() adapter.Manifest {
	manifest := a.Adapter.Manifest()
	manifest.Engine = adminCredentialAPIEngine
	manifest.Capabilities = append(manifest.Capabilities,
		adapter.CapConnectionAdminCredentialSwitch,
		adapter.CapConnectionAdminCredentialRotate)
	return manifest
}

func (a *adminCredentialAPIAdapter) AssessConnectionAdminCredential(context.Context,
	adapter.Connection) (adapter.AdminCredentialAssessment, error) {
	return adapter.AdminCredentialAssessment{
		SwitchSupported: true, RotateSupported: true, CanonicalIdentity: "admin",
		AuthorityFingerprint: "authority", TargetIdentity: "target",
	}, nil
}

func (a *adminCredentialAPIAdapter) ProveConnectionAdminCredential(context.Context,
	adapter.Connection, adapter.Credential) (adapter.AdminCredentialProof, error) {
	return adapter.AdminCredentialProof{
		CanonicalIdentity: "admin", AuthorityFingerprint: "authority", TargetIdentity: "target",
	}, nil
}

func (a *adminCredentialAPIAdapter) RotateConnectionAdminCredential(context.Context,
	adapter.Connection, adapter.Credential, adapter.AdminCredentialProof) (adapter.AdminCredentialRotationResult, error) {
	return adapter.AdminCredentialRotationResult{}, errors.New("not used by API staging test")
}

func registerAdminCredentialAPIAdapter() {
	registerAdminCredentialAPIOnce.Do(func() {
		adapter.Register(adminCredentialAPIEngine, newAdminCredentialAPIAdapter)
	})
}

func adminCredentialAPIConnection(t *testing.T, env *testEnv, vaultClient *vault.Client) connections.Connection {
	t.Helper()
	registerAdminCredentialAPIAdapter()
	store := connections.NewStore()
	ad := newAdminCredentialAPIAdapter()
	conn, err := store.Create(t.Context(), env.pool, connections.CreateParams{
		DisplayName: "admin-credential-api-" + uuid.NewString(), Engine: adminCredentialAPIEngine,
		Environment: "test", Capabilities: ad.Manifest().CapabilityNames(),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range [][2]connections.Status{
		{connections.StatusDraft, connections.StatusValidating},
		{connections.StatusValidating, connections.StatusDiscovering},
		{connections.StatusDiscovering, connections.StatusActive},
	} {
		conn, err = store.Transition(t.Context(), env.pool, conn.ID, step[0], step[1])
		if err != nil {
			t.Fatal(err)
		}
	}
	path, err := vault.ConnectionAdminPath(conn.ID.String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vaultClient.Put(t.Context(), path,
		map[string]any{"username": "old-admin", "password": "old-value"}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(t.Context(), `
		update connections set vault_admin_path = $2, admin_credential_set_at = now(), updated_at = now()
		where id = $1`, conn.ID, path); err != nil {
		t.Fatal(err)
	}
	topology := []byte(`{
		"admin_credential_switch_supported":true,
		"admin_credential_rotate_supported":true,
		"admin_credential_canonical_identity":"old-admin",
		"admin_credential_authority_fingerprint":"authority",
		"admin_credential_target_identity":"target"
	}`)
	if err := store.SetDiscoveryResult(t.Context(), env.pool, conn.ID, "test", topology,
		ad.Manifest().CapabilityNames(), time.Now()); err != nil {
		t.Fatal(err)
	}
	conn, err = store.Get(t.Context(), env.pool, conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func TestIntegrationAdminCredentialSwitchIsIdempotentBlockedAndCancellable(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	conn := adminCredentialAPIConnection(t, env, vaultClient)
	admin := session(auth.RoleAdmin)
	requestID := uuid.New()
	const candidateCanary = "candidate-secret-canary"
	body := map[string]any{
		"request_id": requestID, "updated_at": conn.UpdatedAt,
		"username": "replacement-admin", "password": candidateCanary,
	}
	path := "/api/v1/connections/" + conn.ID.String() + "/admin-credential/switch"
	resp := env.do(t, http.MethodPost, path, body, &admin, true)
	requireStatus(t, resp, http.StatusAccepted)
	raw := readBody(t, resp)
	if strings.Contains(string(raw), candidateCanary) {
		t.Fatal("switch response leaked candidate")
	}
	var started struct {
		OperationID uuid.UUID `json:"operation_id"`
	}
	if err := json.Unmarshal(raw, &started); err != nil || started.OperationID != requestID {
		t.Fatalf("start response=%s err=%v", raw, err)
	}

	// Lost-response retry uses request_id before updated_at CAS and returns the
	// original operation even though connection.updated_at already changed.
	resp = env.do(t, http.MethodPost, path, body, &admin, true)
	requireStatus(t, resp, http.StatusAccepted)
	var duplicate struct {
		OperationID uuid.UUID `json:"operation_id"`
	}
	if err := json.Unmarshal(readBody(t, resp), &duplicate); err != nil {
		t.Fatal(err)
	}
	if duplicate.OperationID != requestID {
		t.Fatalf("duplicate operation = %s", duplicate.OperationID)
	}

	updating, err := connections.NewStore().Get(t.Context(), env.pool, conn.ID)
	if err != nil || updating.Status != connections.StatusCredentialUpdating {
		t.Fatalf("connection status=%q err=%v", updating.Status, err)
	}
	resp = env.do(t, http.MethodPatch, "/api/v1/connections/"+conn.ID.String(), map[string]any{
		"updated_at": updating.UpdatedAt, "display_name": "blocked-edit",
	}, &admin, true)
	requireStatus(t, resp, http.StatusConflict)
	resp = env.do(t, http.MethodDelete, "/api/v1/connections/"+conn.ID.String()+"?force=true", nil, &admin, true)
	requireStatus(t, resp, http.StatusConflict)

	resp = env.do(t, http.MethodGet, "/api/v1/connections/"+conn.ID.String(), nil, &admin, false)
	requireStatus(t, resp, http.StatusOK)
	detail := readBody(t, resp)
	if strings.Contains(string(detail), candidateCanary) || !strings.Contains(string(detail), requestID.String()) {
		t.Fatal("connection detail leaked candidate or omitted active change")
	}

	cancelID := uuid.New()
	resp = env.do(t, http.MethodPost,
		"/api/v1/connections/"+conn.ID.String()+"/admin-credential/cancel",
		map[string]any{"request_id": cancelID, "updated_at": updating.UpdatedAt}, &admin, true)
	requireStatus(t, resp, http.StatusAccepted)
	after, err := connections.NewStore().Get(t.Context(), env.pool, conn.ID)
	if err != nil || after.Status != connections.StatusActive {
		t.Fatalf("connection after cancel status=%q err=%v", after.Status, err)
	}
	op, err := operations.NewStore().Get(t.Context(), env.pool, requestID)
	if err != nil || op.Status != operations.StatusCancelled {
		t.Fatalf("operation after cancel status=%q err=%v", op.Status, err)
	}
	stagePath, _ := vault.ConnectionAdminChangeStagePath(conn.ID.String(), requestID.String())
	if _, err := vaultClient.Metadata(t.Context(), stagePath); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("cancelled stage still exists: %v", err)
	}
}

func TestIntegrationAdminCredentialStageReservationSurvivesEnqueueFailure(t *testing.T) {
	vaultClient := newTestVault(t)
	dispatcher := &countingDispatcher{err: errors.New("forced credential enqueue failure")}
	env := buildTestEnv(t, testEnvOpts{
		vault: vaultClient, enforcement: policy.EnforcementDisabled, dispatcher: dispatcher,
	})
	conn := adminCredentialAPIConnection(t, env, vaultClient)
	admin := session(auth.RoleAdmin)
	requestID := uuid.New()
	body := map[string]any{
		"request_id": requestID, "updated_at": conn.UpdatedAt,
		"username": "replacement-admin", "password": "reservation-canary",
	}
	path := "/api/v1/connections/" + conn.ID.String() + "/admin-credential/switch"
	resp := env.do(t, http.MethodPost, path, body, &admin, true)
	requireStatus(t, resp, http.StatusInternalServerError)
	change, err := admincredentials.NewStore().GetByRequest(t.Context(), env.pool, conn.ID, requestID)
	if err != nil || change.Phase != admincredentials.PhasePreparing || change.StagedVaultVersion != 0 {
		t.Fatalf("provisional change=%+v err=%v", change, err)
	}
	if _, _, err := vaultClient.Get(t.Context(), change.StageVaultPath); err != nil {
		t.Fatalf("tracked stage missing after enqueue failure: %v", err)
	}
	// Same request_id resumes the provisional row and binds/enqueues the exact
	// existing stage instead of creating an untracked secret or new operation.
	dispatcher.err = nil
	resp = env.do(t, http.MethodPost, path, body, &admin, true)
	requireStatus(t, resp, http.StatusAccepted)
	change, err = admincredentials.NewStore().Get(t.Context(), env.pool, requestID)
	if err != nil || change.Phase != admincredentials.PhaseStaged || change.StagedVaultVersion <= 0 {
		t.Fatalf("finalized change=%+v err=%v", change, err)
	}
	updating, err := connections.NewStore().Get(t.Context(), env.pool, conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	resp = env.do(t, http.MethodPost,
		"/api/v1/connections/"+conn.ID.String()+"/admin-credential/cancel",
		map[string]any{"request_id": uuid.New(), "updated_at": updating.UpdatedAt}, &admin, true)
	requireStatus(t, resp, http.StatusAccepted)
}

func TestIntegrationAdminCredentialStageLockSerializesCancelAndConcurrentRequest(t *testing.T) {
	vaultClient := newTestVault(t)
	stageEntered := make(chan struct{})
	releaseStage := make(chan struct{})
	var hookOnce sync.Once
	env := buildTestEnv(t, testEnvOpts{
		vault: vaultClient, enforcement: policy.EnforcementDisabled,
		beforeAdminCredentialStage: func(ctx context.Context, _ uuid.UUID) error {
			hookOnce.Do(func() { close(stageEntered) })
			select {
			case <-releaseStage:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	})
	conn := adminCredentialAPIConnection(t, env, vaultClient)
	admin := session(auth.RoleAdmin)
	firstID := uuid.New()
	path := "/api/v1/connections/" + conn.ID.String() + "/admin-credential/switch"
	firstBody := map[string]any{
		"request_id": firstID, "updated_at": conn.UpdatedAt,
		"username": "replacement-admin", "password": "serialized-candidate",
	}
	firstDone := make(chan *http.Response, 1)
	go func() { firstDone <- env.do(t, http.MethodPost, path, firstBody, &admin, true) }()
	select {
	case <-stageEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("stage hook was not reached")
	}
	updating, err := connections.NewStore().Get(t.Context(), env.pool, conn.ID)
	if err != nil || updating.Status != connections.StatusCredentialUpdating {
		t.Fatalf("provisional connection status=%q err=%v", updating.Status, err)
	}

	cancelDone := make(chan *http.Response, 1)
	go func() {
		cancelDone <- env.do(t, http.MethodPost,
			"/api/v1/connections/"+conn.ID.String()+"/admin-credential/cancel",
			map[string]any{"request_id": uuid.New(), "updated_at": updating.UpdatedAt}, &admin, true)
	}()
	secondID := uuid.New()
	secondDone := make(chan *http.Response, 1)
	go func() {
		secondDone <- env.do(t, http.MethodPost, path, map[string]any{
			"request_id": secondID, "updated_at": conn.UpdatedAt,
			"username": "other-admin", "password": "losing-candidate",
		}, &admin, true)
	}()
	select {
	case response := <-cancelDone:
		t.Fatalf("cancel escaped the in-flight stage lock with status %d", response.StatusCode)
	case response := <-secondDone:
		t.Fatalf("concurrent request escaped the in-flight stage lock with status %d", response.StatusCode)
	case <-time.After(150 * time.Millisecond):
	}
	close(releaseStage)
	requireStatus(t, <-firstDone, http.StatusAccepted)
	requireStatus(t, <-secondDone, http.StatusConflict)
	requireStatus(t, <-cancelDone, http.StatusAccepted)

	if _, err := admincredentials.NewStore().GetByRequest(t.Context(), env.pool, conn.ID, secondID); !errors.Is(err, admincredentials.ErrNotFound) {
		t.Fatalf("losing request created a lifecycle row: %v", err)
	}
	firstStage, _ := vault.ConnectionAdminChangeStagePath(conn.ID.String(), firstID.String())
	if _, err := vaultClient.Metadata(t.Context(), firstStage); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("cancel left winner stage behind: %v", err)
	}
	secondStage, _ := vault.ConnectionAdminChangeStagePath(conn.ID.String(), secondID.String())
	if _, err := vaultClient.Metadata(t.Context(), secondStage); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("losing request created an orphan stage: %v", err)
	}
}

var _ adapter.ConnectionAdminCredentialManager = (*adminCredentialAPIAdapter)(nil)
