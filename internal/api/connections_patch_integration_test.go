//go:build integration

package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/kafka"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/locks"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/policy"
)

type countingDispatcher struct {
	calls atomic.Int64
	err   error
}

func (d *countingDispatcher) EnqueueOperationTx(context.Context, pgx.Tx, uuid.UUID) error {
	d.calls.Add(1)
	return d.err
}

func (d *countingDispatcher) EnqueueOperationSequenceTx(ctx context.Context, tx pgx.Tx, operationIDs ...uuid.UUID) error {
	for _, id := range operationIDs {
		if err := d.EnqueueOperationTx(ctx, tx, id); err != nil {
			return err
		}
	}
	return nil
}

type patchConnectionBody struct {
	ID              uuid.UUID       `json:"id"`
	DisplayName     string          `json:"display_name"`
	Environment     string          `json:"environment"`
	Tags            []string        `json:"tags"`
	Endpoints       []string        `json:"endpoints"`
	Status          string          `json:"status"`
	ServerVersion   string          `json:"server_version"`
	Topology        json.RawMessage `json:"topology"`
	LastDiscoveryAt *time.Time      `json:"last_discovery_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
	OperationID     *uuid.UUID      `json:"operation_id"`
}

func createPatchConnection(t *testing.T, env *testEnv, status connections.Status) connections.Connection {
	t.Helper()
	store := connections.NewStore()
	conn, err := store.Create(t.Context(), env.pool, connections.CreateParams{
		DisplayName:     "itest-patch-" + uuid.NewString(),
		Engine:          "fake",
		Environment:     "itest",
		Tags:            []string{"old"},
		Endpoints:       []string{"target-postgres:5432"},
		TLSConfig:       json.RawMessage(`{"mode":"disabled"}`),
		DiscoveryConfig: json.RawMessage(`{"database":"postgres"}`),
	})
	if err != nil {
		t.Fatalf("create patch connection: %v", err)
	}
	chain := []connections.Status{}
	switch status {
	case connections.StatusDraft:
	case connections.StatusValidating:
		chain = []connections.Status{connections.StatusValidating}
	case connections.StatusDiscovering:
		chain = []connections.Status{connections.StatusValidating, connections.StatusDiscovering}
	case connections.StatusActive, connections.StatusDisabled:
		chain = []connections.Status{connections.StatusValidating, connections.StatusDiscovering, connections.StatusActive}
		if status == connections.StatusDisabled {
			chain = append(chain, connections.StatusDisabled)
		}
	default:
		t.Fatalf("unsupported test status %q", status)
	}
	from := connections.StatusDraft
	for _, to := range chain {
		conn, err = store.Transition(t.Context(), env.pool, conn.ID, from, to)
		if err != nil {
			t.Fatalf("transition %q -> %q: %v", from, to, err)
		}
		from = to
	}
	if status == connections.StatusActive {
		at := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
		if err := store.SetDiscoveryResult(t.Context(), env.pool, conn.ID, "fake-1", []byte(`{"cluster":"old"}`), conn.Capabilities, at); err != nil {
			t.Fatalf("seed discovery result: %v", err)
		}
		conn, err = store.Get(t.Context(), env.pool, conn.ID)
		if err != nil {
			t.Fatalf("reload patch connection: %v", err)
		}
	}
	return conn
}

func patchBody(version time.Time, fields map[string]any) map[string]any {
	body := map[string]any{"updated_at": version}
	for key, value := range fields {
		body[key] = value
	}
	return body
}

func createRabbitMQPatchConnection(t *testing.T, env *testEnv) connections.Connection {
	t.Helper()
	store := connections.NewStore()
	conn, err := store.Create(t.Context(), env.pool, connections.CreateParams{
		DisplayName: "itest-rabbit-patch-" + uuid.NewString(),
		Engine:      "rabbitmq",
		Environment: "itest",
		Endpoints:   []string{"target-postgres:5432"},
		TLSConfig:   json.RawMessage(`{"mode":"disabled"}`),
		DiscoveryConfig: json.RawMessage(`{"rabbitmq_permission_templates":[{
			"key":"template-a","name":"Template A","description":"Initial template",
			"vhost":"sl","configure":"^status$","write":"^updates$",
			"read":"^(status|updates)$","dangerous":false
		}]}`),
	})
	if err != nil {
		t.Fatalf("create RabbitMQ patch connection: %v", err)
	}
	from := connections.StatusDraft
	for _, to := range []connections.Status{
		connections.StatusValidating, connections.StatusDiscovering, connections.StatusActive,
	} {
		conn, err = store.Transition(t.Context(), env.pool, conn.ID, from, to)
		if err != nil {
			t.Fatalf("transition RabbitMQ connection %q -> %q: %v", from, to, err)
		}
		from = to
	}
	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	if err := store.SetDiscoveryResult(t.Context(), env.pool, conn.ID, "3.13.0", []byte(`{"topology":"standalone"}`), nil, at); err != nil {
		t.Fatalf("seed RabbitMQ discovery result: %v", err)
	}
	conn, err = store.Get(t.Context(), env.pool, conn.ID)
	if err != nil {
		t.Fatalf("reload RabbitMQ patch connection: %v", err)
	}
	return conn
}

func TestIntegrationPatchConnectionMetadataPreservesSnapshot(t *testing.T) {
	dispatcher := &countingDispatcher{}
	env := buildTestEnv(t, testEnvOpts{enforcement: policy.EnforcementDisabled, dispatcher: dispatcher})
	admin := session(auth.RoleAdmin)
	conn := createPatchConnection(t, env, connections.StatusActive)

	resp := env.do(t, http.MethodPatch, "/api/v1/connections/"+conn.ID.String(),
		patchBody(conn.UpdatedAt, map[string]any{
			"display_name": "renamed",
			"tags":         []string{"new"},
			// Присутствующее, но фактически неизменное operational-поле не
			// превращает mixed payload в reconfigure.
			"endpoints": conn.Endpoints,
		}), &admin, true)
	requireStatus(t, resp, http.StatusOK)
	var out patchConnectionBody
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode metadata patch: %v", err)
	}
	if out.DisplayName != "renamed" || !slices.Equal(out.Tags, []string{"new"}) {
		t.Errorf("metadata patch response = %+v", out)
	}
	var topology map[string]string
	if err := json.Unmarshal(out.Topology, &topology); err != nil {
		t.Fatalf("decode preserved topology: %v", err)
	}
	if out.Status != string(connections.StatusActive) || out.ServerVersion != "fake-1" ||
		topology["cluster"] != "old" || out.LastDiscoveryAt == nil {
		t.Errorf("metadata patch changed snapshot/status: %+v topology=%s", out, out.Topology)
	}
	if out.OperationID != nil || dispatcher.calls.Load() != 0 {
		t.Errorf("metadata patch queued discovery: operation=%v calls=%d", out.OperationID, dispatcher.calls.Load())
	}
	events, err := audit.NewWriter().List(t.Context(), env.pool,
		audit.Filter{ConnectionID: &conn.ID, Actions: []string{"connection.updated"}}, 10, 0)
	if err != nil || len(events) != 1 {
		t.Fatalf("metadata update audit: len=%d err=%v", len(events), err)
	}
	var metadata struct {
		ChangedFields []string `json:"changed_fields"`
		Operational   bool     `json:"operational"`
	}
	if err := json.Unmarshal(events[0].Metadata, &metadata); err != nil {
		t.Fatalf("decode metadata update audit: %v", err)
	}
	if metadata.Operational || !slices.Equal(metadata.ChangedFields, []string{"display_name", "tags"}) {
		t.Errorf("metadata audit reports non-effective fields: %+v", metadata)
	}
}

func TestIntegrationPatchConnectionRejectsEmptyAndNoopWithoutSideEffects(t *testing.T) {
	dispatcher := &countingDispatcher{}
	env := buildTestEnv(t, testEnvOpts{enforcement: policy.EnforcementDisabled, dispatcher: dispatcher})
	admin := session(auth.RoleAdmin)
	conn := createPatchConnection(t, env, connections.StatusActive)
	path := "/api/v1/connections/" + conn.ID.String()

	for _, body := range []map[string]any{
		{},
		{"updated_at": conn.UpdatedAt},
		patchBody(conn.UpdatedAt, map[string]any{
			"display_name":     conn.DisplayName,
			"tags":             conn.Tags,
			"environment":      conn.Environment,
			"endpoints":        conn.Endpoints,
			"tls_config":       json.RawMessage(conn.TLSConfig),
			"discovery_config": json.RawMessage(conn.DiscoveryConfig),
		}),
	} {
		resp := env.do(t, http.MethodPatch, path, body, &admin, true)
		requireStatus(t, resp, http.StatusBadRequest)
	}
	stored, err := connections.NewStore().Get(t.Context(), env.pool, conn.ID)
	if err != nil {
		t.Fatalf("reload after no-op patches: %v", err)
	}
	if !stored.UpdatedAt.Equal(conn.UpdatedAt) || stored.Status != conn.Status {
		t.Errorf("no-op patch changed connection: before=%+v after=%+v", conn, stored)
	}
	if dispatcher.calls.Load() != 0 {
		t.Errorf("no-op patches dispatched %d operation(s)", dispatcher.calls.Load())
	}
	var operationsCount, auditCount int
	if err := env.pool.QueryRow(t.Context(), `select count(*) from operations where connection_id=$1`, conn.ID).Scan(&operationsCount); err != nil {
		t.Fatalf("count no-op operations: %v", err)
	}
	if err := env.pool.QueryRow(t.Context(), `select count(*) from audit_events where connection_id=$1 and action='connection.updated'`, conn.ID).Scan(&auditCount); err != nil {
		t.Fatalf("count no-op audit: %v", err)
	}
	if operationsCount != 0 || auditCount != 0 {
		t.Errorf("no-op side effects: operations=%d audit=%d", operationsCount, auditCount)
	}
}

func TestIntegrationPatchConnectionOperationalReconfiguresOnceAndSanitizesAudit(t *testing.T) {
	dispatcher := &countingDispatcher{}
	env := buildTestEnv(t, testEnvOpts{enforcement: policy.EnforcementDisabled, dispatcher: dispatcher})
	admin := session(auth.RoleAdmin)
	conn := createPatchConnection(t, env, connections.StatusActive)
	const marker = "audit-sensitive-config-marker"
	body := patchBody(conn.UpdatedAt, map[string]any{
		"endpoints":        []string{"target-postgres:5432"},
		"discovery_config": map[string]any{"database": marker},
	})

	resp := env.do(t, http.MethodPatch, "/api/v1/connections/"+conn.ID.String(), body, &admin, true)
	requireStatus(t, resp, http.StatusAccepted)
	var out patchConnectionBody
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode operational patch: %v", err)
	}
	if out.Status != string(connections.StatusDiscovering) || out.ServerVersion != "" ||
		string(out.Topology) != `{}` || out.LastDiscoveryAt != nil || out.OperationID == nil {
		t.Errorf("operational patch did not reset snapshot/queue discovery: %+v topology=%s", out, out.Topology)
	}
	if dispatcher.calls.Load() != 1 {
		t.Fatalf("dispatcher calls = %d, want 1", dispatcher.calls.Load())
	}

	var opCount int
	if err := env.pool.QueryRow(t.Context(), `select count(*) from operations where connection_id=$1 and kind='connection.discover'`, conn.ID).Scan(&opCount); err != nil {
		t.Fatalf("count discovery operations: %v", err)
	}
	if opCount != 1 {
		t.Errorf("discovery operations = %d, want 1", opCount)
	}
	events, err := audit.NewWriter().List(t.Context(), env.pool, audit.Filter{ConnectionID: &conn.ID, Actions: []string{"connection.updated"}}, 10, 0)
	if err != nil || len(events) != 1 {
		t.Fatalf("connection.updated audit: len=%d err=%v", len(events), err)
	}
	if strings.Contains(string(events[0].Metadata), marker) {
		t.Fatal("audit metadata leaks discovery_config value")
	}
	var metadata struct {
		ChangedFields   []string `json:"changed_fields"`
		Operational     bool     `json:"operational"`
		SnapshotReset   bool     `json:"snapshot_reset"`
		DiscoveryQueued bool     `json:"discovery_queued"`
	}
	if err := json.Unmarshal(events[0].Metadata, &metadata); err != nil {
		t.Fatalf("decode update audit metadata: %v", err)
	}
	if !metadata.Operational || !metadata.SnapshotReset || !metadata.DiscoveryQueued ||
		!slices.Equal(metadata.ChangedFields, []string{"discovery_config"}) {
		t.Errorf("unexpected update audit metadata: %+v", metadata)
	}

	// Потерянный ответ не позволяет повторно создать discovery: старый CAS
	// получает 409, а operation/enqueue остаются ровно одними.
	resp = env.do(t, http.MethodPatch, "/api/v1/connections/"+conn.ID.String(), body, &admin, true)
	requireStatus(t, resp, http.StatusConflict)
	if dispatcher.calls.Load() != 1 {
		t.Errorf("stale retry dispatcher calls = %d, want 1", dispatcher.calls.Load())
	}
}

func TestIntegrationPatchConnectionFailedAccessReplacementBlocksOnlyRabbitMQTemplates(t *testing.T) {
	dispatcher := &countingDispatcher{}
	env := buildTestEnv(t, testEnvOpts{enforcement: policy.EnforcementDisabled, dispatcher: dispatcher})
	admin := session(auth.RoleAdmin)
	conn := createRabbitMQPatchConnection(t, env)
	invStore := inventory.NewStore()
	opStore := operations.NewStore()
	account, err := invStore.CreateManagedAccount(t.Context(), env.pool, inventory.CreateManagedAccountParams{
		ConnectionID: conn.ID, EngineIdentity: "failed-replace-" + uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create replacement account: %v", err)
	}
	assignmentKey := "rabbitmq:vhost:sl"
	var permissionA, permissionB uuid.UUID
	for _, item := range []struct {
		id   *uuid.UUID
		key  string
		name string
	}{
		{&permissionA, "template:a:" + uuid.NewString(), "Template A"},
		{&permissionB, "template:b:" + uuid.NewString(), "Template B"},
	} {
		if err := env.pool.QueryRow(t.Context(), `
			insert into permission_definitions
				(connection_id, engine, external_id, name, assignment_key, assignable, attributes)
			values ($1, 'rabbitmq', $2, $3, $4, true,
				jsonb_build_object('template_key', $2::text))
			returning id`, conn.ID, item.key, item.name, assignmentKey).Scan(item.id); err != nil {
			t.Fatalf("insert %s: %v", item.name, err)
		}
	}
	binding, _, err := invStore.EnsureBinding(t.Context(), env.pool, inventory.EnsureBindingParams{
		AccountID: account.ID, PermissionID: permissionA, DesiredState: inventory.BindingPresent,
	})
	if err != nil {
		t.Fatalf("ensure source binding: %v", err)
	}
	if _, err := env.pool.Exec(t.Context(), `
		update bindings set observed_state='present', observed_effective=true,
			observed_permission_definition_id=$2, status='synced'
		where id=$1`, binding.ID, permissionA); err != nil {
		t.Fatalf("seed source binding observation: %v", err)
	}
	op, _, err := opStore.Create(t.Context(), env.pool, operations.CreateParams{
		Kind: "access.replace", ConnectionID: &conn.ID, AccountID: &account.ID,
		BindingID: &binding.ID, ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create replacement operation: %v", err)
	}
	transition := inventory.AccessReplacementTransition{
		BindingID: binding.ID, OperationID: op.ID,
		FromPermissionID: permissionA, ToPermissionID: permissionB,
		AssignmentKey: assignmentKey, ExpectedVersion: binding.Version + 1,
	}
	if _, err := invStore.ReserveAccessReplacement(t.Context(), env.pool, transition); err != nil {
		t.Fatalf("reserve replacement: %v", err)
	}
	if err := invStore.MarkAccessReplacementFailed(t.Context(), env.pool, transition); err != nil {
		t.Fatalf("mark replacement binding failed: %v", err)
	}
	if _, err := opStore.Transition(t.Context(), env.pool, op.ID,
		operations.StatusPending, operations.StatusRunning, operations.TransitionOpts{}); err != nil {
		t.Fatalf("start replacement operation: %v", err)
	}
	if _, err := opStore.Transition(t.Context(), env.pool, op.ID,
		operations.StatusRunning, operations.StatusFailed, operations.TransitionOpts{Error: "forced test failure"}); err != nil {
		t.Fatalf("fail replacement operation: %v", err)
	}

	path := "/api/v1/connections/" + conn.ID.String()
	resp := env.do(t, http.MethodPatch, path, patchBody(conn.UpdatedAt, map[string]any{
		"discovery_config": map[string]any{
			"rabbitmq_permission_templates": []map[string]any{{
				"key": "template-b", "name": "Template B", "description": "Changed template",
				"vhost": "sl", "configure": "^status$", "write": "^new_updates$",
				"read": "^(status|new_updates)$", "dangerous": false,
			}},
		},
	}), &admin, true)
	requireStatus(t, resp, http.StatusConflict)
	if dispatcher.calls.Load() != 0 {
		t.Fatalf("blocked template patch dispatched %d operation(s)", dispatcher.calls.Load())
	}

	// Failed access.replace retains durable transition ownership for retry or
	// exact reverse, but it must not freeze unrelated connection recovery.
	resp = env.do(t, http.MethodPatch, path, patchBody(conn.UpdatedAt, map[string]any{
		"endpoints":  []string{"target-postgres:5433"},
		"tls_config": map[string]any{"mode": "verify-full"},
	}), &admin, true)
	requireStatus(t, resp, http.StatusAccepted)
	if dispatcher.calls.Load() != 1 {
		t.Fatalf("endpoint/TLS patch dispatcher calls = %d, want 1", dispatcher.calls.Load())
	}
	stored, err := connections.NewStore().Get(t.Context(), env.pool, conn.ID)
	if err != nil {
		t.Fatalf("reload connection after endpoint/TLS patch: %v", err)
	}
	var tlsConfig struct {
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(stored.TLSConfig, &tlsConfig); err != nil {
		t.Fatalf("decode persisted TLS config: %v", err)
	}
	if !slices.Equal(stored.Endpoints, []string{"target-postgres:5433"}) || tlsConfig.Mode != "verify-full" {
		t.Fatalf("endpoint/TLS patch not persisted: endpoints=%v tls=%+v", stored.Endpoints, tlsConfig)
	}
	var discoveryConfig struct {
		Templates []struct {
			Key string `json:"key"`
		} `json:"rabbitmq_permission_templates"`
	}
	if err := json.Unmarshal(stored.DiscoveryConfig, &discoveryConfig); err != nil {
		t.Fatalf("decode persisted discovery config: %v", err)
	}
	if len(discoveryConfig.Templates) != 1 || discoveryConfig.Templates[0].Key != "template-a" {
		t.Fatalf("blocked template patch changed discovery config: %+v", discoveryConfig)
	}
}

func TestIntegrationPatchConnectionRejectsRBACCSRFUnknownImmutableAndNotFound(t *testing.T) {
	env := newTestEnv(t, nil)
	admin := session(auth.RoleAdmin)
	operator := session(auth.RoleOperator)
	viewer := session(auth.RoleViewer)
	conn := createPatchConnection(t, env, connections.StatusDraft)
	path := "/api/v1/connections/" + conn.ID.String()
	body := patchBody(conn.UpdatedAt, map[string]any{"display_name": "new"})

	for _, sess := range []auth.Session{viewer, operator} {
		resp := env.do(t, http.MethodPatch, path, body, &sess, true)
		requireStatus(t, resp, http.StatusForbidden)
	}
	resp := env.do(t, http.MethodPatch, path, body, &admin, false)
	requireStatus(t, resp, http.StatusForbidden)

	for _, field := range []string{"engine", "execution_mode", "capabilities", "status", "admin_credential", "admin_credential_mode", "vault_admin_path", "credentials"} {
		t.Run("reject "+field, func(t *testing.T) {
			resp := env.do(t, http.MethodPatch, path,
				patchBody(conn.UpdatedAt, map[string]any{"display_name": "new", field: "forbidden"}), &admin, true)
			requireStatus(t, resp, http.StatusBadRequest)
		})
	}
	resp = env.do(t, http.MethodPatch, "/api/v1/connections/"+uuid.NewString(),
		patchBody(time.Now().UTC(), map[string]any{"display_name": "new"}), &admin, true)
	requireStatus(t, resp, http.StatusNotFound)
}

func TestIntegrationPatchConnectionScopeDoesNotDowngradeAdminOnly(t *testing.T) {
	env := newScopeTestEnv(t, nil, policy.EnforcementEnforce)
	admin := session(auth.RoleAdmin)
	operator := session(auth.RoleOperator)
	environment := "patch-scope-" + uuid.NewString()
	conn := createDraftInEnv(t, env, environment)
	createRolePolicy(t, env, admin, environment)

	// Даже разрешённый scope не превращает operator в администратора connection.
	resp := env.do(t, http.MethodPatch, "/api/v1/connections/"+conn.ID.String(),
		patchBody(conn.UpdatedAt, map[string]any{"display_name": "scoped"}), &operator, true)
	requireStatus(t, resp, http.StatusForbidden)
}

func TestIntegrationPatchConnectionRejectsInvalidStateAndSSRF(t *testing.T) {
	env := newTestEnv(t, nil)
	admin := session(auth.RoleAdmin)
	for _, status := range []connections.Status{
		connections.StatusDisabled, connections.StatusValidating, connections.StatusDiscovering,
	} {
		t.Run(string(status)+" operational", func(t *testing.T) {
			conn := createPatchConnection(t, env, status)
			resp := env.do(t, http.MethodPatch, "/api/v1/connections/"+conn.ID.String(),
				patchBody(conn.UpdatedAt, map[string]any{"endpoints": []string{"changed-target:5432"}}), &admin, true)
			requireStatus(t, resp, http.StatusConflict)
		})
	}
	for _, status := range []connections.Status{connections.StatusValidating, connections.StatusDiscovering} {
		t.Run(string(status)+" metadata", func(t *testing.T) {
			conn := createPatchConnection(t, env, status)
			resp := env.do(t, http.MethodPatch, "/api/v1/connections/"+conn.ID.String(),
				patchBody(conn.UpdatedAt, map[string]any{"display_name": "new"}), &admin, true)
			requireStatus(t, resp, http.StatusConflict)
		})
	}

	conn := createPatchConnection(t, env, connections.StatusActive)
	resp := env.do(t, http.MethodPatch, "/api/v1/connections/"+conn.ID.String(),
		patchBody(conn.UpdatedAt, map[string]any{"endpoints": []string{"169.254.169.254:5432"}}), &admin, true)
	requireStatus(t, resp, http.StatusBadRequest)
	stored, err := connections.NewStore().Get(t.Context(), env.pool, conn.ID)
	if err != nil {
		t.Fatalf("reload after SSRF rejection: %v", err)
	}
	if !stored.UpdatedAt.Equal(conn.UpdatedAt) || stored.Status != connections.StatusActive {
		t.Error("SSRF rejection changed connection")
	}
}

func TestIntegrationPatchConnectionUsesConnectionAdvisoryLock(t *testing.T) {
	env := newTestEnv(t, nil)
	admin := session(auth.RoleAdmin)
	conn := createPatchConnection(t, env, connections.StatusDraft)

	holder, err := env.pool.Begin(t.Context())
	if err != nil {
		t.Fatalf("begin lock holder: %v", err)
	}
	defer holder.Rollback(t.Context()) //nolint:errcheck
	if err := locks.AcquireTx(t.Context(), holder, conn.ID); err != nil {
		t.Fatalf("acquire holder lock: %v", err)
	}

	done := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		raw, _ := json.Marshal(patchBody(conn.UpdatedAt, map[string]any{"display_name": "locked"}))
		req, reqErr := http.NewRequest(http.MethodPatch, env.srv.URL+"/api/v1/connections/"+conn.ID.String(), strings.NewReader(string(raw)))
		if reqErr != nil {
			errCh <- reqErr
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: env.codec.Encode(admin)})
		req.Header.Set(auth.CSRFHeader, env.codec.CSRFToken(admin))
		response, reqErr := http.DefaultClient.Do(req)
		if reqErr != nil {
			errCh <- reqErr
			return
		}
		done <- response
	}()

	select {
	case response := <-done:
		response.Body.Close()
		t.Fatal("PATCH completed while per-connection advisory lock was held")
	case err := <-errCh:
		t.Fatalf("PATCH while lock held: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	if err := holder.Rollback(t.Context()); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		t.Fatalf("release holder lock: %v", err)
	}
	select {
	case response := <-done:
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("PATCH after lock release status = %d", response.StatusCode)
		}
	case err := <-errCh:
		t.Fatalf("PATCH after lock release: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("PATCH did not finish after advisory lock release")
	}
}

func TestIntegrationPatchConnectionRollsBackWhenEnqueueFails(t *testing.T) {
	dispatcher := &countingDispatcher{err: errors.New("forced enqueue failure")}
	env := buildTestEnv(t, testEnvOpts{enforcement: policy.EnforcementDisabled, dispatcher: dispatcher})
	admin := session(auth.RoleAdmin)
	conn := createPatchConnection(t, env, connections.StatusActive)
	resp := env.do(t, http.MethodPatch, "/api/v1/connections/"+conn.ID.String(),
		patchBody(conn.UpdatedAt, map[string]any{"environment": "changed"}), &admin, true)
	requireStatus(t, resp, http.StatusInternalServerError)
	stored, err := connections.NewStore().Get(t.Context(), env.pool, conn.ID)
	if err != nil {
		t.Fatalf("reload after enqueue rollback: %v", err)
	}
	if stored.Environment != conn.Environment || stored.Status != conn.Status || !stored.UpdatedAt.Equal(conn.UpdatedAt) {
		t.Errorf("failed enqueue did not roll back connection: before=%+v after=%+v", conn, stored)
	}
	var count int
	if err := env.pool.QueryRow(t.Context(), `select count(*) from operations where connection_id=$1 and kind=$2`, conn.ID, "connection.discover").Scan(&count); err != nil {
		t.Fatalf("count rolled-back operations: %v", err)
	}
	if count != 0 {
		t.Errorf("failed enqueue left %d discovery operation(s)", count)
	}
}

// createKafkaPatchConnection создаёт active kafka-подключение с SCRAM-
// механизмом по умолчанию и seeded discovery result. Живой брокер не нужен:
// эффективный набор capabilities — чистая функция от конфигурации подключения
// и topology последнего snapshot.
func createKafkaPatchConnection(t *testing.T, env *testEnv, topology string) connections.Connection {
	t.Helper()
	registerKafkaOnceAPI.Do(func() {
		adapter.Register(kafka.Engine, func() adapter.Adapter { return kafka.New() })
	})
	store := connections.NewStore()
	conn, err := store.Create(t.Context(), env.pool, connections.CreateParams{
		DisplayName:     "itest-caps-" + uuid.NewString(),
		Engine:          kafka.Engine,
		Environment:     "itest",
		Endpoints:       []string{"redpanda:9092"},
		TLSConfig:       json.RawMessage(`{"mode":"disabled"}`),
		DiscoveryConfig: json.RawMessage(`{"sasl_mechanism":"scram-sha-256"}`),
		Capabilities:    kafka.New().Manifest().CapabilityNames(),
	})
	if err != nil {
		t.Fatalf("create kafka connection: %v", err)
	}
	from := connections.StatusDraft
	for _, to := range []connections.Status{
		connections.StatusValidating, connections.StatusDiscovering, connections.StatusActive,
	} {
		conn, err = store.Transition(t.Context(), env.pool, conn.ID, from, to)
		if err != nil {
			t.Fatalf("transition %q -> %q: %v", from, to, err)
		}
		from = to
	}
	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	if err := store.SetDiscoveryResult(t.Context(), env.pool, conn.ID, "3.7.0",
		[]byte(topology), kafka.New().Manifest().CapabilityNames(), at); err != nil {
		t.Fatalf("seed discovery result: %v", err)
	}
	conn, err = store.Get(t.Context(), env.pool, conn.ID)
	if err != nil {
		t.Fatalf("reload kafka connection: %v", err)
	}
	return conn
}

// connectionCapabilities читает capabilities подключения ровно так, как их
// видит UI: GET /api/v1/connections/{id}.
func connectionCapabilities(t *testing.T, env *testEnv, sess auth.Session, id uuid.UUID) []string {
	t.Helper()
	resp := env.do(t, http.MethodGet, "/api/v1/connections/"+id.String(), nil, &sess, false)
	requireStatus(t, resp, http.StatusOK)
	var out struct {
		Capabilities []string `json:"capabilities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode connection: %v", err)
	}
	return out.Capabilities
}

// TestIntegrationPatchConnectionRecomputesCapabilities — регрессия на баг
// «capabilities не пересчитываются под подключение»: до фикса подключение
// навсегда сохраняло engine-wide манифест, снятый при создании, и UI предлагал
// account.create / account.delete / credential.rotate на PLAIN-кластере Kafka,
// где SCRAM API нет и Apply гарантированно падает.
func TestIntegrationPatchConnectionRecomputesCapabilities(t *testing.T) {
	dispatcher := &countingDispatcher{}
	env := buildTestEnv(t, testEnvOpts{enforcement: policy.EnforcementDisabled, dispatcher: dispatcher})
	admin := session(auth.RoleAdmin)
	conn := createKafkaPatchConnection(t, env, `{"topology":"standalone"}`)

	scramLifecycle := []string{"account.create", "account.delete", "credential.rotate"}
	aclOps := []string{"access.grant", "access.revoke", "account.disable", "account.enable"}

	before := connectionCapabilities(t, env, admin, conn.ID)
	for _, want := range append(slices.Clone(scramLifecycle), aclOps...) {
		if !slices.Contains(before, want) {
			t.Fatalf("scram connection must expose %q, got %v", want, before)
		}
	}

	// Перевод подключения на PLAIN — operational PATCH.
	resp := env.do(t, http.MethodPatch, "/api/v1/connections/"+conn.ID.String(),
		patchBody(conn.UpdatedAt, map[string]any{
			"discovery_config": map[string]any{"sasl_mechanism": "plain"},
		}), &admin, true)
	requireStatus(t, resp, http.StatusAccepted)
	var out struct {
		Capabilities []string `json:"capabilities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode patch response: %v", err)
	}

	// Ответ PATCH и последующий GET (UI-контракт) обязаны совпадать и не
	// содержать SCRAM-lifecycle.
	after := connectionCapabilities(t, env, admin, conn.ID)
	if !slices.Equal(out.Capabilities, after) {
		t.Errorf("patch response capabilities = %v, GET = %v", out.Capabilities, after)
	}
	for _, gone := range scramLifecycle {
		if slices.Contains(after, gone) {
			t.Errorf("capability %q must be gone on a PLAIN connection: %v", gone, after)
		}
	}
	// ACL-операции и инвентарь на PLAIN остаются: grantor управляет ACL.
	for _, kept := range append(slices.Clone(aclOps), "inventory.resources", "inventory.accounts") {
		if !slices.Contains(after, kept) {
			t.Errorf("capability %q must survive on a PLAIN connection: %v", kept, after)
		}
	}
}

// TestIntegrationDiscoveryResultNarrowsCapabilities проверяет вторую точку
// пересчёта: результат discovery. Kafka сообщает выключенный ACL-авторизатор
// в topology, и подключение перестаёт заявлять ACL-операции, которые на таком
// кластере отклоняются до Apply.
func TestIntegrationDiscoveryResultNarrowsCapabilities(t *testing.T) {
	env := buildTestEnv(t, testEnvOpts{enforcement: policy.EnforcementDisabled})
	admin := session(auth.RoleAdmin)
	conn := createKafkaPatchConnection(t, env,
		`{"topology":"standalone","acl_authorizer":"disabled"}`)

	caps := connectionCapabilities(t, env, admin, conn.ID)
	for _, gone := range []string{"access.grant", "access.revoke", "account.disable", "account.enable"} {
		if slices.Contains(caps, gone) {
			t.Errorf("capability %q must be gone when the acl authorizer is disabled: %v", gone, caps)
		}
	}
	for _, kept := range []string{"inventory.resources", "account.create", "credential.rotate"} {
		if !slices.Contains(caps, kept) {
			t.Errorf("capability %q must survive with a disabled acl authorizer: %v", kept, caps)
		}
	}
}
