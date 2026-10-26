//go:build integration

package connections_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/kafka"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

func TestStoreCreateGetListUpdate(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := connections.NewStore()

	created, err := store.Create(ctx, pool, connections.CreateParams{
		DisplayName:         "itest-conn-" + uuid.NewString(),
		Engine:              "postgres",
		Environment:         "test",
		Tags:                []string{"team:devops"},
		Endpoints:           []string{"db1.example.com:5432", "db2.example.com:5432"},
		TLSConfig:           json.RawMessage(`{"mode":"disabled"}`),
		AdminCredentialMode: "existing_vault_ref",
		VaultAdminPath:      "connections/test/admin",
		Capabilities:        []string{"inventory.resources"},
		DiscoveryConfig:     json.RawMessage(`{"database":"postgres"}`),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.Status != connections.StatusDraft {
		t.Errorf("created status = %q, want draft", created.Status)
	}
	if created.ExecutionMode != "direct" {
		t.Errorf("created execution mode = %q, want direct (default)", created.ExecutionMode)
	}
	if created.LastDiscoveryAt != nil {
		t.Error("created last discovery at is set, want nil")
	}

	got, err := store.Get(ctx, pool, created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.DisplayName != created.DisplayName || got.Engine != "postgres" ||
		got.Environment != "test" || got.VaultAdminPath != "connections/test/admin" {
		t.Errorf("Get returned %+v, want fields of created connection", got)
	}
	if !slices.Equal(got.Endpoints, created.Endpoints) {
		t.Errorf("Get endpoints = %v, want %v", got.Endpoints, created.Endpoints)
	}
	if !slices.Equal(got.Tags, []string{"team:devops"}) {
		t.Errorf("Get tags = %v, want [team:devops]", got.Tags)
	}
	if !slices.Equal(got.Capabilities, []string{"inventory.resources"}) {
		t.Errorf("Get capabilities = %v, want [inventory.resources]", got.Capabilities)
	}

	if _, err := store.Get(ctx, pool, uuid.New()); !errors.Is(err, connections.ErrNotFound) {
		t.Errorf("Get missing: err = %v, want ErrNotFound", err)
	}

	list, err := store.List(ctx, pool)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if !slices.ContainsFunc(list, func(c connections.Connection) bool { return c.ID == created.ID }) {
		t.Error("List does not contain created connection")
	}

	updated, err := store.Update(ctx, pool, created.ID, connections.UpdateParams{
		DisplayName:     created.DisplayName + "-renamed",
		Environment:     "staging",
		Tags:            []string{"team:devops", "tier:2"},
		Endpoints:       []string{"db3.example.com:5432"},
		TLSConfig:       json.RawMessage(`{"mode":"require"}`),
		DiscoveryConfig: json.RawMessage(`{"database":"appdb"}`),
		Capabilities:    []string{"inventory.resources", "inventory.accounts"},
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Environment != "staging" || !slices.Equal(updated.Endpoints, []string{"db3.example.com:5432"}) {
		t.Errorf("Update returned %+v, want updated fields", updated)
	}
	var tlsConfig map[string]any
	if err := json.Unmarshal(updated.TLSConfig, &tlsConfig); err != nil {
		t.Fatalf("unmarshal updated tls config: %v", err)
	}
	if tlsConfig["mode"] != "require" {
		t.Errorf("Update tls config = %s, want mode require", updated.TLSConfig)
	}
	if updated.Engine != "postgres" || updated.VaultAdminPath != created.VaultAdminPath {
		t.Error("Update touched non-editable fields")
	}

	if _, err := store.Update(ctx, pool, uuid.New(), connections.UpdateParams{DisplayName: "x"}); !errors.Is(err, connections.ErrNotFound) {
		t.Errorf("Update missing: err = %v, want ErrNotFound", err)
	}
}

func TestStoreTransition(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := connections.NewStore()

	conn, err := store.Create(ctx, pool, connections.CreateParams{
		DisplayName: "itest-transition-" + uuid.NewString(),
		Engine:      "postgres",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Happy path: draft -> validating -> discovering.
	conn, err = store.Transition(ctx, pool, conn.ID, connections.StatusDraft, connections.StatusValidating)
	if err != nil {
		t.Fatalf("Transition draft -> validating: %v", err)
	}
	if conn.Status != connections.StatusValidating {
		t.Errorf("status = %q, want validating", conn.Status)
	}
	conn, err = store.Transition(ctx, pool, conn.ID, connections.StatusValidating, connections.StatusDiscovering)
	if err != nil {
		t.Fatalf("Transition validating -> discovering: %v", err)
	}

	// Недопустимый переход отклоняется до запроса к базе.
	if _, err := store.Transition(ctx, pool, conn.ID, connections.StatusDiscovering, connections.StatusDisabled); !errors.Is(err, connections.ErrInvalidTransition) {
		t.Errorf("invalid transition: err = %v, want ErrInvalidTransition", err)
	}

	// Guard: ожидаемый from не совпадает с фактическим статусом.
	if _, err := store.Transition(ctx, pool, conn.ID, connections.StatusDraft, connections.StatusValidating); !errors.Is(err, connections.ErrStatusConflict) {
		t.Errorf("stale from: err = %v, want ErrStatusConflict", err)
	}

	if _, err := store.Transition(ctx, pool, uuid.New(), connections.StatusDraft, connections.StatusValidating); !errors.Is(err, connections.ErrNotFound) {
		t.Errorf("missing connection: err = %v, want ErrNotFound", err)
	}
}

func TestStoreSetDiscoveryResult(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := connections.NewStore()

	conn, err := store.Create(ctx, pool, connections.CreateParams{
		DisplayName: "itest-discovery-result-" + uuid.NewString(),
		Engine:      "postgres",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	at := time.Now().UTC().Truncate(time.Microsecond)
	if err := store.SetDiscoveryResult(ctx, pool, conn.ID, "16.4", []byte(`{"in_recovery":false}`), []string{"inventory.resources", "account.restore"}, at); err != nil {
		t.Fatalf("SetDiscoveryResult: %v", err)
	}

	got, err := store.Get(ctx, pool, conn.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ServerVersion != "16.4" {
		t.Errorf("server version = %q, want 16.4", got.ServerVersion)
	}
	if got.LastDiscoveryAt == nil || !got.LastDiscoveryAt.Equal(at) {
		t.Errorf("last discovery at = %v, want %v", got.LastDiscoveryAt, at)
	}
	if !slices.Equal(got.Capabilities, []string{"inventory.resources", "account.restore"}) {
		t.Errorf("capabilities = %v, want discovery manifest capabilities", got.Capabilities)
	}
	var topology map[string]any
	if err := json.Unmarshal(got.Topology, &topology); err != nil {
		t.Fatalf("unmarshal topology: %v", err)
	}
	if topology["in_recovery"] != false {
		t.Errorf("topology = %v, want in_recovery=false", topology)
	}

	if err := store.SetDiscoveryResult(ctx, pool, uuid.New(), "16.4", nil, nil, at); !errors.Is(err, connections.ErrNotFound) {
		t.Errorf("missing connection: err = %v, want ErrNotFound", err)
	}
}

// registerKafkaOnceStore защищает от повторной регистрации adapter: registry
// глобален на процесс тестов.
var registerKafkaOnceStore sync.Once

func registerKafka(t *testing.T) {
	t.Helper()
	registerKafkaOnceStore.Do(func() {
		adapter.Register(kafka.Engine, func() adapter.Adapter { return kafka.New() })
	})
}

// TestStoreNarrowsCapabilitiesPerConnection — регрессия на баг «capabilities
// не пересчитываются под подключение»: колонка обязана хранить эффективный
// набор этого подключения, а не engine-wide манифест, на всех рабочих путях
// записи (Create, PatchCAS, SetDiscoveryResult).
func TestStoreNarrowsCapabilitiesPerConnection(t *testing.T) {
	registerKafka(t)
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := connections.NewStore()
	manifest := kafka.New().Manifest().CapabilityNames()

	has := func(caps []string, name string) bool { return slices.Contains(caps, name) }

	// Create: PLAIN-подключение сразу не заявляет SCRAM-lifecycle.
	plain, err := store.Create(ctx, pool, connections.CreateParams{
		DisplayName:     "itest-caps-plain-" + uuid.NewString(),
		Engine:          kafka.Engine,
		Environment:     "test",
		Endpoints:       []string{"redpanda:9092"},
		TLSConfig:       json.RawMessage(`{"mode":"disabled"}`),
		DiscoveryConfig: json.RawMessage(`{"sasl_mechanism":"plain"}`),
		Capabilities:    manifest,
	})
	if err != nil {
		t.Fatalf("Create plain: %v", err)
	}
	for _, gone := range []string{"account.create", "account.delete", "credential.rotate"} {
		if has(plain.Capabilities, gone) {
			t.Errorf("created plain connection must not declare %q: %v", gone, plain.Capabilities)
		}
	}
	if !has(plain.Capabilities, "access.grant") || !has(plain.Capabilities, "inventory.resources") {
		t.Errorf("created plain connection lost acl/inventory capabilities: %v", plain.Capabilities)
	}

	// Create: SCRAM сохраняет engine capabilities, но connection-admin
	// switch/rotate остаются fail-closed до live discovery assessment.
	scram, err := store.Create(ctx, pool, connections.CreateParams{
		DisplayName:     "itest-caps-scram-" + uuid.NewString(),
		Engine:          kafka.Engine,
		Environment:     "test",
		Endpoints:       []string{"redpanda:9092"},
		TLSConfig:       json.RawMessage(`{"mode":"disabled"}`),
		DiscoveryConfig: json.RawMessage(`{"sasl_mechanism":"scram-sha-256"}`),
		Capabilities:    manifest,
	})
	if err != nil {
		t.Fatalf("Create scram: %v", err)
	}
	expectedCreate := adapter.CapabilityNames(adapter.ScopeAdminCredentialCapabilities(
		kafka.New().Manifest().Capabilities, nil))
	if !slices.Equal(scram.Capabilities, expectedCreate) {
		t.Fatalf("created scram connection capabilities = %v, want scoped manifest %v",
			scram.Capabilities, expectedCreate)
	}

	// SetDiscoveryResult: свежая topology с выключенным ACL-авторизатором
	// снимает ACL-операции, даже если ей передан engine-wide манифест.
	at := time.Now().UTC().Truncate(time.Microsecond)
	if err := store.SetDiscoveryResult(ctx, pool, scram.ID, "3.7.0",
		[]byte(`{"topology":"standalone","acl_authorizer":"disabled"}`), manifest, at); err != nil {
		t.Fatalf("SetDiscoveryResult: %v", err)
	}
	afterDiscovery, err := store.Get(ctx, pool, scram.ID)
	if err != nil {
		t.Fatalf("Get after discovery: %v", err)
	}
	for _, gone := range []string{"access.grant", "access.revoke", "account.disable", "account.enable"} {
		if has(afterDiscovery.Capabilities, gone) {
			t.Errorf("disabled acl authorizer must drop %q: %v", gone, afterDiscovery.Capabilities)
		}
	}
	if !has(afterDiscovery.Capabilities, "credential.rotate") {
		t.Errorf("scram lifecycle must survive a disabled acl authorizer: %v", afterDiscovery.Capabilities)
	}

	// PatchCAS: перевод на PLAIN снимает SCRAM-lifecycle, а operational-сброс
	// topology возвращает ACL-операции до следующего discovery.
	current, err := store.Get(ctx, pool, scram.ID)
	if err != nil {
		t.Fatalf("Get before patch: %v", err)
	}
	patched, err := store.PatchCAS(ctx, pool, current.ID, connections.PatchParams{
		DisplayName:       current.DisplayName,
		Environment:       current.Environment,
		Endpoints:         current.Endpoints,
		TLSConfig:         current.TLSConfig,
		DiscoveryConfig:   json.RawMessage(`{"sasl_mechanism":"plain"}`),
		ExpectedUpdatedAt: current.UpdatedAt,
		ExpectedStatus:    current.Status,
		Operational:       true,
	})
	if err != nil {
		t.Fatalf("PatchCAS: %v", err)
	}
	for _, gone := range []string{"account.create", "account.delete", "credential.rotate"} {
		if has(patched.Capabilities, gone) {
			t.Errorf("patch to plain must drop %q: %v", gone, patched.Capabilities)
		}
	}
	if !has(patched.Capabilities, "access.grant") {
		t.Errorf("operational patch resets topology, so acl operations must return: %v", patched.Capabilities)
	}
}
