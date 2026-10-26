//go:build integration

// Integration-тесты против реального Vault, например dev-сервера:
//
//	vault server -dev -dev-root-token-id=root
//
//	GRANTOR_TEST_VAULT_ADDR=http://127.0.0.1:8200 \
//	GRANTOR_TEST_VAULT_TOKEN=root \
//	go test -tags integration ./internal/providers/vault/
//
// Mount по умолчанию "secret": именно туда dev-сервер Vault монтирует KV v2;
// переопределяется через GRANTOR_TEST_VAULT_MOUNT.
package vault_test

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/ArtefactoO/grantor/internal/providers/vault"
)

// newTestClient создаёт клиента из окружения или пропускает тест, если
// Vault для integration-тестов не настроен.
func newTestClient(t *testing.T) *vault.Client {
	t.Helper()

	addr := os.Getenv("GRANTOR_TEST_VAULT_ADDR")
	token := os.Getenv("GRANTOR_TEST_VAULT_TOKEN")
	if addr == "" || token == "" {
		t.Skip("set GRANTOR_TEST_VAULT_ADDR and GRANTOR_TEST_VAULT_TOKEN to run Vault integration tests")
	}
	mount := os.Getenv("GRANTOR_TEST_VAULT_MOUNT")
	if mount == "" {
		mount = "secret"
	}

	c, err := vault.New(vault.Config{Address: addr, Token: token, Mount: mount})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// testPath возвращает уникальный путь, чтобы прогоны тестов не мешали друг
// другу и не зависели от остатков прошлых прогонов.
func testPath(t *testing.T) string {
	t.Helper()

	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return "grantor-test/" + hex.EncodeToString(b[:])
}

// requireErrorWithoutMarker проверяет, что операция завершилась ошибкой и
// текст ошибки не содержит секретный маркер.
func requireErrorWithoutMarker(t *testing.T, op string, err error, marker string) {
	t.Helper()

	if err == nil {
		t.Fatalf("%s: expected error", op)
	}
	if strings.Contains(err.Error(), marker) {
		t.Errorf("%s: error text contains secret marker", op)
	}
}

func TestIntegrationPing(t *testing.T) {
	c := newTestClient(t)
	if err := c.Ping(t.Context()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestIntegrationPutGetRoundtrip(t *testing.T) {
	c := newTestClient(t)
	ctx := t.Context()
	path := testPath(t)

	version, err := c.Put(ctx, path, map[string]any{"username": "grantor", "password": "first-value"})
	if err != nil {
		t.Fatalf("Put v1: %v", err)
	}
	if version != 1 {
		t.Errorf("Put v1 version = %d, want 1", version)
	}

	data, version, err := c.Get(ctx, path)
	if err != nil {
		t.Fatalf("Get after v1: %v", err)
	}
	if version != 1 {
		t.Errorf("Get version = %d, want 1", version)
	}
	if data["password"] != "first-value" {
		t.Errorf("Get data[password] = %v, want first-value", data["password"])
	}

	version, err = c.Put(ctx, path, map[string]any{"username": "grantor", "password": "second-value"})
	if err != nil {
		t.Fatalf("Put v2: %v", err)
	}
	if version != 2 {
		t.Errorf("Put v2 version = %d, want 2", version)
	}

	data, version, err = c.Get(ctx, path)
	if err != nil {
		t.Fatalf("Get after v2: %v", err)
	}
	if version != 2 {
		t.Errorf("Get version = %d, want 2", version)
	}
	if data["password"] != "second-value" {
		t.Errorf("Get data[password] = %v, want second-value", data["password"])
	}

	old, err := c.GetVersion(ctx, path, 1)
	if err != nil {
		t.Fatalf("GetVersion(1): %v", err)
	}
	if old["password"] != "first-value" {
		t.Errorf("GetVersion(1) data[password] = %v, want first-value", old["password"])
	}
}

func TestIntegrationPutCASRejectsStaleVersionAndPreservesCanonical(t *testing.T) {
	c := newTestClient(t)
	ctx := t.Context()
	path := testPath(t)

	version, err := c.PutCAS(ctx, path, map[string]any{"username": "admin", "password": "first"}, 0)
	if err != nil || version != 1 {
		t.Fatalf("PutCAS create version=%d err=%v", version, err)
	}
	version, err = c.PutCAS(ctx, path, map[string]any{"username": "admin", "password": "second"}, 1)
	if err != nil || version != 2 {
		t.Fatalf("PutCAS promote version=%d err=%v", version, err)
	}
	if _, err := c.PutCAS(ctx, path, map[string]any{"username": "admin", "password": "stale"}, 1); err == nil {
		t.Fatal("stale PutCAS unexpectedly succeeded")
	}
	data, actualVersion, err := c.Get(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if actualVersion != 2 || data["password"] != "second" {
		t.Fatalf("canonical after stale CAS mismatch: version=%d value_matches=%v",
			actualVersion, data["password"] == "second")
	}
}

func TestIntegrationGetNotFound(t *testing.T) {
	c := newTestClient(t)

	_, _, err := c.Get(t.Context(), testPath(t))
	if !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("Get(missing) error = %v, want ErrNotFound", err)
	}
}

func TestIntegrationMetadata(t *testing.T) {
	c := newTestClient(t)
	ctx := t.Context()
	path := testPath(t)

	for i := 1; i <= 2; i++ {
		if _, err := c.Put(ctx, path, map[string]any{"n": strconv.Itoa(i)}); err != nil {
			t.Fatalf("Put v%d: %v", i, err)
		}
	}

	md, err := c.Metadata(ctx, path)
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	if md.CurrentVersion != 2 {
		t.Errorf("CurrentVersion = %d, want 2", md.CurrentVersion)
	}
	if len(md.Versions) != 2 {
		t.Errorf("len(Versions) = %d, want 2", len(md.Versions))
	}
	for v := 1; v <= 2; v++ {
		vm, ok := md.Versions[v]
		if !ok {
			t.Fatalf("Versions missing version %d", v)
		}
		if vm.CreatedAt.IsZero() {
			t.Errorf("version %d: CreatedAt is zero", v)
		}
		if vm.Destroyed {
			t.Errorf("version %d: Destroyed = true, want false", v)
		}
		if vm.DeletionTime != nil {
			t.Errorf("version %d: DeletionTime = %v, want nil", v, vm.DeletionTime)
		}
	}
}

func TestIntegrationDestroyVersions(t *testing.T) {
	c := newTestClient(t)
	ctx := t.Context()
	path := testPath(t)

	if _, err := c.Put(ctx, path, map[string]any{"k": "v1"}); err != nil {
		t.Fatalf("Put v1: %v", err)
	}
	if _, err := c.Put(ctx, path, map[string]any{"k": "v2"}); err != nil {
		t.Fatalf("Put v2: %v", err)
	}

	if err := c.DestroyVersions(ctx, path, []int{1}); err != nil {
		t.Fatalf("DestroyVersions(1): %v", err)
	}

	// Уничтоженная версия: допустимы либо ошибка, либо пустые данные,
	// но не исходное значение.
	data, err := c.GetVersion(ctx, path, 1)
	if err == nil && len(data) != 0 {
		t.Errorf("GetVersion(1) after destroy = %v, want error or empty data", data)
	}

	latest, version, err := c.Get(ctx, path)
	if err != nil {
		t.Fatalf("Get latest after destroy: %v", err)
	}
	if version != 2 {
		t.Errorf("latest version = %d, want 2", version)
	}
	if latest["k"] != "v2" {
		t.Errorf("latest data[k] = %v, want v2", latest["k"])
	}

	md, err := c.Metadata(ctx, path)
	if err != nil {
		t.Fatalf("Metadata after destroy: %v", err)
	}
	if !md.Versions[1].Destroyed {
		t.Error("Metadata: version 1 Destroyed = false, want true")
	}
	if md.Versions[2].Destroyed {
		t.Error("Metadata: version 2 Destroyed = true, want false")
	}
}

func TestIntegrationErrorsDoNotLeakSecrets(t *testing.T) {
	const marker = "s3cr3t-marker-value"

	c := newTestClient(t)
	ctx := t.Context()
	path := testPath(t)

	if _, err := c.Put(ctx, path, map[string]any{"password": marker}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	_, err := c.GetVersion(ctx, path, 42)
	requireErrorWithoutMarker(t, "GetVersion(missing version)", err, marker)

	_, _, err = c.Get(ctx, path+"-missing")
	requireErrorWithoutMarker(t, "Get(missing path)", err, marker)

	_, err = c.Metadata(ctx, path+"-missing")
	requireErrorWithoutMarker(t, "Metadata(missing path)", err, marker)
}
