package vault

// Unit-тесты Kubernetes-аутентификации поверх фейкового Vault (httptest):
// login, фоновое продление, re-login при отказе продления (403) со свежим
// JWT и конкурентные KV-чтения во время token swap. Реальный Vault не
// требуется; integration-контур (token-режим) не меняется.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeVault — минимальный фейковый Vault: kubernetes login, token
// renew-self и чтение KV v2. Все ранее выданные токены остаются валидными
// (как в реальном Vault до истечения TTL), поэтому конкурентные чтения во
// время swap не флапают.
type fakeVault struct {
	t *testing.T

	mu          sync.Mutex
	tokens      map[string]bool // выданные client tokens
	logins      int
	renews      int
	failRenew   bool
	leaseSec    int
	lastJWT     string
	expectRole  string
	kvResponses map[string]map[string]any // path -> data
}

func newFakeVault(t *testing.T, leaseSec int) (*fakeVault, *httptest.Server) {
	t.Helper()
	fv := &fakeVault{
		t:          t,
		tokens:     map[string]bool{},
		leaseSec:   leaseSec,
		expectRole: "grantor",
		kvResponses: map[string]map[string]any{
			"connections/c1/admin": {"username": "admin", "password": "pw"},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(fv.handle))
	t.Cleanup(srv.Close)
	return fv, srv
}

func (f *fakeVault) handle(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPut && r.URL.Path == "/v1/auth/kubernetes-test/login":
		f.handleLogin(w, r)
	case r.Method == http.MethodPut && r.URL.Path == "/v1/auth/token/renew-self":
		f.handleRenew(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/secret/data/"):
		f.handleKVGet(w, r)
	default:
		http.Error(w, `{"errors":["unsupported path"]}`, http.StatusNotFound)
	}
}

func (f *fakeVault) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Role string `json:"role"`
		JWT  string `json:"jwt"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"errors":["bad request"]}`, http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if body.Role != f.expectRole || body.JWT == "" {
		http.Error(w, `{"errors":["invalid role or jwt"]}`, http.StatusForbidden)
		return
	}
	f.logins++
	f.lastJWT = body.JWT
	token := fmt.Sprintf("s.fake-token-%d", f.logins)
	f.tokens[token] = true
	writeJSON(w, map[string]any{
		"auth": map[string]any{
			"client_token":   token,
			"lease_duration": f.leaseSec,
			"renewable":      true,
		},
	})
}

func (f *fakeVault) handleRenew(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.tokens[r.Header.Get("X-Vault-Token")] {
		http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
		return
	}
	if f.failRenew {
		http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
		return
	}
	f.renews++
	writeJSON(w, map[string]any{
		"auth": map[string]any{
			"client_token":   r.Header.Get("X-Vault-Token"),
			"lease_duration": f.leaseSec,
			"renewable":      true,
		},
	})
}

func (f *fakeVault) handleKVGet(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.tokens[r.Header.Get("X-Vault-Token")] {
		http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/v1/secret/data/")
	data, ok := f.kvResponses[path]
	if !ok {
		http.Error(w, `{"errors":[]}`, http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{
		"data": map[string]any{
			"data": data,
			"metadata": map[string]any{
				"version":      1,
				"created_time": time.Now().UTC().Format(time.RFC3339),
			},
		},
	})
}

// counters возвращает снимок счётчиков login/renew.
func (f *fakeVault) counters() (logins, renews int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.logins, f.renews
}

func (f *fakeVault) lastLoginJWT() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastJWT
}

func (f *fakeVault) setFailRenew(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failRenew = v
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// writeJWTFile создаёт (или перезаписывает) файл JWT и возвращает путь.
func writeJWTFile(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "sa-token")
	if err := os.WriteFile(path, []byte(content+"\n"), 0o600); err != nil {
		t.Fatalf("write jwt file: %v", err)
	}
	return path
}

// newK8sClient собирает клиента в kubernetes-режиме поверх фейкового Vault.
func newK8sClient(t *testing.T, srvURL, jwtPath string) *Client {
	t.Helper()
	c, err := New(Config{
		Address:     srvURL,
		Auth:        AuthKubernetes,
		Mount:       "secret",
		K8sAuthPath: "kubernetes-test",
		K8sRole:     "grantor",
		K8sJWTPath:  jwtPath,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// waitFor опрашивает cond до timeout; false — условие не наступило.
func waitFor(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cond()
}

func TestKubernetesAuthConfigValidation(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{"missing auth path", Config{Address: "http://127.0.0.1:8200", Auth: AuthKubernetes, K8sRole: "r"}},
		{"missing role", Config{Address: "http://127.0.0.1:8200", Auth: AuthKubernetes, K8sAuthPath: "kubernetes"}},
		{"unknown auth method", Config{Address: "http://127.0.0.1:8200", Auth: "approle", Token: "x"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.cfg); err == nil {
				t.Errorf("New(%s): expected error", tt.name)
			}
		})
	}

	// В kubernetes-режиме статический токен не требуется.
	c, err := New(Config{
		Address:     "http://127.0.0.1:8200",
		Auth:        AuthKubernetes,
		K8sAuthPath: "kubernetes",
		K8sRole:     "grantor",
	})
	if err != nil {
		t.Fatalf("New(kubernetes without token): %v", err)
	}
	if c.k8s == nil {
		t.Error("kubernetes auth state is not initialized")
	}
	if c.k8s.jwtPath != DefaultK8sJWTPath {
		t.Errorf("default jwt path = %q, want %q", c.k8s.jwtPath, DefaultK8sJWTPath)
	}
}

func TestStartAuthTokenModeIsNoop(t *testing.T) {
	c, err := New(Config{Address: "http://127.0.0.1:8200", Token: "test-token"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Токен-режим: StartAuth не ходит в сеть и не ошибается.
	if err := c.StartAuth(context.Background()); err != nil {
		t.Fatalf("StartAuth(token mode) = %v, want nil", err)
	}
}

// TestKubernetesLoginAndKV — login JWT'ом ServiceAccount и последующее
// KV-чтение выданным client token.
func TestKubernetesLoginAndKV(t *testing.T) {
	fv, srv := newFakeVault(t, 3600)
	jwtPath := writeJWTFile(t, t.TempDir(), "jwt-initial")
	c := newK8sClient(t, srv.URL, jwtPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.StartAuth(ctx); err != nil {
		t.Fatalf("StartAuth: %v", err)
	}
	if got := fv.lastLoginJWT(); got != "jwt-initial" {
		t.Errorf("login jwt = %q, want %q (trimmed file contents)", got, "jwt-initial")
	}

	data, version, err := c.Get(ctx, "connections/c1/admin")
	if err != nil {
		t.Fatalf("Get after login: %v", err)
	}
	if version != 1 || data["username"] != "admin" {
		t.Errorf("Get = (%v, %d), want username=admin version=1", data, version)
	}
	if logins, _ := fv.counters(); logins != 1 {
		t.Errorf("logins = %d, want 1", logins)
	}
}

// TestKubernetesRenew — фоновый цикл продлевает токен на ~2/3 lease через
// auth/token/renew-self; повторный login не выполняется.
func TestKubernetesRenew(t *testing.T) {
	fv, srv := newFakeVault(t, 1) // renew примерно через 0.6–0.75s
	jwtPath := writeJWTFile(t, t.TempDir(), "jwt-renew")
	c := newK8sClient(t, srv.URL, jwtPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.StartAuth(ctx); err != nil {
		t.Fatalf("StartAuth: %v", err)
	}

	if !waitFor(5*time.Second, func() bool { _, renews := fv.counters(); return renews >= 2 }) {
		logins, renews := fv.counters()
		t.Fatalf("renewals did not happen: logins=%d renews=%d", logins, renews)
	}
	if logins, _ := fv.counters(); logins != 1 {
		t.Errorf("logins = %d, want 1 (renewal must not re-login)", logins)
	}
	if _, _, err := c.Get(ctx, "connections/c1/admin"); err != nil {
		t.Fatalf("Get after renewals: %v", err)
	}
}

// TestKubernetesReloginOnRenewalFailure — отказ renew-self (403) ведёт к
// re-login со СВЕЖИМ JWT из файла (projected token ротируется), после чего
// KV-чтения работают новым client token.
func TestKubernetesReloginOnRenewalFailure(t *testing.T) {
	fv, srv := newFakeVault(t, 1)
	dir := t.TempDir()
	jwtPath := writeJWTFile(t, dir, "jwt-first")
	c := newK8sClient(t, srv.URL, jwtPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.StartAuth(ctx); err != nil {
		t.Fatalf("StartAuth: %v", err)
	}

	// Ротация projected token + отказ продления: следующий цикл обязан
	// перелогиниться свежим JWT.
	writeJWTFile(t, dir, "jwt-rotated")
	fv.setFailRenew(true)

	if !waitFor(5*time.Second, func() bool { logins, _ := fv.counters(); return logins >= 2 }) {
		logins, renews := fv.counters()
		t.Fatalf("re-login did not happen: logins=%d renews=%d", logins, renews)
	}
	if got := fv.lastLoginJWT(); got != "jwt-rotated" {
		t.Errorf("re-login jwt = %q, want fresh %q", got, "jwt-rotated")
	}
	if _, _, err := c.Get(ctx, "connections/c1/admin"); err != nil {
		t.Fatalf("Get after re-login: %v", err)
	}
}

// TestKubernetesConcurrentReadsDuringSwap — KV-чтения из нескольких горутин
// во время постоянных re-login (каждое продление падает → каждый цикл меняет
// токен). Ловится гонками -race; старые токены остаются валидными до
// истечения, как в реальном Vault.
func TestKubernetesConcurrentReadsDuringSwap(t *testing.T) {
	fv, srv := newFakeVault(t, 1)
	jwtPath := writeJWTFile(t, t.TempDir(), "jwt-swap")
	c := newK8sClient(t, srv.URL, jwtPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.StartAuth(ctx); err != nil {
		t.Fatalf("StartAuth: %v", err)
	}
	fv.setFailRenew(true) // каждый цикл — новый login и token swap

	var wg sync.WaitGroup
	errCh := make(chan error, 4)
	deadline := time.Now().Add(2 * time.Second)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				if _, _, err := c.Get(ctx, "connections/c1/admin"); err != nil {
					errCh <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	if err := <-errCh; err != nil {
		t.Fatalf("concurrent Get during token swap: %v", err)
	}
	if logins, _ := fv.counters(); logins < 2 {
		t.Fatalf("logins = %d, want >= 2 (token swap did not happen during reads)", logins)
	}
}
