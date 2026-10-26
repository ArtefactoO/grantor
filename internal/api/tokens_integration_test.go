//go:build integration

// Integration-тесты service tokens и token-аутентификации API v1. Разделяют
// хелперы с api_integration_test.go (newTestEnv, session, do, ...).
package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/audit"
)

// doBearer выполняет запрос с аутентификацией по service-токену
// (Authorization: Bearer), без cookie и без CSRF-заголовка.
func (e *testEnv) doBearer(t *testing.T, method, path string, body any, token string) *http.Response {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, e.srv.URL+path, rd)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	t.Cleanup(func() { resp.Body.Close() }) //nolint:errcheck
	return resp
}

// createPrincipal создаёт принципала заданного типа и возвращает его id.
func createPrincipal(t *testing.T, env *testEnv, admin auth.Session, kind string) string {
	t.Helper()
	body := map[string]any{"type": kind, "display_name": "itest-" + kind + "-" + uuid.NewString()}
	resp := env.do(t, http.MethodPost, "/api/v1/principals", body, &admin, true)
	requireStatus(t, resp, http.StatusCreated)
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(readBody(t, resp), &created); err != nil {
		t.Fatalf("unmarshal created principal: %v", err)
	}
	return created.ID
}

func TestIntegrationServiceTokenLifecycle(t *testing.T) {
	env := newTestEnv(t, nil)
	admin := session(auth.RoleAdmin)
	operator := session(auth.RoleOperator)

	servicePrincipalID := createPrincipal(t, env, admin, "service")

	// Выпуск токена — admin. operator не может.
	tokenBody := map[string]any{"name": "ci-runner"}
	resp := env.do(t, http.MethodPost, "/api/v1/principals/"+servicePrincipalID+"/tokens", tokenBody, &operator, true)
	requireStatus(t, resp, http.StatusForbidden)

	resp = env.do(t, http.MethodPost, "/api/v1/principals/"+servicePrincipalID+"/tokens", tokenBody, &admin, true)
	requireStatus(t, resp, http.StatusCreated)
	var issued struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(readBody(t, resp), &issued); err != nil {
		t.Fatalf("unmarshal issued token: %v", err)
	}
	if !strings.HasPrefix(issued.Token, "grt_") || issued.ID == "" {
		t.Fatalf("unexpected issued token: %+v", issued)
	}

	// Список токенов не раскрывает сам токен (только метаданные).
	resp = env.do(t, http.MethodGet, "/api/v1/principals/"+servicePrincipalID+"/tokens", nil, &admin, false)
	requireStatus(t, resp, http.StatusOK)
	raw := readBody(t, resp)
	if strings.Contains(string(raw), issued.Token) {
		t.Fatal("token list leaks the plaintext token")
	}
	var list struct {
		Tokens []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatalf("unmarshal token list: %v", err)
	}
	if len(list.Tokens) != 1 || list.Tokens[0].ID != issued.ID {
		t.Fatalf("unexpected token list: %+v", list.Tokens)
	}

	// Token-auth работает: запрос с Bearer-токеном без cookie и без CSRF.
	resp = env.doBearer(t, http.MethodGet, "/api/v1/connections", nil, issued.Token)
	requireStatus(t, resp, http.StatusOK)

	// Token-auth несёт actor_type=service: мутация от имени service-принципала
	// (создание принципала) без CSRF-заголовка пишет audit с actor_type service.
	newPrincipalBody := map[string]any{"type": "service", "display_name": "itest-by-token-" + uuid.NewString()}
	resp = env.doBearer(t, http.MethodPost, "/api/v1/principals", newPrincipalBody, issued.Token)
	requireStatus(t, resp, http.StatusCreated)

	events, err := audit.NewWriter().List(t.Context(), env.pool, audit.Filter{
		Actions:  []string{"principal.created"},
		ActorID: servicePrincipalID,
	}, 10, 0)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("no principal.created audit event with service actor")
	}
	for _, e := range events {
		if e.ActorType != "service" {
			t.Errorf("audit actor_type = %q, want service", e.ActorType)
		}
		if e.ActorID != servicePrincipalID {
			t.Errorf("audit actor_id = %q, want %q", e.ActorID, servicePrincipalID)
		}
	}

	// Отзыв токена — admin. После отзыва token-auth возвращает 401.
	resp = env.do(t, http.MethodDelete, "/api/v1/tokens/"+issued.ID, nil, &admin, true)
	requireStatus(t, resp, http.StatusOK)

	resp = env.doBearer(t, http.MethodGet, "/api/v1/connections", nil, issued.Token)
	requireStatus(t, resp, http.StatusUnauthorized)

	// Отзыв несуществующего токена — 404.
	resp = env.do(t, http.MethodDelete, "/api/v1/tokens/"+uuid.NewString(), nil, &admin, true)
	requireStatus(t, resp, http.StatusNotFound)
}

func TestIntegrationServiceTokenNonServicePrincipal(t *testing.T) {
	env := newTestEnv(t, nil)
	admin := session(auth.RoleAdmin)

	humanID := createPrincipal(t, env, admin, "human")

	// Выпуск токена для не-service принципала запрещён (409).
	resp := env.do(t, http.MethodPost, "/api/v1/principals/"+humanID+"/tokens",
		map[string]any{"name": "nope"}, &admin, true)
	requireStatus(t, resp, http.StatusConflict)
}

func TestIntegrationInvalidBearerToken(t *testing.T) {
	env := newTestEnv(t, nil)

	// Неизвестный токен — 401; значение без префикса — тоже 401.
	resp := env.doBearer(t, http.MethodGet, "/api/v1/connections", nil, "grt_unknown-token")
	requireStatus(t, resp, http.StatusUnauthorized)
	resp = env.doBearer(t, http.MethodGet, "/api/v1/connections", nil, "not-a-token")
	requireStatus(t, resp, http.StatusUnauthorized)
}
