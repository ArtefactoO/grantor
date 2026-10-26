//go:build integration

// Integration-тесты SSRF-guard и security-findings API v1. Разделяют
// хелперы с api_integration_test.go (newTestEnv, session, do, ...).
package api_test

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapters/fake"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/audit"
)

// securityConnBody — подмножество connectionJSON для проверки findings.
type securityConnBody struct {
	ID               string   `json:"id"`
	SecurityFindings []string `json:"security_findings"`
}

// createConnectionBody собирает валидное тело создания connection с
// заданными endpoints и tls_config (nil = без tls_config).
func createConnectionBody(endpoints []string, tls map[string]any) map[string]any {
	body := map[string]any{
		"display_name": "itest-security-" + uuid.NewString(),
		"engine":       fake.Engine,
		"environment":  "itest",
		"endpoints":    endpoints,
		"admin_credential": map[string]string{
			"username": "grantor_admin",
			"password": "itest-secret-value",
		},
	}
	if tls != nil {
		body["tls_config"] = tls
	}
	return body
}

// TestIntegrationEndpointSSRFBlocked: заблокированные адреса endpoint
// отвергаются на этапе валидации (400) до обращения к Vault, поэтому
// Vault для теста не нужен.
func TestIntegrationEndpointSSRFBlocked(t *testing.T) {
	env := newTestEnv(t, nil)
	admin := session(auth.RoleAdmin)

	blocked := []struct {
		name     string
		endpoint string
	}{
		{"aws metadata", "169.254.169.254:5432"},
		{"loopback", "127.0.0.1:5432"},
		{"link-local", "169.254.10.20:5432"},
	}
	for _, tc := range blocked {
		t.Run(tc.name, func(t *testing.T) {
			body := createConnectionBody([]string{tc.endpoint}, nil)
			resp := env.do(t, http.MethodPost, "/api/v1/connections", body, &admin, true)
			requireStatus(t, resp, http.StatusBadRequest)
			raw := readBody(t, resp)
			if !strings.Contains(string(raw), "is not allowed") {
				t.Errorf("body does not explain SSRF block: %s", raw)
			}
			// Причина блокировки не раскрывает резолвленный адрес сверх
			// того, что клиент прислал сам (endpoint эхом допустим).
		})
	}
}

// TestIntegrationEndpointPrivateAllowed: приватный IP НЕ блокируется как
// SSRF — при пустой политике создание проходит (нужен Vault для секрета).
func TestIntegrationEndpointPrivateAllowed(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	admin := session(auth.RoleAdmin)

	body := createConnectionBody([]string{"10.1.2.3:5432"}, nil)
	resp := env.do(t, http.MethodPost, "/api/v1/connections", body, &admin, true)
	// Приватный адрес должен пройти SSRF-проверку: ожидаем 201, но в любом
	// случае — НЕ 400 (не заблокирован guard'ом).
	if resp.StatusCode == http.StatusBadRequest {
		t.Fatalf("private endpoint blocked by SSRF guard: %s", readBody(t, resp))
	}
	requireStatus(t, resp, http.StatusCreated)
}

// TestIntegrationTLSNoCertVerifyFinding: connection с mode=require и
// insecure_skip_verify создаётся, GET возвращает finding tls_no_cert_verify,
// а audit-событие создания несёт эффективный tls_mode и список findings.
func TestIntegrationTLSNoCertVerifyFinding(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	admin := session(auth.RoleAdmin)
	viewer := session(auth.RoleViewer)

	body := createConnectionBody(
		[]string{"target-postgres:5432"},
		map[string]any{"mode": "require", "insecure_skip_verify": true},
	)
	resp := env.do(t, http.MethodPost, "/api/v1/connections", body, &admin, true)
	requireStatus(t, resp, http.StatusCreated)
	var created securityConnBody
	if err := json.Unmarshal(readBody(t, resp), &created); err != nil {
		t.Fatalf("unmarshal create response: %v", err)
	}
	if !slices.Contains(created.SecurityFindings, "tls_no_cert_verify") {
		t.Errorf("create response findings = %v, want tls_no_cert_verify", created.SecurityFindings)
	}

	// GET возвращает то же findings.
	resp = env.do(t, http.MethodGet, "/api/v1/connections/"+created.ID, nil, &viewer, false)
	requireStatus(t, resp, http.StatusOK)
	var got securityConnBody
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode get response: %v", err)
	}
	if !slices.Contains(got.SecurityFindings, "tls_no_cert_verify") {
		t.Errorf("get response findings = %v, want tls_no_cert_verify", got.SecurityFindings)
	}

	// Audit-событие создания несёт эффективный tls_mode и finding.
	connID, err := uuid.Parse(created.ID)
	if err != nil {
		t.Fatalf("parse connection id: %v", err)
	}
	events, err := audit.NewWriter().List(t.Context(), env.pool, audit.Filter{
		ConnectionID: &connID,
		Actions:       []string{"connection.created"},
	}, 10, 0)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	// metadata — jsonb (нормализован, порядок ключей не гарантирован):
	// сравниваем разобранные значения, а не подстроки.
	var meta struct {
		TLSMode          string   `json:"tls_mode"`
		SecurityFindings []string `json:"security_findings"`
	}
	if err := json.Unmarshal(events[0].Metadata, &meta); err != nil {
		t.Fatalf("unmarshal audit metadata: %v", err)
	}
	if meta.TLSMode != "require" {
		t.Errorf("audit tls_mode = %q, want require", meta.TLSMode)
	}
	if !slices.Contains(meta.SecurityFindings, "tls_no_cert_verify") {
		t.Errorf("audit security_findings = %v, want tls_no_cert_verify", meta.SecurityFindings)
	}
}

// TestIntegrationTLSDisabledFinding: connection без tls_config (plaintext)
// создаётся успешно (дефолт не меняется) и несёт finding tls_disabled в
// ответе и audit — небезопасный выбор становится видимым.
func TestIntegrationTLSDisabledFinding(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	admin := session(auth.RoleAdmin)

	body := createConnectionBody([]string{"target-postgres:5432"}, nil)
	resp := env.do(t, http.MethodPost, "/api/v1/connections", body, &admin, true)
	requireStatus(t, resp, http.StatusCreated)
	var created securityConnBody
	if err := json.Unmarshal(readBody(t, resp), &created); err != nil {
		t.Fatalf("unmarshal create response: %v", err)
	}
	if !slices.Contains(created.SecurityFindings, "tls_disabled") {
		t.Errorf("create response findings = %v, want tls_disabled", created.SecurityFindings)
	}

	connID, err := uuid.Parse(created.ID)
	if err != nil {
		t.Fatalf("parse connection id: %v", err)
	}
	events, err := audit.NewWriter().List(t.Context(), env.pool, audit.Filter{
		ConnectionID: &connID,
		Actions:       []string{"connection.created"},
	}, 10, 0)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	var meta struct {
		TLSMode          string   `json:"tls_mode"`
		SecurityFindings []string `json:"security_findings"`
	}
	if err := json.Unmarshal(events[0].Metadata, &meta); err != nil {
		t.Fatalf("unmarshal audit metadata: %v", err)
	}
	if meta.TLSMode != "disabled" {
		t.Errorf("audit tls_mode = %q, want disabled", meta.TLSMode)
	}
	if !slices.Contains(meta.SecurityFindings, "tls_disabled") {
		t.Errorf("audit security_findings = %v, want tls_disabled", meta.SecurityFindings)
	}
}
