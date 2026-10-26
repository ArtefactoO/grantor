//go:build integration

package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapters/fake"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/principals"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
)

type principalCredentialListBody struct {
	Credentials []struct {
		Environment string `json:"environment"`
		Connections int    `json:"connections"`
		Configured  bool   `json:"configured"`
	} `json:"credentials"`
}

func TestIntegrationPrincipalCredentialEnvironmentsAndLifecycle(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	operator := session(auth.RoleOperator)
	admin := session(auth.RoleAdmin)
	envTest := "credential-test-" + uuid.NewString()
	envProd := "credential-prod-" + uuid.NewString()

	for _, item := range []struct {
		name, environment string
	}{
		{"credentials-test-a", envTest},
		{"credentials-test-b", envTest},
		{"credentials-prod", envProd},
	} {
		if _, err := connections.NewStore().Create(t.Context(), env.pool, connections.CreateParams{
			DisplayName: item.name + "-" + uuid.NewString(), Engine: fake.Engine,
			Environment: item.environment, Endpoints: []string{"target:5432"},
		}); err != nil {
			t.Fatalf("create connection %s: %v", item.environment, err)
		}
	}
	p, err := principals.NewStore().Create(t.Context(), env.pool, principals.CreateParams{
		Type: principals.TypeHuman, DisplayName: "credential environments " + uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create principal: %v", err)
	}

	listPath := "/api/v1/principals/" + p.ID.String() + "/credentials"
	resp := env.do(t, http.MethodGet, listPath, nil, &operator, false)
	requireStatus(t, resp, http.StatusOK)
	var before principalCredentialListBody
	if err := json.Unmarshal(readBody(t, resp), &before); err != nil {
		t.Fatalf("decode credentials: %v", err)
	}
	byEnvironment := make(map[string]struct {
		connections int
		configured  bool
	})
	for _, item := range before.Credentials {
		byEnvironment[item.Environment] = struct {
			connections int
			configured  bool
		}{item.Connections, item.Configured}
	}
	if got := byEnvironment[envTest].connections; got != 2 {
		t.Errorf("test connection count = %d, want 2", got)
	}
	if got := byEnvironment[envProd].connections; got != 1 {
		t.Errorf("prod connection count = %d, want 1", got)
	}

	createPath := listPath
	resp = env.do(t, http.MethodPost, createPath, map[string]any{
		"environment": envTest, "mode": "generated",
	}, &operator, true)
	requireStatus(t, resp, http.StatusCreated)
	if raw := string(readBody(t, resp)); strings.Contains(raw, "password") {
		t.Fatalf("create response contains secret-shaped field: %s", raw)
	}

	const marker = "provided-secret-must-not-replace"
	resp = env.do(t, http.MethodPost, createPath, map[string]any{
		"environment": envTest, "mode": "provided", "password": marker,
	}, &operator, true)
	requireStatus(t, resp, http.StatusOK)
	if strings.Contains(string(readBody(t, resp)), marker) {
		t.Fatal("idempotent create response leaks provided password")
	}
	path, err := vault.PrincipalEnvironmentCredentialPath(p.ID.String(), envTest)
	if err != nil {
		t.Fatalf("credential path: %v", err)
	}
	secret, _, err := vaultClient.Get(t.Context(), path)
	if err != nil {
		t.Fatalf("read generated credential: %v", err)
	}
	if secret["password"] == marker {
		t.Fatal("create overwrote existing credential; rotation must remain explicit")
	}

	resp = env.do(t, http.MethodPost, createPath, map[string]any{
		"environment": "missing-" + uuid.NewString(), "mode": "generated",
	}, &operator, true)
	requireStatus(t, resp, http.StatusBadRequest)

	// Offboard обратим: секреты переживают его целыми — уничтожает их только
	// истечение срока хранения. Без аккаунтов ротировать нечего (детей нет),
	// поэтому версии остаются прежними.
	resp = env.do(t, http.MethodPost, createPath, map[string]any{
		"environment": envProd, "mode": "generated",
	}, &operator, true)
	requireStatus(t, resp, http.StatusCreated)
	_ = readBody(t, resp)
	versionsBefore := map[string]int{}
	for _, environment := range []string{envTest, envProd} {
		path, pathErr := vault.PrincipalEnvironmentCredentialPath(p.ID.String(), environment)
		if pathErr != nil {
			t.Fatalf("credential path %s: %v", environment, pathErr)
		}
		_, version, getErr := vaultClient.Get(t.Context(), path)
		if getErr != nil {
			t.Fatalf("credential %s before offboard: %v", environment, getErr)
		}
		versionsBefore[environment] = version
	}
	resp = env.do(t, http.MethodPost,
		"/api/v1/principals/"+p.ID.String()+"/offboard?confirm=true", nil, &admin, true)
	requireStatus(t, resp, http.StatusOK)
	_ = readBody(t, resp)
	for _, environment := range []string{envTest, envProd} {
		path, pathErr := vault.PrincipalEnvironmentCredentialPath(p.ID.String(), environment)
		if pathErr != nil {
			t.Fatalf("credential path %s: %v", environment, pathErr)
		}
		_, version, getErr := vaultClient.Get(t.Context(), path)
		if getErr != nil {
			t.Errorf("credential %s after offboard: %v (offboard must be reversible)", environment, getErr)
			continue
		}
		if version != versionsBefore[environment] {
			t.Errorf("credential %s version = %d, want unchanged %d: there is no account to rotate",
				environment, version, versionsBefore[environment])
		}
	}
}
