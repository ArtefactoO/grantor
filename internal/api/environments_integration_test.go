//go:build integration

package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/principals"
)

// Реестр окружений позволяет подготовить env-credential принципала до
// первого подключения: раньше create отвечал 400 на любое окружение без
// connections.
func TestIntegrationEnvironmentRegistryEnablesEarlyCredential(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	admin := session(auth.RoleAdmin)
	operator := session(auth.RoleOperator)
	name := "registry-" + uuid.NewString()

	resp := env.do(t, http.MethodPost, "/api/v1/environments",
		map[string]any{"name": name}, &admin, true)
	requireStatus(t, resp, http.StatusCreated)
	_ = readBody(t, resp)

	// Дубликат — конфликт, а не молчаливый успех.
	resp = env.do(t, http.MethodPost, "/api/v1/environments",
		map[string]any{"name": name}, &admin, true)
	requireStatus(t, resp, http.StatusConflict)
	_ = readBody(t, resp)

	// Имя с '/' сломало бы Vault-путь секрета — отклоняется до базы.
	resp = env.do(t, http.MethodPost, "/api/v1/environments",
		map[string]any{"name": "bad/name"}, &admin, true)
	requireStatus(t, resp, http.StatusBadRequest)
	_ = readBody(t, resp)

	resp = env.do(t, http.MethodGet, "/api/v1/environments", nil, &operator, false)
	requireStatus(t, resp, http.StatusOK)
	var list struct {
		Environments []struct {
			Name string `json:"name"`
		} `json:"environments"`
	}
	if err := json.Unmarshal(readBody(t, resp), &list); err != nil {
		t.Fatalf("decode environments: %v", err)
	}
	found := false
	for _, item := range list.Environments {
		found = found || item.Name == name
	}
	if !found {
		t.Fatalf("environment %q missing from registry list", name)
	}

	p, err := principals.NewStore().Create(t.Context(), env.pool, principals.CreateParams{
		Type: principals.TypeHuman, DisplayName: "early credential " + uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create principal: %v", err)
	}
	credPath := "/api/v1/principals/" + p.ID.String() + "/credentials"

	// Окружение из реестра видно в списке ещё без единого подключения.
	resp = env.do(t, http.MethodGet, credPath, nil, &operator, false)
	requireStatus(t, resp, http.StatusOK)
	var creds principalCredentialListBody
	if err := json.Unmarshal(readBody(t, resp), &creds); err != nil {
		t.Fatalf("decode credentials: %v", err)
	}
	seen := false
	for _, item := range creds.Credentials {
		if item.Environment == name {
			seen = true
			if item.Connections != 0 {
				t.Errorf("registry environment connections = %d, want 0", item.Connections)
			}
		}
	}
	if !seen {
		t.Fatalf("registry environment %q missing from credential environments", name)
	}

	resp = env.do(t, http.MethodPost, credPath, map[string]any{
		"environment": name, "mode": "generated",
	}, &operator, true)
	requireStatus(t, resp, http.StatusCreated)
	_ = readBody(t, resp)
}
