//go:build integration

// Профиль connector'а (ADR-0019): имя и тип развёртывания — представление
// поверх CN сертификата, удаление записи допустимо только для offline.
package api_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/connectorstate"
)

type connectorsOut struct {
	Connectors []struct {
		ConnectorID      string `json:"connector_id"`
		Status           string `json:"status"`
		DisplayName      string `json:"display_name"`
		DeploymentKind   string `json:"deployment_kind"`
		DeploymentSource string `json:"deployment_source"`
	} `json:"connectors"`
}

func listConnectors(t *testing.T, env *testEnv, sess *auth.Session) connectorsOut {
	t.Helper()
	resp := env.do(t, http.MethodGet, "/api/v1/connectors", nil, sess, false)
	requireStatus(t, resp, http.StatusOK)
	var out connectorsOut
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode connectors: %v", err)
	}
	return out
}

func TestIntegrationConnectorProfile(t *testing.T) {
	env := newTestEnv(t, nil)
	admin := session(auth.RoleAdmin)
	operator := session(auth.RoleOperator)
	store := connectorstate.NewStore(env.pool)

	online := "itest-online-" + uniqueSuffix()[:8]
	offline := "itest-offline-" + uniqueSuffix()[:8]
	now := time.Now()
	// Агент объявил себя сам; вторая запись давно молчит — её и можно забыть.
	if err := store.Observe(t.Context(), connectorstate.Session{
		ConnectorID: online, ConnectedAt: now.Add(-time.Hour), LastSeenAt: now,
		CertificateNotAfter: now.Add(720 * time.Hour), ProtocolVersion: "v1",
		Capabilities: []string{"access.grant"},
		Deployment:   connectorstate.DeploymentKubernetes,
	}); err != nil {
		t.Fatalf("observe online: %v", err)
	}
	if err := store.Observe(t.Context(), connectorstate.Session{
		ConnectorID: offline, ConnectedAt: now.Add(-48 * time.Hour),
		LastSeenAt: now.Add(-47 * time.Hour), CertificateNotAfter: now.Add(720 * time.Hour),
		Capabilities: []string{},
	}); err != nil {
		t.Fatalf("observe offline: %v", err)
	}

	// Самообъявление агента видно и помечено своим источником.
	before := listConnectors(t, env, &admin)
	for _, item := range before.Connectors {
		if item.ConnectorID != online {
			continue
		}
		if item.DeploymentKind != connectorstate.DeploymentKubernetes || item.DeploymentSource != "agent" {
			t.Errorf("agent-declared deployment = %q/%q, want kubernetes/agent",
				item.DeploymentKind, item.DeploymentSource)
		}
	}

	path := "/api/v1/connectors/" + online
	// Профиль меняет только admin.
	resp := env.do(t, http.MethodPatch, path, map[string]any{"display_name": "Сегмент VDO"}, &operator, true)
	requireStatus(t, resp, http.StatusForbidden)
	// Неизвестный тип отклоняется, а не сохраняется как есть.
	resp = env.do(t, http.MethodPatch, path, map[string]any{"deployment_kind": "openshift"}, &admin, true)
	requireStatus(t, resp, http.StatusBadRequest)

	resp = env.do(t, http.MethodPatch, path,
		map[string]any{"display_name": "Сегмент VDO", "deployment_kind": "vm"}, &admin, true)
	requireStatus(t, resp, http.StatusOK)

	after := listConnectors(t, env, &admin)
	var seen bool
	for _, item := range after.Connectors {
		if item.ConnectorID != online {
			continue
		}
		seen = true
		if item.DisplayName != "Сегмент VDO" {
			t.Errorf("display_name = %q, want the operator value", item.DisplayName)
		}
		// Решение оператора сильнее самообъявления агента.
		if item.DeploymentKind != connectorstate.DeploymentVM || item.DeploymentSource != "operator" {
			t.Errorf("deployment = %q/%q, want vm/operator", item.DeploymentKind, item.DeploymentSource)
		}
	}
	if !seen {
		t.Fatalf("connector %q disappeared from the list", online)
	}

	// Пока connector на связи, забыть его нельзя: запись появится снова.
	resp = env.do(t, http.MethodDelete, path, nil, &admin, true)
	requireStatus(t, resp, http.StatusConflict)

	resp = env.do(t, http.MethodDelete, "/api/v1/connectors/"+offline, nil, &admin, true)
	requireStatus(t, resp, http.StatusNoContent)
	final := listConnectors(t, env, &admin)
	for _, item := range final.Connectors {
		if item.ConnectorID == offline {
			t.Errorf("connector %q is still listed after being forgotten", offline)
		}
	}
}
