package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ArtefactoO/grantor/internal/core/connectorstate"
)

// Тесты покрывали только чистые функции, поэтому инвертированное условие
// на rejectUnknownQuery дожило до продакшена: обработчик выходил до записи
// ответа, и вкладка получала пустое тело вместо envelope.
func TestListConnectorsAlwaysWritesEnvelope(t *testing.T) {
	rec := httptest.NewRecorder()
	(&Server{}).listConnectors(rec, httptest.NewRequest(http.MethodGet, "/api/v1/connectors", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var body struct {
		Connectors []connectorJSON `json:"connectors"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("тело ответа не разбирается как JSON (%q): %v", rec.Body.String(), err)
	}
	if body.Connectors == nil {
		t.Fatal("connectors = null, want []")
	}
}

func TestListConnectorsRejectsUnknownQuery(t *testing.T) {
	rec := httptest.NewRecorder()
	(&Server{}).listConnectors(rec, httptest.NewRequest(http.MethodGet, "/api/v1/connectors?tab=connectors", nil))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// Короткий разрыв во время перевыката control plane не должен выглядеть
// как потерянный сегмент.
func TestConnectorStatusTolerateShortSilence(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name     string
		lastSeen time.Time
		want     string
	}{
		{"только что", now.Add(-5 * time.Second), connectorStatusOnline},
		{"минуту назад", now.Add(-time.Minute), connectorStatusOnline},
		{"пять минут", now.Add(-5 * time.Minute), connectorStatusStale},
		{"час", now.Add(-time.Hour), connectorStatusOffline},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := connectorStatus(tc.lastSeen, now); got != tc.want {
				t.Fatalf("connectorStatus = %q, want %q", got, tc.want)
			}
		})
	}
}

// Истёкший сертификат остаётся видимым с отрицательным остатком: разница
// между «истёк вчера» и «истёк год назад» важна при разборе.
func TestConnectorViewKeepsExpiredCertificateVisible(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	view := connectorView(connectorstate.Session{
		ConnectorID:         "test",
		ConnectedAt:         now.Add(-2 * time.Hour),
		LastSeenAt:          now.Add(-30 * time.Second),
		CertificateNotAfter: now.Add(-48 * time.Hour),
		Capabilities:        []string{"discover"},
		ProtocolVersion:     "v1",
	}, connectorstate.Profile{}, now)

	if view.CertificateDaysLeft != -2 {
		t.Fatalf("CertificateDaysLeft = %d, want -2", view.CertificateDaysLeft)
	}
	if view.Status != connectorStatusOnline {
		t.Fatalf("Status = %q, want online: истёкший сертификат не отменяет связи", view.Status)
	}
}

func TestConnectorViewFormatsTimesAsRFC3339(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	view := connectorView(connectorstate.Session{
		ConnectorID:         "test",
		ConnectedAt:         now,
		LastSeenAt:          now,
		CertificateNotAfter: now.Add(24 * time.Hour),
	}, connectorstate.Profile{}, now)

	if _, err := time.Parse(time.RFC3339, view.CertificateNotAfter); err != nil {
		t.Fatalf("CertificateNotAfter не разбирается как RFC3339: %v", err)
	}
	if view.CertificateDaysLeft != 1 {
		t.Fatalf("CertificateDaysLeft = %d, want 1", view.CertificateDaysLeft)
	}
}

// Профиль оператора сильнее самообъявления агента: агент выводит среду
// эвристикой по окружению процесса, оператор знает, куда сегмент установлен.
func TestConnectorViewPrefersOperatorDeployment(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	session := connectorstate.Session{
		ConnectorID: "test", ConnectedAt: now, LastSeenAt: now,
		CertificateNotAfter: now.Add(24 * time.Hour),
		Deployment:          connectorstate.DeploymentKubernetes,
	}

	declared := connectorView(session, connectorstate.Profile{}, now)
	if declared.DeploymentKind != connectorstate.DeploymentKubernetes ||
		declared.DeploymentSource != connectorDeploymentAgent {
		t.Fatalf("declared = %q/%q, want kubernetes/agent",
			declared.DeploymentKind, declared.DeploymentSource)
	}

	overridden := connectorView(session, connectorstate.Profile{
		DisplayName: "Сегмент VDO", DeploymentKind: connectorstate.DeploymentVM,
	}, now)
	if overridden.DeploymentKind != connectorstate.DeploymentVM ||
		overridden.DeploymentSource != connectorDeploymentOperator {
		t.Fatalf("overridden = %q/%q, want vm/operator",
			overridden.DeploymentKind, overridden.DeploymentSource)
	}
	if overridden.DisplayName != "Сегмент VDO" {
		t.Errorf("DisplayName = %q, want the operator value", overridden.DisplayName)
	}
	// Идентификатор остаётся CN сертификата — имя его не подменяет.
	if overridden.ConnectorID != "test" {
		t.Errorf("ConnectorID = %q, want the certificate CN", overridden.ConnectorID)
	}
}
