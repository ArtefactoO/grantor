package metrics

import (
	"testing"

	dto "github.com/prometheus/client_model/go"
)

// gather собирает текущее состояние registry прикладных метрик и
// возвращает семейство по имени (nil, если его нет).
func gather(t *testing.T, name string) *dto.MetricFamily {
	t.Helper()
	families, err := Gatherer().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() == name {
			return f
		}
	}
	return nil
}

// labelSet собирает пары label=value одной метрики в map для проверок.
func labelSet(m *dto.Metric) map[string]string {
	out := make(map[string]string, len(m.GetLabel()))
	for _, l := range m.GetLabel() {
		out[l.GetName()] = l.GetValue()
	}
	return out
}

func TestObserveCredentialRevealLabels(t *testing.T) {
	ObserveCredentialReveal(OperationAccountShare, ResultAllowed)
	ObserveCredentialReveal(OperationPrincipalShare, ResultLimited)

	fam := gather(t, "grantor_credential_reveal_total")
	if fam == nil {
		t.Fatal("grantor_credential_reveal_total not exported")
	}
	if fam.GetType() != dto.MetricType_COUNTER {
		t.Errorf("type = %v, want COUNTER", fam.GetType())
	}

	// Кардинальность лейблов ограничена: только operation и result, никаких
	// per-subject/per-secret меток (инвариант раздела 24).
	var found bool
	for _, m := range fam.GetMetric() {
		labels := labelSet(m)
		if len(labels) != 2 {
			t.Errorf("metric has %d labels %v, want exactly {operation, result}", len(labels), labels)
		}
		if _, ok := labels["operation"]; !ok {
			t.Errorf("missing operation label in %v", labels)
		}
		if _, ok := labels["result"]; !ok {
			t.Errorf("missing result label in %v", labels)
		}
		if labels["operation"] == OperationAccountShare && labels["result"] == ResultAllowed {
			found = true
			if got := m.GetCounter().GetValue(); got < 1 {
				t.Errorf("account_share/allowed counter = %v, want >= 1", got)
			}
		}
	}
	if !found {
		t.Error("no sample for operation=account_share result=allowed")
	}
}

func TestObserveCredentialRevealAnomalyLabels(t *testing.T) {
	ObserveCredentialRevealAnomaly(OperationAccountShare)

	fam := gather(t, "grantor_credential_reveal_anomaly_total")
	if fam == nil {
		t.Fatal("grantor_credential_reveal_anomaly_total not exported")
	}
	for _, m := range fam.GetMetric() {
		labels := labelSet(m)
		if len(labels) != 1 {
			t.Errorf("anomaly metric has %d labels %v, want exactly {operation}", len(labels), labels)
		}
		if _, ok := labels["operation"]; !ok {
			t.Errorf("missing operation label in %v", labels)
		}
	}
}

func TestAdminCredentialAgeGauge(t *testing.T) {
	ResetAdminCredentialAge()
	const connID = "11111111-1111-1111-1111-111111111111"
	SetAdminCredentialAge(connID, 4242)
	SetAdminCredentialAgedCount(3)

	fam := gather(t, "grantor_connection_admin_credential_age_seconds")
	if fam == nil {
		t.Fatal("grantor_connection_admin_credential_age_seconds not exported")
	}
	var got float64
	var seen bool
	for _, m := range fam.GetMetric() {
		labels := labelSet(m)
		if len(labels) != 1 || labels["connection_id"] == "" {
			t.Errorf("age gauge labels = %v, want exactly {connection_id}", labels)
		}
		if labels["connection_id"] == connID {
			seen = true
			got = m.GetGauge().GetValue()
		}
	}
	if !seen {
		t.Fatalf("no age gauge sample for connection %s", connID)
	}
	if got != 4242 {
		t.Errorf("age gauge = %v, want 4242", got)
	}

	agedFam := gather(t, "grantor_connection_admin_credential_aged")
	if agedFam == nil || len(agedFam.GetMetric()) == 0 {
		t.Fatal("grantor_connection_admin_credential_aged not exported")
	}
	if got := agedFam.GetMetric()[0].GetGauge().GetValue(); got != 3 {
		t.Errorf("aged count gauge = %v, want 3", got)
	}
}

func TestOffboardingIncompletePrincipalsGauge(t *testing.T) {
	SetOffboardingIncompletePrincipals(2)

	fam := gather(t, "grantor_offboarding_incomplete_principals")
	if fam == nil || len(fam.GetMetric()) == 0 {
		t.Fatal("grantor_offboarding_incomplete_principals not exported")
	}
	if fam.GetType() != dto.MetricType_GAUGE {
		t.Errorf("type = %v, want GAUGE", fam.GetType())
	}
	// Скалярный gauge: без лейблов (bounded cardinality).
	m := fam.GetMetric()[0]
	if len(m.GetLabel()) != 0 {
		t.Errorf("gauge has labels %v, want none", labelSet(m))
	}
	if got := m.GetGauge().GetValue(); got != 2 {
		t.Errorf("gauge = %v, want 2", got)
	}

	// Эвалуация без findings обнуляет gauge (не залипает на старом значении).
	SetOffboardingIncompletePrincipals(0)
	fam = gather(t, "grantor_offboarding_incomplete_principals")
	if got := fam.GetMetric()[0].GetGauge().GetValue(); got != 0 {
		t.Errorf("gauge after zero evaluation = %v, want 0", got)
	}
}

func TestObservePrincipalDisabledLabels(t *testing.T) {
	ObservePrincipalDisabled(ReasonDirectoryDisabled)
	ObservePrincipalDisabled(ReasonDirectoryMissing)

	fam := gather(t, "grantor_principals_disabled_total")
	if fam == nil {
		t.Fatal("grantor_principals_disabled_total not exported")
	}
	if fam.GetType() != dto.MetricType_COUNTER {
		t.Errorf("type = %v, want COUNTER", fam.GetType())
	}
	seen := map[string]bool{}
	for _, m := range fam.GetMetric() {
		labels := labelSet(m)
		// Кардинальность ограничена: только reason, без субъекта/id.
		if len(labels) != 1 {
			t.Errorf("metric has %d labels %v, want exactly {reason}", len(labels), labels)
		}
		reason, ok := labels["reason"]
		if !ok {
			t.Errorf("missing reason label in %v", labels)
			continue
		}
		seen[reason] = true
		if m.GetCounter().GetValue() < 1 {
			t.Errorf("counter for reason %q = %v, want >= 1", reason, m.GetCounter().GetValue())
		}
	}
	if !seen[ReasonDirectoryDisabled] || !seen[ReasonDirectoryMissing] {
		t.Errorf("seen reasons = %v, want both %q and %q", seen, ReasonDirectoryDisabled, ReasonDirectoryMissing)
	}
}

func TestResetAdminCredentialAgeClearsSeries(t *testing.T) {
	SetAdminCredentialAge("22222222-2222-2222-2222-222222222222", 1)
	ResetAdminCredentialAge()
	fam := gather(t, "grantor_connection_admin_credential_age_seconds")
	if fam != nil && len(fam.GetMetric()) != 0 {
		t.Errorf("age gauge has %d series after reset, want 0", len(fam.GetMetric()))
	}
}
