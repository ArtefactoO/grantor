package api

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/netguard"
)

// stubResolver — фейковый netguard.Resolver для unit-тестов без сети.
type stubResolver map[string][]net.IP

func (s stubResolver) LookupIP(_ context.Context, host string) ([]net.IP, error) {
	if ips, ok := s[host]; ok {
		return ips, nil
	}
	return nil, errors.New("stubResolver: no such host")
}

func TestCheckEndpointPolicy(t *testing.T) {
	_, priv, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	allowlist := netguard.Policy{AllowedCIDRs: []net.IPNet{*priv}, AllowedPorts: []int{5432}}

	cases := []struct {
		name     string
		policy   netguard.Policy
		resolver netguard.Resolver
		endpoint string
		wantErr  error  // errors.Is target; nil = без ошибки
		wantSub  string // подстрока сообщения при ошибке
	}{
		{
			name:     "metadata blocked on empty policy",
			endpoint: "169.254.169.254:5432",
			wantErr:  netguard.ErrBlockedAddress,
			wantSub:  "is not allowed",
		},
		{
			name:     "loopback blocked on empty policy",
			endpoint: "127.0.0.1:5432",
			wantErr:  netguard.ErrBlockedAddress,
			wantSub:  "is not allowed",
		},
		{
			name:     "private allowed on empty policy",
			endpoint: "10.1.2.3:5432",
			wantErr:  nil,
		},
		{
			name:     "public allowed on empty policy",
			endpoint: "8.8.8.8:5432",
			wantErr:  nil,
		},
		{
			name:     "invalid port format",
			endpoint: "host:bogus",
			wantSub:  "invalid port",
		},
		{
			name:     "in allowlist",
			policy:   allowlist,
			endpoint: "10.1.2.3:5432",
			wantErr:  nil,
		},
		{
			name:     "outside allowlist cidr",
			policy:   allowlist,
			endpoint: "192.168.1.1:5432",
			wantErr:  netguard.ErrNotAllowed,
			wantSub:  "is not allowed",
		},
		{
			name:     "port outside allowlist",
			policy:   allowlist,
			endpoint: "10.1.2.3:6379",
			wantErr:  netguard.ErrNotAllowed,
			wantSub:  "is not allowed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkEndpointPolicy(t.Context(), tc.policy, tc.resolver, tc.endpoint)
			switch {
			case tc.wantErr == nil && tc.wantSub == "":
				if err != nil {
					t.Fatalf("checkEndpointPolicy(%q) = %v, want nil", tc.endpoint, err)
				}
			default:
				if err == nil {
					t.Fatalf("checkEndpointPolicy(%q) = nil, want error", tc.endpoint)
				}
				if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
					t.Errorf("error %v does not wrap %v", err, tc.wantErr)
				}
				if tc.wantSub != "" && !strings.Contains(err.Error(), tc.wantSub) {
					t.Errorf("error %q does not contain %q", err, tc.wantSub)
				}
			}
		})
	}

	// Резолвинг hostname через фейковый resolver: metadata среди IP → блок.
	res := stubResolver{"target-postgres": {net.ParseIP("10.1.2.3")}}
	if err := checkEndpointPolicy(t.Context(), netguard.Policy{}, res, "target-postgres:5432"); err != nil {
		t.Errorf("resolved private host = %v, want nil", err)
	}
	rebind := stubResolver{"evil": {net.ParseIP("10.1.2.3"), net.ParseIP("169.254.169.254")}}
	if err := checkEndpointPolicy(t.Context(), netguard.Policy{}, rebind, "evil:5432"); !errors.Is(err, netguard.ErrBlockedAddress) {
		t.Errorf("rebinding host error = %v, want ErrBlockedAddress", err)
	}
}

func TestCheckEndpointPolicyDoesNotLeakResolvedIP(t *testing.T) {
	// Ошибка не должна содержать резолвленный внутренний адрес.
	res := stubResolver{"evil": {net.ParseIP("169.254.169.254")}}
	err := checkEndpointPolicy(t.Context(), netguard.Policy{}, res, "evil:5432")
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "169.254.169.254") {
		t.Errorf("error %q leaks resolved IP", err)
	}
}

// TestSecurityFindings проверяет маппинг эффективного режима tls_config
// (и topology.server_supports_tls) в security-findings.
func TestSecurityFindings(t *testing.T) {
	boolPtr := func(b bool) *bool { return &b }
	// topology строит topology-документ с ключом server_supports_tls; nil —
	// topology без ключа (discovery не определял поддержку TLS).
	topology := func(supported *bool) json.RawMessage {
		if supported == nil {
			return nil
		}
		b, err := json.Marshal(map[string]any{"server_supports_tls": *supported})
		if err != nil {
			t.Fatalf("marshal topology: %v", err)
		}
		return b
	}
	cases := []struct {
		name     string
		tls      string
		topology *bool // nil = topology без ключа server_supports_tls
		want     []string
	}{
		{"empty -> disabled", "", nil, []string{findingTLSDisabled}},
		{"empty object -> disabled", "{}", nil, []string{findingTLSDisabled}},
		{"explicit disabled", `{"mode":"disabled"}`, nil, []string{findingTLSDisabled}},
		{"malformed -> disabled", `{not json`, nil, []string{findingTLSDisabled}},
		{"disabled + server supports tls", `{"mode":"disabled"}`, boolPtr(true),
			[]string{findingTLSDisabled, findingTLSAvailableButDisabled}},
		{"empty + server supports tls", "", boolPtr(true),
			[]string{findingTLSDisabled, findingTLSAvailableButDisabled}},
		{"disabled + server no tls", `{"mode":"disabled"}`, boolPtr(false), []string{findingTLSDisabled}},
		{"require without ca", `{"mode":"require"}`, nil, []string{findingTLSNoCertVerify}},
		{"require with ca", `{"mode":"require","ca_cert_pem":"pem"}`, nil, nil},
		{"require insecure_skip_verify despite ca", `{"mode":"require","ca_cert_pem":"pem","insecure_skip_verify":true}`, nil,
			[]string{findingTLSNoCertVerify}},
		{"verify-ca clean", `{"mode":"verify-ca","ca_cert_pem":"pem"}`, nil, nil},
		{"verify-full clean", `{"mode":"verify-full","ca_cert_pem":"pem"}`, nil, nil},
		{"verify-full insecure_skip_verify", `{"mode":"verify-full","insecure_skip_verify":true}`, nil,
			[]string{findingTLSNoCertVerify}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var raw json.RawMessage
			if tc.tls != "" {
				raw = json.RawMessage(tc.tls)
			}
			conn := connections.Connection{TLSConfig: raw, Topology: topology(tc.topology)}
			if got := securityFindings(conn); !slices.Equal(got, tc.want) {
				t.Errorf("securityFindings(tls=%q, topology=%v) = %v, want %v", tc.tls, tc.topology, got, tc.want)
			}
		})
	}
}

func TestToConnectionJSONSecurityFindings(t *testing.T) {
	// Пустой tls_config = соединение без шифрования: finding tls_disabled.
	plain := toConnectionJSON(connections.Connection{}, nil)
	if !slices.Contains(plain.SecurityFindings, findingTLSDisabled) {
		t.Errorf("SecurityFindings = %v, want %q", plain.SecurityFindings, findingTLSDisabled)
	}

	// verify-full с CA — findings нет (nil → omitempty в JSON).
	secure := toConnectionJSON(connections.Connection{
		TLSConfig: json.RawMessage(`{"mode":"verify-full","ca_cert_pem":"pem"}`),
	}, nil)
	if secure.SecurityFindings != nil {
		t.Errorf("SecurityFindings = %v, want nil", secure.SecurityFindings)
	}
	b, err := json.Marshal(secure)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "security_findings") {
		t.Errorf("empty findings must be omitted from JSON: %s", b)
	}
}
