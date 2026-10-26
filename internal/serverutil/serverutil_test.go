package serverutil

import (
	"net"
	"testing"
	"time"
)

func TestEndpointPolicyFromEnv(t *testing.T) {
	t.Setenv("GRANTOR_ENDPOINT_ALLOWED_CIDRS", "10.0.0.0/8, 192.168.0.0/16")
	t.Setenv("GRANTOR_ENDPOINT_ALLOWED_PORTS", "5432, 6379")
	t.Setenv("GRANTOR_ENDPOINT_ALLOWED_DNS_SUFFIXES", "db.internal, .svc.cluster.local")

	policy, err := EndpointPolicyFromEnv()
	if err != nil {
		t.Fatalf("EndpointPolicyFromEnv: %v", err)
	}
	if len(policy.AllowedCIDRs) != 2 || !policy.AllowedCIDRs[0].Contains(net.ParseIP("10.1.2.3")) {
		t.Fatalf("AllowedCIDRs = %v, want configured networks", policy.AllowedCIDRs)
	}
	if len(policy.AllowedPorts) != 2 || policy.AllowedPorts[0] != 5432 || policy.AllowedPorts[1] != 6379 {
		t.Fatalf("AllowedPorts = %v, want [5432 6379]", policy.AllowedPorts)
	}
	wantSuffixes := []string{".db.internal", ".svc.cluster.local"}
	for i := range wantSuffixes {
		if len(policy.AllowedDNSSuffixes) <= i || policy.AllowedDNSSuffixes[i] != wantSuffixes[i] {
			t.Fatalf("AllowedDNSSuffixes = %v, want %v", policy.AllowedDNSSuffixes, wantSuffixes)
		}
	}
}

func TestEndpointPolicyFromEnvRejectsInvalidConfiguration(t *testing.T) {
	t.Setenv("GRANTOR_ENDPOINT_ALLOWED_PORTS", "not-a-port")
	if _, err := EndpointPolicyFromEnv(); err == nil {
		t.Fatal("EndpointPolicyFromEnv must reject invalid port")
	}
}

func TestEnvDuration(t *testing.T) {
	t.Run("parses valid duration", func(t *testing.T) {
		t.Setenv("GRANTOR_TEST_DUR", "90m")
		if got := EnvDuration("GRANTOR_TEST_DUR", time.Hour); got != 90*time.Minute {
			t.Errorf("EnvDuration = %v, want %v", got, 90*time.Minute)
		}
	})
	t.Run("empty falls back to default", func(t *testing.T) {
		if got := EnvDuration("GRANTOR_TEST_DUR_UNSET", time.Hour); got != time.Hour {
			t.Errorf("EnvDuration = %v, want %v", got, time.Hour)
		}
	})
	t.Run("invalid falls back to default", func(t *testing.T) {
		t.Setenv("GRANTOR_TEST_DUR_BAD", "not-a-duration")
		if got := EnvDuration("GRANTOR_TEST_DUR_BAD", 5*time.Second); got != 5*time.Second {
			t.Errorf("EnvDuration = %v, want %v", got, 5*time.Second)
		}
	})
}
