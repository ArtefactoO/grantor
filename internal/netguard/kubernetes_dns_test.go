package netguard

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

type kubernetesResolver struct {
	canonical string
	answers   [][]net.IP
	lookups   int
}

func (r *kubernetesResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	if r.canonical != "" {
		return r.canonical, nil
	}
	return strings.TrimSuffix(host, ".") + ".", nil
}

func (r *kubernetesResolver) LookupIP(context.Context, string) ([]net.IP, error) {
	i := r.lookups
	r.lookups++
	if i >= len(r.answers) {
		return nil, errors.New("no DNS answer")
	}
	return r.answers[i], nil
}

func TestPrivateKubernetesDNSRejectsUnsafePeersBeforeDial(t *testing.T) {
	for _, address := range []string{"8.8.8.8", "127.0.0.1", "169.254.169.254", "169.254.1.2", "0.0.0.0", "224.0.0.1", "::1", "fe80::1", "fd00:ec2::254", "100.100.100.100"} {
		t.Run(address, func(t *testing.T) {
			resolver := &kubernetesResolver{answers: [][]net.IP{{net.ParseIP(address)}}}
			dial := NewGuardedDialerWithDial(Policy{PrivateKubernetesDNS: true}, resolver, func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("unsafe DNS answer reached TCP transport")
				return nil, nil
			})
			if _, err := dial.DialContext(t.Context(), "tcp", "kafka-cluster.betting-services.svc.cluster.local:9092"); err == nil {
				t.Fatal("unsafe DNS answer accepted")
			}
		})
	}
}

func TestPrivateKubernetesDNSRejectsExternalNameAndMixedAnswer(t *testing.T) {
	for _, resolver := range []*kubernetesResolver{
		{canonical: "private.corporate.example.", answers: [][]net.IP{{net.ParseIP("10.10.1.5")}}},
		{answers: [][]net.IP{{net.ParseIP("10.10.1.5"), net.ParseIP("8.8.8.8")}}},
	} {
		dial := NewGuardedDialerWithDial(Policy{PrivateKubernetesDNS: true}, resolver, func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("ExternalName or mixed DNS reached TCP transport")
			return nil, nil
		})
		if _, err := dial.DialContext(t.Context(), "tcp", "kafka-cluster.betting-services.svc.cluster.local:9092"); err == nil {
			t.Fatal("untrusted target accepted")
		}
	}
}

func TestPrivateKubernetesDNSPinsAnswerAndGuardsEveryAdvertisedDial(t *testing.T) {
	resolver := &kubernetesResolver{answers: [][]net.IP{{net.ParseIP("10.10.1.5")}, {net.ParseIP("8.8.8.8")}}}
	dials := 0
	dial := NewGuardedDialerWithDial(Policy{PrivateKubernetesDNS: true}, resolver, func(_ context.Context, network, address string) (net.Conn, error) {
		dials++
		if address != "10.10.1.5:9092" {
			t.Fatalf("transport re-resolved a name: %s", address)
		}
		client, peer := net.Pipe()
		t.Cleanup(func() { _ = client.Close(); _ = peer.Close() })
		return client, nil
	})
	if _, err := dial.DialContext(t.Context(), "tcp", "kafka-cluster.betting-services.svc.cluster.local:9092"); err != nil {
		t.Fatal(err)
	}
	if _, err := dial.DialContext(t.Context(), "tcp", "kafka-0.kafka-cluster.betting-services.svc.cluster.local:9092"); err == nil {
		t.Fatal("rebound advertised host accepted")
	}
	if resolver.lookups != 2 || dials != 1 {
		t.Fatalf("DNS lookups=%d TCP dials=%d", resolver.lookups, dials)
	}
}

func TestKubernetesDNSProfileIsNarrowAndDerived(t *testing.T) {
	endpoint := "kafka-cluster.betting-services.svc.cluster.local:9092"
	if KubernetesDNSNetworkGuard("connector", "disabled", []string{endpoint}) != PrivateKubernetesDNSV1 {
		t.Fatal("headless Service rejected")
	}
	for _, bad := range []string{"svc.cluster.local", "evil.svc.cluster.local", "kafka.test.svc.cluster.local.evil", "*.test.svc.cluster.local", "kafka..svc.cluster.local", "kafka_test.test.svc.cluster.local", "db.corporate.example"} {
		if IsKubernetesDNSHost(bad) {
			t.Fatalf("invalid K8s host accepted: %s", bad)
		}
	}
	for _, mode := range []string{"direct", ""} {
		if KubernetesDNSNetworkGuard(mode, "disabled", []string{endpoint}) != "" {
			t.Fatal("direct target received a connector DNS profile")
		}
	}
	if KubernetesDNSNetworkGuard("connector", "verify-ca", []string{endpoint}) != "" {
		t.Fatal("weak TLS upgraded to a plaintext DNS exception")
	}
	if KubernetesDNSNetworkGuard("connector", "disabled", []string{endpoint, "outside.example:9092"}) != "" {
		t.Fatal("mixed DNS target accepted")
	}
}
