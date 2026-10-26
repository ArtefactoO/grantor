package agent

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
	"github.com/ArtefactoO/grantor/internal/adapters/kafka"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/netguard"
)

type badPeerResolver struct{ canonical, ip string }

func (r badPeerResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	if r.canonical != "" {
		return r.canonical, nil
	}
	return host, nil
}
func (r badPeerResolver) LookupIP(context.Context, string) ([]net.IP, error) {
	return []net.IP{net.ParseIP(r.ip)}, nil
}

func TestKafkaGuardedAdapterCannotTransmitCredentialToUnsafeDNS(t *testing.T) {
	for _, resolver := range []badPeerResolver{
		{ip: "8.8.8.8"}, {ip: "127.0.0.1"}, {ip: "169.254.169.254"},
		{canonical: "private.external.example", ip: "10.20.30.40"},
	} {
		a := &Agent{cfg: Config{
			Capabilities:   []adapter.Capability{connector.CapPrivateKubernetesDNSV1},
			TargetResolver: resolver,
			TargetDialContext: func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("unsafe target received a TCP connection")
				return nil, nil
			},
			NewAdapterWithDialer: func(_ string, dial adapterutil.DialContextFunc) (adapter.Adapter, error) {
				return kafka.NewWithDialer(dial), nil
			},
		}}
		ref := connector.ConnectionRef{Engine: "kafka", Endpoints: []string{"kafka-cluster.test.svc.cluster.local:9092"}, NetworkGuard: netguard.PrivateKubernetesDNSV1}
		ad, cfg, err := a.target("kafka", ref, connector.TLSRef{Mode: "disabled"}, map[string]any{"sasl_mechanism": "plain", "security_protocol": "sasl_plaintext"},
			&connector.FrameCredential{Kind: "password", Username: "existing-user", Secret: []byte("guarded-peer-canary")}, 1)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
		err = ad.ValidateConnection(ctx, cfg)
		cancel()
		if err == nil || strings.Contains(err.Error(), "guarded-peer-canary") {
			t.Fatal("unsafe peer accepted or credential leaked")
		}
	}
}

func TestGuardedJobRequiresRuntimeBeforeCredentialsWait(t *testing.T) {
	payload := connector.DiscoverPayload{Connection: connector.ConnectionRef{NetworkGuard: netguard.PrivateKubernetesDNSV1}}
	raw, err := payload.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	a := &Agent{}
	if err := a.preflightJob(connector.Job{Kind: connector.JobDiscover, Payload: raw}); err == nil {
		t.Fatal("legacy runtime accepted guarded job")
	}
}
