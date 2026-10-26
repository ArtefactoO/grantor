package agent_test

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
	"github.com/ArtefactoO/grantor/internal/adapters/fake"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/connector/agent"
	"github.com/ArtefactoO/grantor/internal/connector/gateway"
	"github.com/ArtefactoO/grantor/internal/netguard"
)

type roundtripDNS struct{ canonical, ip string }

func (r roundtripDNS) LookupCNAME(_ context.Context, host string) (string, error) {
	if r.canonical != "" {
		return r.canonical, nil
	}
	return host, nil
}
func (r roundtripDNS) LookupIP(context.Context, string) ([]net.IP, error) {
	return []net.IP{net.ParseIP(r.ip)}, nil
}

type credentialTransportAdapter struct {
	adapter.Adapter
	dial adapterutil.DialContextFunc
}

func (a credentialTransportAdapter) Discover(ctx context.Context, cfg adapter.Connection) (*adapter.Snapshot, error) {
	conn, err := a.dial(ctx, "tcp", cfg.Endpoints[0])
	if err != nil {
		return nil, err
	}
	defer conn.Close() //nolint:errcheck
	if _, err := conn.Write(cfg.AdminCredential.Secret); err != nil {
		return nil, err
	}
	return &adapter.Snapshot{ObservedAt: time.Now()}, nil
}

func TestPrivateDNSConnectorRoundTripGuardsTargetCredentialTransmission(t *testing.T) {
	for _, tc := range []struct {
		name     string
		dns      roundtripDNS
		accepted bool
	}{
		{"headless private", roundtripDNS{ip: "10.10.1.5"}, true},
		{"public", roundtripDNS{ip: "8.8.8.8"}, false},
		{"loopback", roundtripDNS{ip: "127.0.0.1"}, false},
		{"link local", roundtripDNS{ip: "169.254.1.5"}, false},
		{"externalname private", roundtripDNS{canonical: "private.corporate.example", ip: "10.10.1.5"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			canary := []byte("target-transport-canary")
			received := make(chan string, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close() //nolint:errcheck
				_ = conn.SetReadDeadline(time.Now().Add(time.Second))
				data := make([]byte, len(canary))
				_, err = io.ReadFull(conn, data)
				if err == nil {
					received <- string(data)
				}
			}()
			var dials atomic.Int64
			rt := newRuntimeWith(t, pairs(t)[0], gateway.Config{}, agent.Config{
				Capabilities: []adapter.Capability{connector.CapPrivateKubernetesDNSV1}, TargetResolver: tc.dns,
				TargetDialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
					dials.Add(1)
					if address != "10.10.1.5:9092" {
						return nil, netguard.ErrNotAllowed
					}
					// Redirect only the already checked numeric fixture address to
					// an owned loopback listener; production never re-resolves it.
					return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
				},
				NewAdapterWithDialer: func(_ string, dial adapterutil.DialContextFunc) (adapter.Adapter, error) {
					return credentialTransportAdapter{Adapter: fake.New(), dial: dial}, nil
				},
			}, func(string) (adapter.Adapter, error) { t.Fatal("guarded job used a legacy adapter"); return nil, nil }, runtime{})
			payload := connector.DiscoverPayload{Connection: connector.ConnectionRef{ID: "guarded-connection", Engine: "fake",
				Endpoints: []string{"kafka-cluster.test.svc.cluster.local:9092"}, NetworkGuard: netguard.PrivateKubernetesDNSV1}, TLS: connector.TLSRef{Mode: "disabled"}}
			raw, err := payload.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			result, err := rt.srv.Dispatch(t.Context(), connector.Job{ID: "guarded-roundtrip", ConnectionID: "guarded-connection", Engine: "fake",
				Kind: connector.JobDiscover, ProtocolVersion: connector.ProtocolVersion, Payload: raw}, connector.JobCredentials{
				Admin: &adapter.Credential{Kind: "password", Username: "existing-user", Secret: append([]byte(nil), canary...)},
			})
			if err != nil {
				t.Fatal(err)
			}
			if tc.accepted {
				if result.Status != connector.JobSuccess {
					t.Fatalf("legitimate DNS failed: %s", result.Error)
				}
				select {
				case got := <-received:
					if got != string(canary) {
						t.Fatal("credential changed")
					}
				case <-time.After(time.Second):
					t.Fatal("legitimate target received no credential")
				}
			} else {
				if result.Status != connector.JobFailed || dials.Load() != 0 {
					t.Fatal("unsafe DNS reached target TCP")
				}
				select {
				case <-received:
					t.Fatal("credential leaked to rejected peer")
				default:
				}
			}
		})
	}
}
