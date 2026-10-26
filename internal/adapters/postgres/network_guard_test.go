package postgres

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/netguard"
)

type postgresGuardResolver struct {
	canonical        string
	ips              []net.IP
	canonicalLookups atomic.Int64
}

func (r *postgresGuardResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	r.canonicalLookups.Add(1)
	if r.canonical != "" {
		return r.canonical, nil
	}
	return host, nil
}

func (r *postgresGuardResolver) LookupIP(context.Context, string) ([]net.IP, error) {
	if r.ips != nil {
		return r.ips, nil
	}
	return []net.IP{net.ParseIP("10.20.30.40")}, nil
}

func TestGuardedPostgresDriverDefersDNSUntilTransport(t *testing.T) {
	for _, tc := range []struct {
		name, canonical string
		ips             []net.IP
		allowed         bool
	}{
		{name: "external name with private IP", canonical: "private.corporate.example."},
		{name: "mixed private and public DNS", ips: []net.IP{net.ParseIP("10.20.30.40"), net.ParseIP("8.8.8.8")}},
		{name: "private Kubernetes peer", allowed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &postgresGuardResolver{canonical: tc.canonical, ips: tc.ips}
			var dials atomic.Int64
			guard := netguard.NewGuardedDialerWithDial(netguard.Policy{PrivateKubernetesDNS: true}, resolver,
				func(_ context.Context, _ string, address string) (net.Conn, error) {
					dials.Add(1)
					if address != "10.20.30.40:5432" {
						t.Errorf("unchecked hostname reached TCP: %s", address)
					}
					return nil, errors.New("fixture stops before PostgreSQL authentication")
				})
			cfg := adapter.Connection{Engine: Engine, Endpoints: []string{"database.monitor.svc.cluster.local:5432"},
				TLS: adapter.TLSConfig{Mode: "disabled"}, AdminCredential: adapter.Credential{
					Kind: "password", Username: "grantor", Secret: []byte("postgres-transport-canary"),
				}}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			err := NewWithDialer(guard.DialContext).ValidateConnection(ctx, cfg)
			cancel()
			if err == nil || strings.Contains(err.Error(), "postgres-transport-canary") {
				t.Fatal("failed transport accepted or leaked its credential")
			}
			if resolver.canonicalLookups.Load() != 1 {
				t.Fatal("pgx resolved before the guarded transport received the original hostname")
			}
			if tc.allowed && dials.Load() != 1 {
				t.Fatal("legitimate DNS did not reach its checked numeric IP")
			}
			if !tc.allowed && dials.Load() != 0 {
				t.Fatal("rejected DNS reached TCP transport")
			}
		})
	}
}

func TestDefaultPostgresConfigKeepsDriverDNSResolution(t *testing.T) {
	cc, err := connConfig(testConnection("disabled"), "postgres")
	if err != nil {
		t.Fatal(err)
	}
	addresses, err := cc.LookupFunc(t.Context(), "localhost")
	if err != nil || len(addresses) == 0 {
		t.Fatal("default pgx lookup unavailable")
	}
	for _, address := range addresses {
		if net.ParseIP(address) == nil {
			t.Fatal("default adapter unexpectedly deferred DNS")
		}
	}
}
