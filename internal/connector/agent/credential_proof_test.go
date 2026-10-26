package agent_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/fake"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/connector/agent"
	"github.com/ArtefactoO/grantor/internal/connector/gateway"
)

type standaloneProver struct {
	adapter.Adapter
	calls *atomic.Int64
	seen  chan []byte
	err   error
	t     *testing.T
}

func (p standaloneProver) ProveCredential(_ context.Context, _ adapter.Connection, account adapter.Account, credential adapter.Credential) error {
	p.calls.Add(1)
	if account.EngineIdentity != "legacy_app" || credential.Username != account.EngineIdentity {
		p.t.Error("proof identity changed")
	}
	p.seen <- credential.Secret
	return p.err
}

func (p standaloneProver) RotateCredential(context.Context, adapter.Connection, adapter.Account, adapter.Credential) error {
	p.t.Error("standalone proof must never rotate")
	return errors.New("rotation forbidden")
}
func (p standaloneProver) Plan(context.Context, adapter.DesiredChange) (*adapter.Plan, error) {
	p.t.Error("standalone proof must never plan mutations")
	return nil, errors.New("mutation forbidden")
}

func TestStandaloneCredentialProofRoundTrip(t *testing.T) {
	for _, sv := range pairs(t) {
		for _, tc := range []struct {
			name, code                 string
			err                        error
			wrongIdentity, unsupported bool
		}{
			{name: "accepted"},
			{name: "rejected", code: "password_rejected", err: fmt.Errorf("proof-canary: %w", adapter.ErrExternalIdentityConflict)},
			{name: "unavailable", code: "target_unavailable", err: errors.New("proof-canary")},
			{name: "identity", code: "credential_identity_mismatch", wrongIdentity: true},
			{name: "unsupported", code: "credential_proof_unsupported", unsupported: true},
		} {
			t.Run(sv.name+"/"+tc.name, func(t *testing.T) {
				calls := &atomic.Int64{}
				seen := make(chan []byte, 1)
				rt := newRuntimeWith(t, sv, gateway.Config{}, agent.Config{Capabilities: []adapter.Capability{connector.CapCredentialProofV1}},
					func(string) (adapter.Adapter, error) {
						if tc.unsupported {
							return noProofRotatingAdapter{Adapter: fake.New(), rotateCalls: &atomic.Int64{}}, nil
						}
						return standaloneProver{Adapter: fake.New(), calls: calls, seen: seen, err: tc.err, t: t}, nil
					}, runtime{})
				payload, err := json.Marshal(connector.CredentialProofPayload{
					Connection: connector.ConnectionRef{ID: "conn", Engine: fake.Engine},
					Account:    connector.AccountRef{Kind: "login", EngineIdentity: "legacy_app"}, AccountID: "account",
				})
				if err != nil {
					t.Fatal(err)
				}
				job := connector.Job{ID: "proof", Kind: connector.JobProveCredential, ConnectionID: "conn", Engine: fake.Engine,
					ProtocolVersion: connector.ProtocolVersion, IdempotencyKey: "proof", Payload: payload}
				creds := adminCreds()
				username := "legacy_app"
				if tc.wrongIdentity {
					username = "someone_else"
				}
				creds.Account = &adapter.Credential{Kind: "password", Username: username, Secret: []byte("proof-canary")}
				creds.AccountVaultVersion = 7
				defer creds.Zero()
				res, err := rt.srv.Dispatch(t.Context(), job, creds)
				if err != nil {
					t.Fatal(err)
				}
				raw, _ := json.Marshal(res)
				if bytes.Contains(raw, []byte("proof-canary")) {
					t.Fatal("result leaked credential or adapter error")
				}
				if tc.code == "" {
					out, err := connector.ParseCredentialProofOutcome(res.Result)
					if err != nil || res.Status != connector.JobSuccess || out.VaultVersion != 7 || out.AccountID != "account" {
						t.Fatalf("proof not confirmed: %+v %v", res, err)
					}
				} else if res.Status != connector.JobFailed || res.ErrorCode != tc.code {
					t.Fatalf("unexpected result: %+v", res)
				}
				if tc.wrongIdentity || tc.unsupported {
					if calls.Load() != 0 {
						t.Fatal("invalid proof reached target")
					}
				} else {
					if calls.Load() != 1 {
						t.Fatal("proof was not called once")
					}
					material := <-seen
					if !bytes.Equal(material, make([]byte, len(material))) {
						t.Fatal("agent retained credential bytes")
					}
				}
			})
		}
	}
}
