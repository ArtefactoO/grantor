package agent_test

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/fake"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/connector/agent"
	"github.com/ArtefactoO/grantor/internal/connector/gateway"
)

type deniedProofAccess struct {
	*fake.Fake
	rotations *atomic.Int64
}

func (a deniedProofAccess) CheckCredentialProofAccess(context.Context, adapter.Connection, adapter.Account) error {
	return adapter.ErrCredentialProofAccessDenied
}
func (a deniedProofAccess) RotateCredential(context.Context, adapter.Connection, adapter.Account, adapter.Credential) error {
	a.rotations.Add(1)
	return nil
}

func TestManagedLinkChecksDatabaseAdmissionBeforePasswordChange(t *testing.T) {
	for _, sv := range pairs(t) {
		t.Run(sv.name, func(t *testing.T) {
			rotations := &atomic.Int64{}
			rt := newRuntimeWith(t, sv, gateway.Config{}, agent.Config{}, func(string) (adapter.Adapter, error) {
				return deniedProofAccess{Fake: fake.New(), rotations: rotations}, nil
			}, runtime{})
			payload, err := (connector.RotatePayload{Connection: connector.ConnectionRef{ID: "c", Engine: fake.Engine},
				Account: connector.AccountRef{Kind: "login", EngineIdentity: "okorshunov"}, VerifyCredential: true}).Marshal()
			if err != nil {
				t.Fatal(err)
			}
			creds := adminCreds()
			creds.Account = &adapter.Credential{Kind: "password", Username: "okorshunov", Secret: []byte("never-applied")}
			defer creds.Zero()
			res, err := rt.srv.Dispatch(t.Context(), connector.Job{ID: "preflight", Kind: connector.JobRotateCredential, ConnectionID: "c", Engine: fake.Engine,
				ProtocolVersion: connector.ProtocolVersion, IdempotencyKey: "preflight", Payload: payload}, creds)
			if err != nil {
				t.Fatal(err)
			}
			if res.Status != connector.JobFailed || res.ErrorCode != "credential_access_denied" || rotations.Load() != 0 {
				t.Fatalf("preflight did not stop rotation: %+v rotations=%d", res, rotations.Load())
			}
		})
	}
}
