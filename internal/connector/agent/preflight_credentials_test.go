package agent

import (
	"context"
	"crypto/tls"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/connector"
)

func TestRejectedMutationPreflightDoesNotWaitForOrConsumeCredentials(t *testing.T) {
	secret := []byte("connector-preflight-test")
	signer := connector.NewHMACSigner("preflight", secret)
	var adapterResolutions atomic.Int64
	agent, err := New(Config{
		GatewayAddr:        "unused.invalid:443",
		TLS:                &tls.Config{MinVersion: tls.VersionTLS12},
		Verifier:           connector.NewHMACVerifier("preflight", secret),
		CredentialsTimeout: 2 * time.Second,
		NewAdapter: func(string) (adapter.Adapter, error) {
			adapterResolutions.Add(1)
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	basePayload := func(change connector.ChangeRef) connector.MutationPayload {
		return connector.MutationPayload{
			Connection: connector.ConnectionRef{
				ID: "connection-id", Engine: "postgres", Endpoints: []string{"db:5432"},
				ConfigIncarnation: strings.Repeat("a", 64),
			},
			Change: change,
		}
	}
	baseJob := func(t *testing.T, id string, payload connector.MutationPayload) connector.Job {
		t.Helper()
		raw, err := payload.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return connector.Job{
			ID: id, Kind: connector.JobApply, ConnectionID: payload.Connection.ID,
			Engine: payload.Connection.Engine, ProtocolVersion: connector.ProtocolVersion,
			IssuedAt: time.Now().Unix(), IdempotencyKey: id, Nonce: id + "-nonce", Payload: raw,
		}
	}

	tests := []struct {
		name string
		job  func(*testing.T) connector.Job
		want string
	}{
		{
			name: "unknown job kind",
			job: func(t *testing.T) connector.Job {
				job := baseJob(t, "unknown-job", basePayload(connector.ChangeRef{
					Kind: string(adapter.ChangeGrant), Account: connector.AccountRef{Kind: "login", EngineIdentity: "service"},
					Permission: "role:r_app",
				}))
				job.Kind = connector.JobKind("job.raw_sql")
				return job
			},
			want: "unknown job kind",
		},
		{
			name: "unknown mutation kind",
			job: func(t *testing.T) connector.Job {
				return baseJob(t, "unknown-mutation", basePayload(connector.ChangeRef{Kind: "postgres.raw_sql.v99"}))
			},
			want: "is not allowed",
		},
		{
			name: "legacy PostgreSQL mutation",
			job: func(t *testing.T) connector.Job {
				return baseJob(t, "legacy-postgres", basePayload(connector.ChangeRef{
					Kind:    string(adapter.ChangeAccountCreate),
					Account: connector.AccountRef{Kind: "login", EngineIdentity: "service_app"},
				}))
			},
			want: "history-only",
		},
		{
			name: "PostgreSQL v2 mutation without advertised authority capability",
			job: func(t *testing.T) connector.Job {
				return baseJob(t, "phase-one-v2", basePayload(connector.ChangeRef{
					Kind:                     string(adapter.ChangePostgresDatabaseCreateV2),
					ExpectedAdminIdentity:    "grantor",
					ExpectedTargetIdentity:   "postgres:system:42",
					ExpectedDatabaseOwner:    "app_owner",
					ExpectedDatabaseOwnerOID: 17,
					Resource: &adapter.ResourceSpec{Kind: "database", Name: "app",
						Attributes: map[string]any{"owner": "app_owner"}},
				}))
			},
			want: "disabled in this connector build",
		},
		{
			name: "signed connection mismatch",
			job: func(t *testing.T) connector.Job {
				job := baseJob(t, "connection-mismatch", basePayload(connector.ChangeRef{
					Kind: string(adapter.ChangeGrant), Account: connector.AccountRef{Kind: "login", EngineIdentity: "service"},
					Permission: "role:r_app",
				}))
				job.ConnectionID = "different-connection"
				return job
			},
			want: "does not match mutation payload connection",
		},
		{
			name: "signed engine mismatch",
			job: func(t *testing.T) connector.Job {
				job := baseJob(t, "engine-mismatch", basePayload(connector.ChangeRef{
					Kind: string(adapter.ChangeGrant), Account: connector.AccountRef{Kind: "login", EngineIdentity: "service"},
					Permission: "role:r_app",
				}))
				job.Engine = "mongodb"
				return job
			},
			want: "does not match mutation payload engine",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			job := tc.job(t)
			envelope, err := connector.SignJob(signer, job)
			if err != nil {
				t.Fatal(err)
			}

			// An empty credentials channel would block for two seconds if the
			// preflight were ordered after the credentials wait.
			resultCh := make(chan connector.JobResult, 1)
			go func() {
				resultCh <- agent.handleJob(context.Background(), envelope, make(chan connector.CredentialsFrame))
			}()
			select {
			case result := <-resultCh:
				if result.Status != connector.JobFailed || !strings.Contains(result.Error, tc.want) {
					t.Fatalf("preflight result = %+v, want error containing %q", result, tc.want)
				}
			case <-time.After(500 * time.Millisecond):
				t.Fatal("rejected job waited for the credentials frame")
			}

			// A queued frame must remain untouched: the read loop owns cleanup
			// after the rejected job returns, not the preflight itself.
			frame := connector.JobCredentials{}.Frame(job)
			credentials := make(chan connector.CredentialsFrame, 1)
			credentials <- frame
			result := agent.handleJob(context.Background(), envelope, credentials)
			if result.Status != connector.JobFailed || len(credentials) != 1 {
				t.Fatalf("preflight consumed credentials: result=%+v queued=%d", result, len(credentials))
			}
			queued := <-credentials
			queued.Zero()
		})
	}
	if got := adapterResolutions.Load(); got != 0 {
		t.Fatalf("rejected preflights resolved an adapter or target %d times", got)
	}
}
