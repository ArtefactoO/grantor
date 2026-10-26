package jobs

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/operations"
)

func adminCredentialConnectorFixture() (operations.Operation, connections.Connection, adapter.Connection) {
	connID := uuid.New()
	return operations.Operation{ID: uuid.New()}, connections.Connection{
			ID: connID, Engine: "postgres", Endpoints: []string{"db.internal:5432"},
		}, adapter.Connection{
			ID: connID.String(), Engine: "postgres", Endpoints: []string{"db.internal:5432"},
			TLS:        adapter.TLSConfig{Mode: "verify-full", CACertPEM: []byte("public-ca")},
			Attributes: map[string]any{"database": "postgres"},
			AdminCredential: adapter.Credential{
				Kind: "password", Username: "grantor_admin", Secret: []byte("old-secret-canary"),
			},
		}
}

func TestConnectorAdminCredentialJobUsesDedicatedKindsAndSecretFreeIntent(t *testing.T) {
	op, conn, cfg := adminCredentialConnectorFixture()
	now := time.Unix(1_700_000_000, 0)
	for _, tc := range []struct {
		mode connector.AdminCredentialMode
		kind connector.JobKind
	}{
		{connector.AdminCredentialModeSwitch, connector.JobAdminCredentialSwitch},
		{connector.AdminCredentialModeRotate, connector.JobAdminCredentialRotate},
	} {
		t.Run(string(tc.mode), func(t *testing.T) {
			expected := adapter.AdminCredentialProof{}
			if tc.mode == connector.AdminCredentialModeRotate {
				expected = adapter.AdminCredentialProof{
					CanonicalIdentity: "grantor_admin", AuthorityFingerprint: "authority",
					TargetIdentity: "postgres:system:1",
				}
			}
			job, err := connectorAdminCredentialJob(op, conn, cfg, tc.mode, "grantor_admin", 5, 8, expected, now)
			if err != nil {
				t.Fatalf("connectorAdminCredentialJob: %v", err)
			}
			if job.Kind != tc.kind || job.Kind == connector.JobRotateCredential {
				t.Fatalf("job kind = %q, want dedicated %q", job.Kind, tc.kind)
			}
			payload, err := connector.ParseAdminCredentialPayload(job.Payload)
			if err != nil {
				t.Fatalf("ParseAdminCredentialPayload: %v", err)
			}
			if payload.Mode != tc.mode || payload.Epoch != 5 || payload.CandidateUsername != "grantor_admin" {
				t.Fatalf("payload = %+v", payload)
			}
			if strings.Contains(string(job.Payload), "old-secret-canary") {
				t.Fatalf("old credential leaked into payload: %s", job.Payload)
			}
			var raw any
			if err := json.Unmarshal(job.Payload, &raw); err != nil {
				t.Fatalf("unmarshal payload: %v", err)
			}
			assertNoSecretKeys(t, "payload", raw)

			again, err := connectorAdminCredentialJob(op, conn, cfg, tc.mode, "grantor_admin", 5, 8, expected, now)
			if err != nil {
				t.Fatalf("repeat builder: %v", err)
			}
			if again.IdempotencyKey != job.IdempotencyKey {
				t.Fatalf("same immutable intent changed idempotency key: %q != %q",
					again.IdempotencyKey, job.IdempotencyKey)
			}
			changed, err := connectorAdminCredentialJob(op, conn, cfg, tc.mode, "grantor_admin", 5, 9, expected, now)
			if err != nil {
				t.Fatalf("changed version builder: %v", err)
			}
			if changed.IdempotencyKey == job.IdempotencyKey {
				t.Fatal("different staged Vault version reused a cached-success key")
			}
		})
	}
	if _, err := connectorAdminCredentialJob(op, conn, cfg,
		connector.AdminCredentialModeSwitch, "grantor_admin", 1, 0, adapter.AdminCredentialProof{}, now); err == nil {
		t.Fatal("builder accepted a non-exact staged Vault version")
	}
}

type adminCredentialConnectorDispatcher struct {
	t             *testing.T
	wantMode      connector.AdminCredentialMode
	wantEpoch     int64
	wantVersion   int
	wantCandidate string
	wantOld       string
	outcome       connector.AdminCredentialOutcome
}

func (d *adminCredentialConnectorDispatcher) Dispatch(
	_ context.Context,
	job connector.Job,
	creds connector.JobCredentials,
) (connector.JobResult, error) {
	d.t.Helper()
	payload, err := connector.ParseAdminCredentialPayload(job.Payload)
	if err != nil {
		d.t.Fatalf("parse dispatched payload: %v", err)
	}
	if payload.Mode != d.wantMode || payload.Epoch != d.wantEpoch {
		d.t.Fatalf("dispatched payload = %+v", payload)
	}
	if creds.Account == nil || creds.Account.Username != d.wantCandidate ||
		string(creds.Account.Secret) != "candidate-secret-canary" ||
		creds.AccountVaultVersion != d.wantVersion {
		d.t.Fatalf("candidate frame mismatch: account=%+v version=%d", creds.Account, creds.AccountVaultVersion)
	}
	if d.wantOld != "" && (creds.Admin == nil || creds.Admin.Username != d.wantOld ||
		string(creds.Admin.Secret) != "old-secret-canary") {
		d.t.Fatalf("old canonical frame mismatch: %+v", creds.Admin)
	}
	raw, err := d.outcome.Marshal()
	if err != nil {
		d.t.Fatalf("marshal stub outcome: %v", err)
	}
	return connector.JobResult{JobID: job.ID, Status: connector.JobSuccess, Result: raw}, nil
}

func TestConnectorAdminCredentialChangeChecksEchoAndPreservesCallerCandidate(t *testing.T) {
	op, conn, cfg := adminCredentialConnectorFixture()
	candidate := adapter.Credential{
		Kind: "password", Username: "grantor_admin", Secret: []byte("candidate-secret-canary"),
	}
	snapshot := &adapter.Snapshot{ServerVersion: "16.4"}
	outcome := connector.AdminCredentialOutcome{
		Mode: connector.AdminCredentialModeRotate, Epoch: 11,
		CandidateUsername: candidate.Username, StagedVaultVersion: 14,
		Proof: adapter.AdminCredentialProof{
			CanonicalIdentity: "grantor_admin", AuthorityFingerprint: "authority",
		},
		Snapshot: snapshot,
	}
	dispatcher := &adminCredentialConnectorDispatcher{
		t: t, wantMode: outcome.Mode, wantEpoch: outcome.Epoch,
		wantVersion: outcome.StagedVaultVersion, wantCandidate: candidate.Username,
		wantOld: cfg.AdminCredential.Username, outcome: outcome,
	}
	executor := NewMainExecutor(DiscoveryDeps{}).WithConnector(ConnectorDeps{Dispatcher: dispatcher})
	got, err := executor.connectorAdminCredentialChange(t.Context(), op, conn, cfg,
		outcome.Mode, candidate, outcome.Epoch, outcome.StagedVaultVersion,
		adapter.AdminCredentialProof{CanonicalIdentity: candidate.Username,
			AuthorityFingerprint: "authority", TargetIdentity: "postgres:system:1"})
	if err != nil {
		t.Fatalf("connectorAdminCredentialChange: %v", err)
	}
	if got.Snapshot == nil || got.Snapshot.ServerVersion != "16.4" {
		t.Fatalf("outcome = %+v", got)
	}
	// connectorDispatch zeroes its frame copies, not the staged value still
	// needed by the control plane for canonical CAS promotion.
	if string(candidate.Secret) != "candidate-secret-canary" ||
		string(cfg.AdminCredential.Secret) != "old-secret-canary" {
		t.Fatal("connector dispatch zeroed caller-owned credentials needed after proof")
	}

	dispatcher.outcome.Epoch++
	if _, err := executor.connectorAdminCredentialChange(t.Context(), op, conn, cfg,
		outcome.Mode, candidate, outcome.Epoch, outcome.StagedVaultVersion,
		adapter.AdminCredentialProof{CanonicalIdentity: candidate.Username,
			AuthorityFingerprint: "authority", TargetIdentity: "postgres:system:1"}); err == nil ||
		!strings.Contains(err.Error(), "mismatched admin credential intent") {
		t.Fatalf("mismatched outcome error = %v", err)
	}
}
