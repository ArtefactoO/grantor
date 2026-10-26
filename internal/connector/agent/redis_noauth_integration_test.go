//go:build integration

package agent_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	redisadapter "github.com/ArtefactoO/grantor/internal/adapters/redis"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/connector/agent"
	"github.com/ArtefactoO/grantor/internal/connector/gateway"
)

func TestRedisNoAuthConnectorActualDiscoveryAndSwitch(t *testing.T) {
	addr := os.Getenv("GRANTOR_TEST_REDIS_NOAUTH_ADDR")
	if addr == "" {
		t.Skip("GRANTOR_TEST_REDIS_NOAUTH_ADDR is required")
	}
	rt := newRuntimeWith(t, pairs(t)[0], gateway.Config{}, agent.Config{Capabilities: []adapter.Capability{connector.CapRedisNoAuthV1}}, func(engine string) (adapter.Adapter, error) { return redisadapter.New(), nil }, runtime{})
	ref := connector.ConnectionRef{ID: "redis-noauth", Engine: "redis", AuthMode: "none", Endpoints: []string{addr}}
	raw, err := (connector.DiscoverPayload{Connection: ref}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	job := connector.Job{ID: "redis-noauth-discover", Kind: connector.JobDiscover, Engine: "redis", ConnectionID: ref.ID, ProtocolVersion: connector.ProtocolVersion, IdempotencyKey: "redis-noauth-discover", Payload: raw}
	result, err := rt.srv.Dispatch(t.Context(), job, connector.JobCredentials{})
	if err != nil || result.Status != connector.JobSuccess {
		t.Fatalf("discovery result %+v error %v", result, err)
	}
	badFrameJob := job
	badFrameJob.ID = "noauth-unexpected-credential"
	badFrameJob.IdempotencyKey = badFrameJob.ID
	badFrame, frameErr := rt.srv.Dispatch(t.Context(), badFrameJob, connector.JobCredentials{Admin: &adapter.Credential{Kind: "password", Username: "default", Secret: []byte("unexpected-test-credential")}})
	if frameErr != nil || badFrame.Status != connector.JobFailed {
		t.Fatalf("no-auth accepted unexpected Admin credentials: %+v %v", badFrame, frameErr)
	}
	var snap adapter.Snapshot
	if err = json.Unmarshal(result.Result, &snap); err != nil {
		t.Fatal(err)
	}
	if snap.Topology["authentication_enabled"] != false {
		t.Fatalf("missing no-auth status %v", snap.Topology)
	}
	ref.AuthMode = "password"
	raw, err = (connector.AdminCredentialPayload{Connection: ref, Mode: connector.AdminCredentialModeSwitch, CandidateUsername: "default", CandidateAuthMode: "none", Epoch: 1}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	job.ID = "redis-noauth-switch"
	job.Kind = connector.JobAdminCredentialSwitch
	job.IdempotencyKey = job.ID
	job.Payload = raw
	result, err = rt.srv.Dispatch(t.Context(), job, connector.JobCredentials{})
	if err != nil || result.Status != connector.JobSuccess {
		t.Fatalf("switch result %+v error %v", result, err)
	}
	outcome, err := connector.ParseAdminCredentialOutcome(result.Result)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.CandidateAuthMode != "none" || outcome.StagedVaultVersion != 0 || outcome.Proof.TargetIdentity == "" {
		t.Fatalf("invalid no-auth proof %+v", outcome)
	}
}
