package connector_test

import (
	"errors"
	"testing"

	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/netguard"
)

func TestNetworkGuardCannotBeRemovedFromSignedJob(t *testing.T) {
	payload := sampleDiscoverPayload()
	payload.Connection.NetworkGuard = netguard.PrivateKubernetesDNSV1
	raw, err := payload.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	key := []byte("synthetic-network-guard-signing-key")
	envelope, err := connector.SignJob(connector.NewHMACSigner("guard", key), connector.Job{
		ID: "guarded", Kind: connector.JobDiscover, ProtocolVersion: connector.ProtocolVersion, Payload: raw,
	})
	if err != nil {
		t.Fatal(err)
	}
	if guard, err := connector.JobNetworkGuard(envelope.Job); err != nil || guard != netguard.PrivateKubernetesDNSV1 {
		t.Fatal("guard profile lost")
	}
	payload.Connection.NetworkGuard = ""
	envelope.Job.Payload, err = payload.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := connector.VerifyEnvelope(connector.NewHMACVerifier("guard", key), envelope); !errors.Is(err, connector.ErrBadSignature) {
		t.Fatal("signed guard removal was accepted")
	}
	payload.Connection.NetworkGuard = "unknown-profile"
	envelope.Job.Payload, err = payload.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connector.JobNetworkGuard(envelope.Job); err == nil {
		t.Fatal("unknown guard profile accepted")
	}
}
