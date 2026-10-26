package connector

import (
	"encoding/json"
	"errors"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/netguard"
)

const CapPrivateKubernetesDNSV1 adapter.Capability = "connector.private_kubernetes_dns.v1"

// JobNetworkGuard inspects the signed connection descriptor before a gateway
// sends credentials or an agent consumes them. Creation wraps this descriptor.
func JobNetworkGuard(job Job) (string, error) {
	if len(job.Payload) == 0 {
		return "", nil
	}
	var descriptor struct {
		Connection ConnectionRef `json:"connection"`
		Request    struct {
			Connection ConnectionRef `json:"connection"`
		} `json:"request"`
	}
	if err := json.Unmarshal(job.Payload, &descriptor); err != nil {
		return "", errors.New("connector: invalid network guard descriptor")
	}
	guard := descriptor.Connection.NetworkGuard
	if job.Kind == JobAccountCreation {
		guard = descriptor.Request.Connection.NetworkGuard
	}
	if guard != "" && guard != netguard.PrivateKubernetesDNSV1 {
		return "", errors.New("connector: unknown network guard profile")
	}
	return guard, nil
}
