package connector

import (
	"encoding/json"
	"errors"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

const CapRedisNoAuthV1 adapter.Capability = "redis.no_auth.v1"

// JobUsesRedisNoAuth checks only signed, secret-free descriptors. The active
// connector must negotiate this contract before receiving any job credentials.
func JobUsesRedisNoAuth(job Job) (bool, error) {
	if len(job.Payload) == 0 {
		return false, nil
	}
	var p struct {
		Connection        ConnectionRef `json:"connection"`
		CandidateAuthMode string        `json:"candidate_auth_mode"`
	}
	if err := json.Unmarshal(job.Payload, &p); err != nil {
		return false, errors.New("connector: invalid authentication descriptor")
	}
	for _, mode := range []string{p.Connection.AuthMode, p.CandidateAuthMode} {
		if mode != "" && mode != "password" && mode != "none" {
			return false, errors.New("connector: unknown authentication mode")
		}
	}
	required := p.Connection.AuthMode == "none" || p.CandidateAuthMode == "none"
	if required && (job.Engine != "redis" || p.Connection.Engine != "redis") {
		return false, errors.New("connector: no-auth is supported only for Redis")
	}
	if required && job.Kind != JobDiscover && job.Kind != JobAdminCredentialSwitch {
		return false, errors.New("connector: no-auth permits inventory and explicit admin switch only")
	}
	return required, nil
}
