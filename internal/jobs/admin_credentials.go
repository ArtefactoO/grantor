package jobs

import (
	"encoding/json"
	"fmt"

	"github.com/ArtefactoO/grantor/internal/core/admincredentials"
)

const (
	KindConnectionAdminCredentialSwitch = "connection.admin_credential.switch"
	KindConnectionAdminCredentialRotate = "connection.admin_credential.rotate"
)

// AdminCredentialOperationPayload is deliberately secret-free. Vault stage
// coordinates and versions are read from the dedicated lifecycle row by
// operation id; payload only pins the immutable epoch/mode for stale-job
// detection and compatibility diagnostics.
type AdminCredentialOperationPayload struct {
	Mode  admincredentials.Mode `json:"mode"`
	Epoch int64                 `json:"epoch"`
}

func MarshalAdminCredentialOperationPayload(mode admincredentials.Mode, epoch int64) ([]byte, error) {
	if !mode.Valid() || epoch <= 0 {
		return nil, fmt.Errorf("jobs: invalid admin credential operation payload")
	}
	return json.Marshal(AdminCredentialOperationPayload{Mode: mode, Epoch: epoch})
}

func ParseAdminCredentialOperationPayload(raw []byte) (AdminCredentialOperationPayload, error) {
	var payload AdminCredentialOperationPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return AdminCredentialOperationPayload{}, fmt.Errorf("jobs: parse admin credential operation payload: %w", err)
	}
	if !payload.Mode.Valid() || payload.Epoch <= 0 {
		return AdminCredentialOperationPayload{}, fmt.Errorf("jobs: invalid admin credential operation payload")
	}
	return payload, nil
}
