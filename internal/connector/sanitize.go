package connector

// Sanitized-проекции adapter.Plan/Result/Verification — ЕДИНСТВЕННАЯ форма, в
// которой план и результат мутации существуют вне памяти процесса: и в
// operations.plan/result metadata DB (direct-исполнение, internal/jobs), и в
// JobResult.Plan/Result протокола connector. Секретные поля DesiredChange
// (credential учётной записи, admin credential подключения) в проекции
// структурно отсутствуют, поэтому один и тот же marshaling обслуживает оба
// пути и инвариант «no secrets in job payload/result» (раздел 24) не зависит
// от дисциплины вызывающего. Формат полей зафиксирован этапом 1b (прежние
// planJSON/resultJSON internal/jobs) и не меняется: строки operations,
// записанные до этапа 3, читаются теми же типами.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

// SanitizedPlan — sanitized-проекция adapter.Plan.
type SanitizedPlan struct {
	Change SanitizedChange     `json:"change"`
	Steps  []SanitizedPlanStep `json:"steps"`
}

// SanitizedChange — несекретная проекция adapter.DesiredChange: вид изменения
// и external id участников. Credential и admin credential сюда не входят.
type SanitizedChange struct {
	Kind       string `json:"kind"`
	Account    string `json:"account,omitempty"`
	Permission string `json:"permission,omitempty"`
	Scope      string `json:"scope,omitempty"`
}

// SanitizedPlanStep — один шаг плана. Description и Attributes по контракту
// adapter не содержат секретов (показываются в UI).
type SanitizedPlanStep struct {
	Kind        string         `json:"kind"`
	Description string         `json:"description"`
	Attributes  map[string]any `json:"attributes,omitempty"`
}

// SanitizedResult — sanitized-проекция adapter.Result и read-back verify.
type SanitizedResult struct {
	Steps        []SanitizedStepResult  `json:"steps"`
	Verification *SanitizedVerification `json:"verification,omitempty"`
}

// SanitizedStepResult — результат одного шага; Error по контракту adapter
// sanitized (DDL с паролём редуцируется до SQLSTATE).
type SanitizedStepResult struct {
	Kind   string `json:"kind"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// SanitizedVerification — результат read-back проверки после Apply.
type SanitizedVerification struct {
	Verified bool           `json:"verified"`
	Details  string         `json:"details,omitempty"`
	Observed map[string]any `json:"observed,omitempty"`
}

// MarshalSanitizedPlan строит sanitized json плана для operations.plan и
// JobResult.Plan.
func MarshalSanitizedPlan(plan *adapter.Plan) ([]byte, error) {
	out := SanitizedPlan{
		Change: SanitizedChange{
			Kind:       string(plan.Change.Kind),
			Account:    plan.Change.Account.EngineIdentity,
			Permission: plan.Change.Permission,
			Scope:      plan.Change.Scope,
		},
		Steps: make([]SanitizedPlanStep, 0, len(plan.Steps)),
	}
	for _, step := range plan.Steps {
		out.Steps = append(out.Steps, SanitizedPlanStep{
			Kind:        step.Kind,
			Description: step.Description,
			Attributes:  step.Attributes,
		})
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("connector: marshal sanitized plan: %w", err)
	}
	return b, nil
}

// MarshalSanitizedResult строит sanitized json результата применения (и, если
// ver != nil, read-back verify) для operations.result и JobResult.Result.
func MarshalSanitizedResult(res *adapter.Result, ver *adapter.Verification) ([]byte, error) {
	out := SanitizedResult{Steps: make([]SanitizedStepResult, 0, len(res.Steps))}
	for _, step := range res.Steps {
		out.Steps = append(out.Steps, SanitizedStepResult{
			Kind:   step.Step.Kind,
			Status: string(step.Status),
			Error:  step.Error,
		})
	}
	if ver != nil {
		observed, err := sanitizedDatabaseObservation(ver.Observed)
		if err != nil {
			return nil, err
		}
		out.Verification = &SanitizedVerification{Verified: ver.Verified, Details: ver.Details, Observed: observed}
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("connector: marshal sanitized result: %w", err)
	}
	return b, nil
}

// ParseSanitizedResult разбирает sanitized json результата (JobResult.Result
// мутирующего задания): operation engine достаёт из него verification, не
// переисполняя adapter.
func ParseSanitizedResult(raw []byte) (SanitizedResult, error) {
	if len(raw) == 0 {
		return SanitizedResult{}, fmt.Errorf("connector: sanitized result is empty")
	}
	var out SanitizedResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return SanitizedResult{}, fmt.Errorf("connector: parse sanitized result: %w", err)
	}
	if out.Verification != nil {
		observed, err := sanitizedDatabaseObservation(out.Verification.Observed)
		if err != nil {
			return SanitizedResult{}, err
		}
		out.Verification.Observed = observed
	}
	return out, nil
}

// Verification observations have two closed, primitive-only projections:
// database creation receipt and PostgreSQL role-policy exactness. Arbitrary
// adapter attributes cannot become a new route for secrets or commands.
func sanitizedDatabaseObservation(observed map[string]any) (map[string]any, error) {
	if len(observed) == 0 {
		return nil, nil
	}
	if direct, ok := observed["direct_privilege"].(bool); ok && direct {
		return sanitizedObjectACLObservation(observed)
	}
	_, databaseProof := observed["database_name"]
	_, policyProof := observed["expected_fingerprint"]
	if databaseProof == policyProof {
		return nil, fmt.Errorf("connector: unknown verification observation shape")
	}
	allowedText := map[string]bool{
		"target_identity": true, "database_owner": true,
	}
	expectedCount := 5
	if databaseProof {
		allowedText["database_name"] = true
	} else {
		expectedCount = 8
		allowedText["expected_fingerprint"] = true
		allowedText["observed_fingerprint"] = true
		allowedText["database"] = true
		allowedText["admin_identity"] = true
	}
	out := make(map[string]any, len(observed))
	for key, value := range observed {
		switch key {
		case "database_name", "database_owner", "target_identity",
			"expected_fingerprint", "observed_fingerprint", "database", "admin_identity":
			if !allowedText[key] {
				return nil, fmt.Errorf("connector: unsupported verification field %q", key)
			}
			text, ok := value.(string)
			if !ok || text == "" || len(text) > 256 {
				return nil, fmt.Errorf("connector: invalid verification field %q", key)
			}
			if (key == "expected_fingerprint" || key == "observed_fingerprint") && !sanitizedFingerprint(text) {
				return nil, fmt.Errorf("connector: invalid verification fingerprint")
			}
			out[key] = text
		case "database_oid", "database_owner_oid":
			var oid uint32
			switch number := value.(type) {
			case uint32:
				oid = number
			case float64:
				if number < 1 || number > float64(^uint32(0)) || float64(uint32(number)) != number {
					return nil, fmt.Errorf("connector: invalid database verification OID")
				}
				oid = uint32(number)
			default:
				return nil, fmt.Errorf("connector: invalid database verification OID")
			}
			if oid == 0 {
				return nil, fmt.Errorf("connector: invalid database verification OID")
			}
			out[key] = oid
		default:
			return nil, fmt.Errorf("connector: unsupported verification field %q", key)
		}
	}
	if len(out) != expectedCount {
		return nil, fmt.Errorf("connector: incomplete verification proof")
	}
	return out, nil
}

func sanitizedObjectACLObservation(observed map[string]any) (map[string]any, error) {
	if len(observed) != 2 || observed["direct_privilege"] != true {
		return nil, adapter.ErrPostgresObjectACL
	}
	raw, err := json.Marshal(observed["grantors"])
	if err != nil {
		return nil, err
	}
	var grantors []adapter.PostgresACLGrantor
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&grantors); err != nil {
		return nil, err
	}
	if len(grantors) > 256 {
		return nil, adapter.ErrPostgresObjectACL
	}
	seen := map[uint32]bool{}
	for _, g := range grantors {
		if g.OID == 0 || g.Name == "" || len(g.Name) > 63 || strings.ContainsRune(g.Name, 0) || g.GrantOption || seen[g.OID] {
			return nil, adapter.ErrPostgresObjectACL
		}
		seen[g.OID] = true
	}
	return map[string]any{"direct_privilege": true, "grantors": grantors}, nil
}

func sanitizedFingerprint(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

// RotateOutcome — несекретный результат задания JobRotateCredential:
// подтверждение применения и версия секрета Vault, которую connector прочитал
// и применил. Формат совпадает с result-артефактом операции credential.rotate
// direct-пути ({"rotated":true,"vault_version":N}).
type RotateOutcome struct {
	Rotated      bool `json:"rotated"`
	VaultVersion int  `json:"vault_version"`
	Verified     bool `json:"verified,omitempty"`
}

// Marshal сериализует RotateOutcome для JobResult.Result.
func (o RotateOutcome) Marshal() ([]byte, error) {
	b, err := json.Marshal(o)
	if err != nil {
		return nil, fmt.Errorf("connector: marshal rotate outcome: %w", err)
	}
	return b, nil
}

// ParseRotateOutcome разбирает результат задания JobRotateCredential.
func ParseRotateOutcome(raw []byte) (RotateOutcome, error) {
	if len(raw) == 0 {
		return RotateOutcome{}, fmt.Errorf("connector: rotate outcome is empty")
	}
	var out RotateOutcome
	if err := json.Unmarshal(raw, &out); err != nil {
		return RotateOutcome{}, fmt.Errorf("connector: parse rotate outcome: %w", err)
	}
	return out, nil
}

// AdminCredentialOutcome is the only durable/wire result of a connection
// administrator credential switch or self-rotation. It contains the signed
// intent coordinates, exact staged Vault version, a secret-free proof and a
// full post-proof discovery snapshot. Credential material never enters this
// value; it remains confined to CredentialsFrame.
type AdminCredentialOutcome struct {
	Mode               AdminCredentialMode          `json:"mode"`
	Epoch              int64                        `json:"epoch"`
	CandidateUsername  string                       `json:"candidate_username"`
	CandidateAuthMode  string                       `json:"candidate_auth_mode,omitempty"`
	StagedVaultVersion int                          `json:"staged_vault_version"`
	Proof              adapter.AdminCredentialProof `json:"proof"`
	AlreadyApplied     bool                         `json:"already_applied,omitempty"`
	Snapshot           *adapter.Snapshot            `json:"snapshot"`
}

func (o AdminCredentialOutcome) validate() error {
	if o.CandidateAuthMode != "" && o.CandidateAuthMode != "password" && o.CandidateAuthMode != "none" {
		return fmt.Errorf("connector: unsupported outcome authentication mode")
	}
	if o.CandidateAuthMode == "none" && (o.Mode != AdminCredentialModeSwitch || o.CandidateUsername != "default" || o.StagedVaultVersion != 0 || o.Proof.CanonicalIdentity != "default") {
		return fmt.Errorf("connector: invalid no-auth outcome")
	}
	switch o.Mode {
	case AdminCredentialModeSwitch, AdminCredentialModeRotate:
	default:
		return fmt.Errorf("connector: admin credential outcome mode %q is not allowed", o.Mode)
	}
	switch {
	case o.Epoch <= 0:
		return fmt.Errorf("connector: admin credential outcome epoch must be positive")
	case o.CandidateUsername == "":
		return fmt.Errorf("connector: admin credential outcome candidate username is empty")
	case o.StagedVaultVersion < 0 || (o.StagedVaultVersion == 0 && (o.CandidateAuthMode != "none" || o.Mode != AdminCredentialModeSwitch || o.CandidateUsername != "default")):
		return fmt.Errorf("connector: admin credential outcome staged Vault version must be positive")
	case o.Proof.CanonicalIdentity == "" || o.Proof.AuthorityFingerprint == "":
		return fmt.Errorf("connector: admin credential outcome proof is incomplete")
	case o.Snapshot == nil:
		return fmt.Errorf("connector: admin credential outcome snapshot is absent")
	case o.Mode == AdminCredentialModeSwitch && o.AlreadyApplied:
		return fmt.Errorf("connector: switch outcome cannot be already applied")
	}
	return nil
}

// Marshal serializes the sanitized outcome after validating all proof fields.
func (o AdminCredentialOutcome) Marshal() ([]byte, error) {
	if err := o.validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(o)
	if err != nil {
		return nil, fmt.Errorf("connector: marshal admin credential outcome: %w", err)
	}
	return b, nil
}

// ParseAdminCredentialOutcome validates a connector result before the
// control plane uses its snapshot for CAS promotion and metadata commit.
func ParseAdminCredentialOutcome(raw []byte) (AdminCredentialOutcome, error) {
	if len(raw) == 0 {
		return AdminCredentialOutcome{}, fmt.Errorf("connector: admin credential outcome is empty")
	}
	var out AdminCredentialOutcome
	if err := json.Unmarshal(raw, &out); err != nil {
		return AdminCredentialOutcome{}, fmt.Errorf("connector: parse admin credential outcome: %w", err)
	}
	if err := out.validate(); err != nil {
		return AdminCredentialOutcome{}, err
	}
	return out, nil
}
