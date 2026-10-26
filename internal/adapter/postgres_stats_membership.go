package adapter

// PostgresStatsMembershipPins is the closed, secret-free statistics membership
// identity contract shared by direct execution and signed connector jobs.
type PostgresStatsMembershipPins struct {
	AdminIdentity         string `json:"admin_identity"`
	TargetIdentity        string `json:"target_identity"`
	ConfigIncarnation     string `json:"config_incarnation"`
	CredentialIncarnation int    `json:"credential_incarnation"`
	BuiltinOID            uint32 `json:"builtin_oid"`
	SubjectOID            uint32 `json:"subject_oid"`
}

// Attributes remains available for decoding historical direct operation data.
// It is never accepted as a typed connector request or adapter mutation.
func (p PostgresStatsMembershipPins) Attributes() map[string]any {
	return map[string]any{"postgres_stats_membership_v1": p}
}

func IsPostgresStatsMembershipChange(kind ChangeKind) bool {
	return kind == ChangePostgresStatsMembershipGrantV1 || kind == ChangePostgresStatsMembershipRevokeV1
}
