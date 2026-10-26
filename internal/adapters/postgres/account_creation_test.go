package postgres

import (
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/ArtefactoO/grantor/internal/adapter"
)

func accountCreationTestChange() adapter.DesiredChange {
	return adapter.DesiredChange{
		Kind: adapter.ChangePostgresAccountCreateV2,
		Connection: adapter.Connection{Engine: Engine, ConfigIncarnation: "config-1", AdminCredentialIncarnation: 1,
			AdminCredential: adapter.Credential{Kind: "password", Username: "grantor"}},
		Account:               adapter.Account{Kind: "login", EngineIdentity: "new_login"},
		Credential:            &adapter.Credential{Kind: "password", Username: "new_login", Secret: []byte("account-test-password")},
		ExpectedAdminIdentity: "grantor", ExpectedTargetIdentity: "postgres:system:123",
	}
}

func TestAccountCreationIntentPinsIdentityAndIncarnations(t *testing.T) {
	base := accountCreationTestChange()
	if err := validateAccountCreationIntent(base); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*adapter.DesiredChange)
	}{
		{"legacy create", func(c *adapter.DesiredChange) { c.Kind = adapter.ChangeAccountCreate }},
		{"restore", func(c *adapter.DesiredChange) { c.Kind = adapter.ChangePostgresAccountRestoreV2 }},
		{"engine", func(c *adapter.DesiredChange) { c.Connection.Engine = "mysql" }},
		{"admin identity", func(c *adapter.DesiredChange) { c.ExpectedAdminIdentity = "other" }},
		{"missing admin incarnation", func(c *adapter.DesiredChange) { c.Connection.AdminCredentialIncarnation = 0 }},
		{"missing config incarnation", func(c *adapter.DesiredChange) { c.Connection.ConfigIncarnation = "" }},
		{"missing target", func(c *adapter.DesiredChange) { c.ExpectedTargetIdentity = "" }},
		{"noncanonical target", func(c *adapter.DesiredChange) { c.ExpectedTargetIdentity = "postgres:system:001" }},
		{"zero target", func(c *adapter.DesiredChange) { c.ExpectedTargetIdentity = "postgres:system:0" }},
		{"credential identity", func(c *adapter.DesiredChange) { c.Credential.Username = "other" }},
		{"credential kind", func(c *adapter.DesiredChange) { c.Credential.Kind = "token" }},
		{"empty password", func(c *adapter.DesiredChange) { c.Credential.Secret = nil }},
		{"missing credential", func(c *adapter.DesiredChange) { c.Credential = nil }},
		{"group", func(c *adapter.DesiredChange) { c.Account.Kind = "group" }},
		{"authentication scope", func(c *adapter.DesiredChange) { c.Account.AuthenticationScope = "other" }},
		{"empty identity", func(c *adapter.DesiredChange) { c.Account.EngineIdentity = "" }},
		{"truncated identity", func(c *adapter.DesiredChange) { c.Account.EngineIdentity = strings.Repeat("x", 64) }},
		{"invalid identity encoding", func(c *adapter.DesiredChange) { c.Account.EngineIdentity = "\xff" }},
		{"NUL identity", func(c *adapter.DesiredChange) { c.Account.EngineIdentity = "login\x00other" }},
		{"system identity", func(c *adapter.DesiredChange) { c.Account.EngineIdentity = "pg_new" }},
		{"unrelated resource", func(c *adapter.DesiredChange) { c.Resource = &adapter.ResourceSpec{} }},
		{"unrelated policy", func(c *adapter.DesiredChange) { c.RolePolicySpec = &adapter.RolePolicySpec{} }},
		{"unrelated permission", func(c *adapter.DesiredChange) { c.Permission = "role:rw" }},
		{"unrelated attributes", func(c *adapter.DesiredChange) { c.Attributes = map[string]any{"sql": "select 1"} }},
		{"unrelated database OID", func(c *adapter.DesiredChange) { c.ExpectedDatabaseOID = 42 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			change := base
			credential := *base.Credential
			change.Credential = &credential
			tc.mutate(&change)
			if err := validateAccountCreationIntent(change); err == nil {
				t.Fatal("unfenced account creation intent was accepted")
			}
		})
	}
}

func TestAccountCreationPreflightRequiresObservedPasswordProtocol(t *testing.T) {
	canary := "server-credential-error-canary"
	for _, tc := range []struct {
		name     string
		frames   []byte
		err      error
		want     error
		succeeds bool
	}{
		{"scram rejection", authFrame(10, "SCRAM-SHA-256\x00\x00"), &pgconn.PgError{Code: "28P01"}, nil, true},
		{"md5 rejection", authFrame(5, "salt"), &pgconn.PgError{Code: "28P01"}, nil, true},
		{"password rejection", authFrame(3, ""), &pgconn.PgError{Code: "28P01"}, nil, true},
		{"bare password error", nil, &pgconn.PgError{Code: "28P01", Message: canary}, adapter.ErrCredentialProofUnsupported, false},
		{"HBA denial", nil, &pgconn.PgError{Code: "28000", Message: canary}, adapter.ErrCredentialProofAccessDenied, false},
		{"database denial", nil, &pgconn.PgError{Code: "3D000"}, adapter.ErrCredentialProofAccessDenied, false},
		{"trust absent role", authFrame(0, ""), &pgconn.PgError{Code: "28000"}, adapter.ErrCredentialProofUnsupported, false},
		{"trust CONNECT denial", authFrame(0, ""), &pgconn.PgError{Code: "42501", Routine: "CheckMyDatabase"}, adapter.ErrCredentialProofUnsupported, false},
		{"unsupported authenticator", authFrame(7, ""), errors.New(canary), adapter.ErrCredentialProofUnsupported, false},
		{"random password accepted", append(authFrame(3, ""), authFrame(0, "")...), nil, adapter.ErrCredentialProofUnsupported, false},
		{"auth OK then rejection", append(authFrame(3, ""), authFrame(0, "")...), &pgconn.PgError{Code: "28P01"}, adapter.ErrCredentialProofUnsupported, false},
		{"network error", nil, errors.New(canary), nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := &authenticationObservation{}
			o.consume(tc.frames)
			err := classifyAccountCreationProbe(o, tc.err)
			if (err == nil) != tc.succeeds || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("probe classification = %v, want sentinel %v, success %t", err, tc.want, tc.succeeds)
			}
			if tc.name == "network error" && (errors.Is(err, adapter.ErrCredentialProofAccessDenied) || errors.Is(err, adapter.ErrCredentialProofUnsupported)) {
				t.Fatal("transport failure became authorization or unsupported authentication")
			}
			if err != nil && strings.Contains(err.Error(), canary) {
				t.Fatal("probe retained server error contents")
			}
		})
	}
}
