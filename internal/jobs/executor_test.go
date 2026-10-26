package jobs

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/operations"
)

func TestMainExecutorUnknownKind(t *testing.T) {
	e := NewMainExecutor(DiscoveryDeps{})
	err := e.Execute(context.Background(), operations.Operation{
		ID:   uuid.New(),
		Kind: "bogus.kind",
	})
	if err == nil {
		t.Fatal("Execute with unknown kind: err = nil, want error")
	}
	if !strings.Contains(err.Error(), `unknown kind "bogus.kind"`) {
		t.Errorf("Execute error = %q, want mention of unknown kind", err)
	}
}

func TestMainExecutorDiscoverRequiresConnectionID(t *testing.T) {
	e := NewMainExecutor(DiscoveryDeps{})
	err := e.Execute(context.Background(), operations.Operation{
		ID:   uuid.New(),
		Kind: KindConnectionDiscover,
	})
	if err == nil {
		t.Fatal("Execute discover without connection id: err = nil, want error")
	}
	if !strings.Contains(err.Error(), "connection id is not set") {
		t.Errorf("Execute error = %q, want mention of missing connection id", err)
	}
}

func TestAdapterConnection(t *testing.T) {
	conn := connections.Connection{
		ID:              uuid.New(),
		Engine:          "postgres",
		Endpoints:       []string{"db.example.com:5432"},
		TLSConfig:       json.RawMessage(`{"mode":"verify-full","ca_cert_pem":"CA-PEM"}`),
		DiscoveryConfig: json.RawMessage(`{"database":"appdb"}`),
	}

	cfg, err := adapterConnection(conn)
	if err != nil {
		t.Fatalf("adapterConnection: %v", err)
	}
	if cfg.ID != conn.ID.String() {
		t.Errorf("cfg.ID = %q, want %q", cfg.ID, conn.ID)
	}
	if cfg.Engine != "postgres" {
		t.Errorf("cfg.Engine = %q, want postgres", cfg.Engine)
	}
	if len(cfg.Endpoints) != 1 || cfg.Endpoints[0] != "db.example.com:5432" {
		t.Errorf("cfg.Endpoints = %v, want [db.example.com:5432]", cfg.Endpoints)
	}
	if cfg.TLS.Mode != "verify-full" {
		t.Errorf("cfg.TLS.Mode = %q, want verify-full", cfg.TLS.Mode)
	}
	if string(cfg.TLS.CACertPEM) != "CA-PEM" {
		t.Errorf("cfg.TLS.CACertPEM = %q, want CA-PEM", cfg.TLS.CACertPEM)
	}
	if cfg.TLS.ClientCertPEM != nil {
		t.Errorf("cfg.TLS.ClientCertPEM = %q, want nil", cfg.TLS.ClientCertPEM)
	}
	if got := cfg.Attributes["database"]; got != "appdb" {
		t.Errorf(`cfg.Attributes["database"] = %v, want appdb`, got)
	}
}

func TestAdapterConnectionEmptyConfigs(t *testing.T) {
	cfg, err := adapterConnection(connections.Connection{ID: uuid.New(), Engine: "postgres"})
	if err != nil {
		t.Fatalf("adapterConnection: %v", err)
	}
	if cfg.TLS.Mode != "" {
		t.Errorf("cfg.TLS.Mode = %q, want empty", cfg.TLS.Mode)
	}
	if _, ok := cfg.Attributes["database"]; ok {
		t.Error("cfg.Attributes contains database for empty discovery config")
	}
}

func TestAdapterConnectionInvalidJSON(t *testing.T) {
	_, err := adapterConnection(connections.Connection{
		ID:        uuid.New(),
		TLSConfig: json.RawMessage(`{broken`),
	})
	if err == nil {
		t.Fatal("adapterConnection with broken tls config: err = nil, want error")
	}
}

func TestCredentialFromVault(t *testing.T) {
	cred, err := credentialFromVault(map[string]any{"username": "admin", "password": "secret"})
	if err != nil {
		t.Fatalf("credentialFromVault: %v", err)
	}
	if cred.Kind != "password" || cred.Username != "admin" || string(cred.Secret) != "secret" {
		t.Errorf("credentialFromVault = %+v, want password/admin credential", cred)
	}

	if _, err := credentialFromVault(map[string]any{"password": "x"}); err == nil {
		t.Error("credentialFromVault without username: err = nil, want error")
	}
	if _, err := credentialFromVault(map[string]any{"username": "admin"}); err == nil {
		t.Error("credentialFromVault without password: err = nil, want error")
	}
}

type versionedVaultReader struct{ version int }

func (v versionedVaultReader) Get(context.Context, string) (map[string]any, int, error) {
	return map[string]any{"username": "grantor", "password": "test-password"}, v.version, nil
}

func TestApplyAdminCredentialPinsVaultIncarnation(t *testing.T) {
	executor := NewMainExecutor(DiscoveryDeps{Vault: versionedVaultReader{version: 37}})
	conn := connections.Connection{VaultAdminPath: "connections/c/admin"}
	cfg := adapter.Connection{}
	if err := executor.applyAdminCredential(t.Context(), conn, &cfg); err != nil {
		t.Fatalf("applyAdminCredential: %v", err)
	}
	defer clear(cfg.AdminCredential.Secret)
	if cfg.AdminCredential.Username != "grantor" || cfg.AdminCredentialIncarnation != 37 {
		t.Fatalf("admin identity/incarnation = %q/%d, want grantor/37",
			cfg.AdminCredential.Username, cfg.AdminCredentialIncarnation)
	}
}
