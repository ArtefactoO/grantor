package redis

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	goredis "github.com/redis/go-redis/v9"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

func validateAuthenticationConfig(cfg adapter.Connection) error {
	switch cfg.AuthMode {
	case "", "password":
		if cfg.AdminCredential.Kind == "none" {
			return errors.New("redis: no-auth requires explicit auth_mode=none")
		}
	case "none":
		if len(cfg.AdminCredential.Secret) != 0 || (cfg.AdminCredential.Username != "" && cfg.AdminCredential.Username != defaultUserName) || (cfg.AdminCredential.Kind != "" && cfg.AdminCredential.Kind != "none") {
			return errors.New("redis: no-auth mode must not carry a password or non-default identity")
		}
	default:
		return errors.New("redis: unsupported authentication mode")
	}
	return nil
}

func requireAuthenticatedMutation(cfg adapter.Connection) error {
	if cfg.AuthMode == "none" || cfg.AdminCredential.Kind == "none" {
		return fmt.Errorf("redis: authentication_disabled: mutation is unavailable: %w", adapter.ErrUnsupportedChange)
	}
	return nil
}

// An unauthenticated default session is an explicit inventory-only authority.
// Identity and ACL facts are read independently of the caller's descriptor;
// there is no AUTH command, ACL update, password probe or target write.
func (a *Adapter) proveUnauthenticatedAdmin(ctx context.Context, cfg adapter.Connection, credential adapter.Credential) (redisAdminCredentialState, error) {
	if credential.Kind != "none" || len(credential.Secret) != 0 || (credential.Username != "" && credential.Username != defaultUserName) {
		return redisAdminCredentialState{}, adapter.ErrAdminCredentialRejected
	}
	probe := cfg
	probe.AuthMode = "none"
	probe.AdminCredential = credential
	client, err := a.newClient(probe)
	if err != nil {
		return redisAdminCredentialState{}, err
	}
	defer client.close()
	identity, err := client.whoAmI(ctx)
	if err != nil {
		if goredis.HasErrorPrefix(err, "NOAUTH") || goredis.HasErrorPrefix(err, "WRONGPASS") {
			return redisAdminCredentialState{}, adapter.ErrAdminCredentialRejected
		}
		return redisAdminCredentialState{}, fmt.Errorf("redis: prove unauthenticated identity: %w", err)
	}
	if identity != defaultUserName {
		return redisAdminCredentialState{}, adapter.ErrAdminCredentialRejected
	}
	users, err := client.aclListUsers(ctx)
	if err != nil {
		return redisAdminCredentialState{}, fmt.Errorf("redis: prove unauthenticated ACL: %w", err)
	}
	self, found := findUser(users, identity)
	if !found || !self.enabled || !self.noPass || !aclAdminAllowed(self) {
		return redisAdminCredentialState{}, adapter.ErrAdminCredentialAuthorityChanged
	}
	info, err := client.serverAndReplicationInfo(ctx)
	if err != nil {
		return redisAdminCredentialState{}, fmt.Errorf("redis: prove unauthenticated target: %w", err)
	}
	if info["run_id"] == "" {
		return redisAdminCredentialState{}, adapter.ErrAdminCredentialProofAmbiguous
	}
	return redisAdminCredentialState{proof: adapter.AdminCredentialProof{
		CanonicalIdentity:    identity,
		AuthorityFingerprint: adapter.AdminCredentialAuthorityFingerprint("authentication=none", "enabled="+strconv.FormatBool(self.enabled), "rules="+rulesSignature(self)),
		TargetIdentity:       "redis:run:" + info["run_id"],
	}, topology: info["redis_mode"], role: info["role"]}, nil
}
