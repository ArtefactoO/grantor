package redis

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	goredis "github.com/redis/go-redis/v9"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
)

var (
	_ adapter.ConnectionAdminCredentialManager = (*Adapter)(nil)
	_ adapter.ConnectionCapabilityScoper       = (*Adapter)(nil)
)

type redisAdminCredentialState struct {
	proof    adapter.AdminCredentialProof
	aclFile  string
	topology string
	role     string
}

func (a *Adapter) AssessConnectionAdminCredential(ctx context.Context, cfg adapter.Connection) (adapter.AdminCredentialAssessment, error) {
	state, err := a.proveConnectionAdminCredential(ctx, cfg, cfg.AdminCredential)
	if err != nil {
		return adapter.AdminCredentialAssessment{}, err
	}
	if cfg.AuthMode == "none" {
		return adapter.AdminCredentialAssessment{SwitchSupported: true, BlockedReason: "authentication_disabled", CanonicalIdentity: state.proof.CanonicalIdentity, AuthorityFingerprint: state.proof.AuthorityFingerprint, TargetIdentity: state.proof.TargetIdentity}, nil
	}
	explicitACLUser := cfg.AdminCredential.Username != "" && state.proof.CanonicalIdentity != defaultUserName
	rotate := explicitACLUser && state.topology == "standalone" && state.role == "master" && state.aclFile != "" &&
		state.proof.TargetIdentity != ""
	reason := ""
	switch {
	case !explicitACLUser:
		reason = "requires_explicit_acl_user"
	case state.topology != "standalone" || state.role != "master":
		reason = "requires_single_writable_node"
	case state.aclFile == "":
		reason = "writable_aclfile_required"
	case state.proof.TargetIdentity == "":
		reason = "target_identity_unavailable"
	}
	return adapter.AdminCredentialAssessment{
		SwitchSupported: true, RotateSupported: rotate, BlockedReason: reason,
		CanonicalIdentity:    state.proof.CanonicalIdentity,
		AuthorityFingerprint: state.proof.AuthorityFingerprint,
		TargetIdentity:       state.proof.TargetIdentity,
	}, nil
}

func (a *Adapter) ProveConnectionAdminCredential(ctx context.Context, cfg adapter.Connection,
	candidate adapter.Credential,
) (adapter.AdminCredentialProof, error) {
	state, err := a.proveConnectionAdminCredential(ctx, cfg, candidate)
	return state.proof, err
}

func (a *Adapter) RotateConnectionAdminCredential(ctx context.Context, cfg adapter.Connection,
	candidate adapter.Credential, expected adapter.AdminCredentialProof,
) (adapter.AdminCredentialRotationResult, error) {
	if cfg.AuthMode == "none" || candidate.Kind == "none" {
		return adapter.AdminCredentialRotationResult{}, adapter.ErrAdminCredentialRotationUnsupported
	}
	result, err := adapter.RunCandidateFirstAdminCredentialRotation(ctx, cfg.AdminCredential, candidate, expected,
		adapter.AdminCredentialRotationHooks{
			Prove: func(ctx context.Context, credential adapter.Credential) (adapter.AdminCredentialProof, error) {
				return a.ProveConnectionAdminCredential(ctx, cfg, credential)
			},
			Apply: func(ctx context.Context, credential adapter.Credential, oldProof adapter.AdminCredentialProof) error {
				client, err := a.newClient(cfg)
				if err != nil {
					return errors.New("redis: rotate connection admin credential: target unavailable")
				}
				defer client.close()
				who, err := client.whoAmI(ctx)
				if err != nil {
					return fmt.Errorf("redis: rotate connection admin credential: read identity: %w", err)
				}
				info, err := client.serverAndReplicationInfo(ctx)
				if err != nil {
					return fmt.Errorf("redis: rotate connection admin credential: read topology: %w", err)
				}
				if info["redis_mode"] != "standalone" || info["role"] != "master" {
					return fmt.Errorf("redis: rotate connection admin credential: target is not a single writable node: %w",
						adapter.ErrAdminCredentialRotationUnsupported)
				}
				if info["run_id"] == "" || "redis:run:"+info["run_id"] != oldProof.TargetIdentity {
					return fmt.Errorf("redis: rotate connection admin credential: target identity changed: %w",
						adapter.ErrTargetIdentityConflict)
				}
				reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
				config, err := client.rdb.ConfigGet(reqCtx, "aclfile").Result()
				cancel()
				if err != nil || config["aclfile"] == "" {
					return fmt.Errorf("redis: rotate connection admin credential: writable aclfile required: %w",
						adapter.ErrAdminCredentialRotationUnsupported)
				}
				// Prove both command authorization and actual aclfile writability
				// before changing the only credential Grantor currently has.
				if err := requireACLSave(ctx, client, oldProof.TargetIdentity); err != nil {
					return fmt.Errorf("redis: rotate connection admin credential preflight: %w", err)
				}
				if err := client.setUser(ctx, who, "resetpass", ">"+string(credential.Secret)); err != nil {
					return fmt.Errorf("redis: rotate connection admin credential: %w", redactACLError(err, string(credential.Secret)))
				}
				return requireACLSave(ctx, client, oldProof.TargetIdentity)
			},
		})
	if err != nil {
		return adapter.AdminCredentialRotationResult{}, err
	}
	if result.AlreadyApplied {
		candidateCfg := cfg
		candidateCfg.AdminCredential = candidate
		client, err := a.newClient(candidateCfg)
		if err != nil {
			return adapter.AdminCredentialRotationResult{}, errors.New("redis: persist recovered admin credential: target unavailable")
		}
		defer client.close()
		if err := requireACLSave(ctx, client, result.Proof.TargetIdentity); err != nil {
			return adapter.AdminCredentialRotationResult{}, err
		}
	}
	return result, nil
}

func (a *Adapter) proveConnectionAdminCredential(ctx context.Context, cfg adapter.Connection,
	credential adapter.Credential,
) (redisAdminCredentialState, error) {
	if credential.Kind == "none" {
		return a.proveUnauthenticatedAdmin(ctx, cfg, credential)
	}
	if (credential.Kind != "password" && credential.Kind != "") || len(credential.Secret) == 0 {
		return redisAdminCredentialState{}, errors.New("redis: admin password is required")
	}
	name := credential.Username
	accepted, identity, err := a.probeAuth(ctx, cfg, name, credential.Secret)
	if err != nil {
		return redisAdminCredentialState{}, errors.New("redis: prove admin credential: target unavailable")
	}
	if !accepted {
		return redisAdminCredentialState{}, fmt.Errorf("redis: admin credential rejected: %w",
			adapter.ErrAdminCredentialRejected)
	}
	probe := cfg
	probe.AdminCredential = credential
	probe.AuthMode = "password"
	client, err := a.newClient(probe)
	if err != nil {
		return redisAdminCredentialState{}, fmt.Errorf("redis: build admin proof client: %w", err)
	}
	defer client.close()
	if identity == "" {
		identity, err = client.whoAmI(ctx)
		if err != nil {
			return redisAdminCredentialState{}, fmt.Errorf("redis: prove admin identity: %w", err)
		}
	}
	if name != "" && identity != name {
		return redisAdminCredentialState{}, fmt.Errorf("redis: authenticated as another identity: %w",
			adapter.ErrAdminCredentialRejected)
	}
	users, err := client.aclListUsers(ctx)
	if err != nil {
		return redisAdminCredentialState{}, fmt.Errorf("redis: read admin ACL rules: %w", err)
	}
	self, found := findUser(users, identity)
	if !found || !aclAdminAllowed(self) {
		return redisAdminCredentialState{}, fmt.Errorf("redis: admin ACL authority is insufficient: %w",
			adapter.ErrAdminCredentialAuthorityChanged)
	}
	wrong, err := adapterutil.RandomPassword(negativeProbePasswordLength)
	if err != nil {
		return redisAdminCredentialState{}, fmt.Errorf("redis: generate negative admin proof: %w", err)
	}
	defer clear(wrong)
	wrongAccepted, _, err := a.probeAuth(ctx, cfg, name, wrong)
	if err != nil {
		return redisAdminCredentialState{}, fmt.Errorf("redis: negative admin proof is ambiguous: %w",
			adapter.ErrAdminCredentialProofAmbiguous)
	}
	if wrongAccepted {
		return redisAdminCredentialState{}, fmt.Errorf("redis: password authentication is not enforced: %w",
			adapter.ErrAdminCredentialProofAmbiguous)
	}
	info, err := client.serverAndReplicationInfo(ctx)
	if err != nil {
		return redisAdminCredentialState{}, fmt.Errorf("redis: read target topology: %w", err)
	}
	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	config, err := client.rdb.ConfigGet(reqCtx, "aclfile").Result()
	cancel()
	if err != nil && !goredis.HasErrorPrefix(err, "NOPERM") {
		return redisAdminCredentialState{}, fmt.Errorf("redis: read aclfile configuration: %w", err)
	}
	aclFile := config["aclfile"]
	facts := []string{
		"enabled=" + strconv.FormatBool(self.enabled),
		"rules=" + rulesSignature(self),
	}
	targetIdentity := ""
	if info["run_id"] != "" {
		targetIdentity = "redis:run:" + info["run_id"]
	}
	return redisAdminCredentialState{
		proof: adapter.AdminCredentialProof{
			CanonicalIdentity:    identity,
			AuthorityFingerprint: adapter.AdminCredentialAuthorityFingerprint(facts...),
			TargetIdentity:       targetIdentity,
		},
		aclFile: aclFile, topology: info["redis_mode"], role: info["role"],
	}, nil
}

func requireACLSave(ctx context.Context, client *adminClient, expectedTarget string) error {
	return requireACLSaveWithCommands(ctx, expectedTarget,
		func(reqCtx context.Context) (string, error) {
			return client.rdb.Info(reqCtx, "server").Result()
		},
		func(reqCtx context.Context) (map[string]string, error) {
			return client.rdb.ConfigGet(reqCtx, "aclfile").Result()
		},
		func(reqCtx context.Context) error {
			return client.rdb.Do(reqCtx, "acl", "save").Err()
		},
	)
}

func requireACLSaveWithCommands(ctx context.Context, expectedTarget string,
	infoCommand func(context.Context) (string, error),
	configCommand func(context.Context) (map[string]string, error),
	saveCommand func(context.Context) error,
) error {
	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	infoText, err := infoCommand(reqCtx)
	cancel()
	info := parseInfo(infoText)
	if err != nil || info["run_id"] == "" || "redis:run:"+info["run_id"] != expectedTarget {
		return fmt.Errorf("redis: ACL SAVE target identity changed: %w", adapter.ErrTargetIdentityConflict)
	}
	reqCtx, cancel = context.WithTimeout(ctx, requestTimeout)
	config, err := configCommand(reqCtx)
	cancel()
	if err != nil || config["aclfile"] == "" {
		return fmt.Errorf("redis: ACL SAVE requires a configured aclfile: %w",
			adapter.ErrAdminCredentialRotationUnsupported)
	}
	reqCtx, cancel = context.WithTimeout(ctx, requestTimeout)
	err = saveCommand(reqCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("redis: mandatory ACL SAVE failed: %w", err)
	}
	return nil
}

func (a *Adapter) CapabilitiesFor(cfg adapter.Connection, topology map[string]any) []adapter.Capability {
	if cfg.AuthMode == "none" {
		return adapter.ScopeAdminCredentialCapabilities([]adapter.Capability{adapter.CapInventoryAccounts, adapter.CapInventoryPermissions, adapter.CapInventoryBindings, adapter.CapConnectionAdminCredentialSwitch}, topology)
	}
	return adapter.ScopeAdminCredentialCapabilities(a.Manifest().Capabilities, topology)
}

func publishAdminCredentialAssessment(ctx context.Context, a *Adapter, cfg adapter.Connection, topology map[string]any) {
	assessment, err := a.AssessConnectionAdminCredential(ctx, cfg)
	if err != nil {
		adapter.PublishAdminCredentialAssessment(topology, adapter.AdminCredentialAssessment{BlockedReason: "assessment_failed"})
		return
	}
	adapter.PublishAdminCredentialAssessment(topology, assessment)
}
