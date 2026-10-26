package rabbitmq

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
)

var (
	_ adapter.ConnectionAdminCredentialManager = (*Adapter)(nil)
	_ adapter.ConnectionCapabilityScoper       = (*Adapter)(nil)
)

type rabbitAdminCredentialState struct {
	proof    adapter.AdminCredentialProof
	internal bool
	tags     []string
}

func (a *Adapter) AssessConnectionAdminCredential(ctx context.Context, cfg adapter.Connection) (adapter.AdminCredentialAssessment, error) {
	state, err := a.proveConnectionAdminCredential(ctx, cfg, cfg.AdminCredential)
	if err != nil {
		return adapter.AdminCredentialAssessment{}, err
	}
	rotate := state.internal && state.proof.TargetIdentity != ""
	reason := ""
	if !state.internal {
		reason = "requires_internal_user"
	} else if state.proof.TargetIdentity == "" {
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
	return adapter.RunCandidateFirstAdminCredentialRotation(ctx, cfg.AdminCredential, candidate, expected,
		adapter.AdminCredentialRotationHooks{
			Prove: func(ctx context.Context, credential adapter.Credential) (adapter.AdminCredentialProof, error) {
				return a.ProveConnectionAdminCredential(ctx, cfg, credential)
			},
			Apply: func(ctx context.Context, credential adapter.Credential, oldProof adapter.AdminCredentialProof) error {
				client, err := a.newClient(cfg)
				if err != nil {
					return errors.New("rabbitmq: rotate connection admin credential: target unavailable")
				}
				user, found, err := client.getUser(ctx, cfg.AdminCredential.Username)
				if err != nil || !found {
					return fmt.Errorf("rabbitmq: rotate connection admin credential: internal user unavailable: %w",
						adapter.ErrAdminCredentialRotationUnsupported)
				}
				tags := parseTags(user.Tags)
				if !hasTag(tags, tagAdministrator) {
					return fmt.Errorf("rabbitmq: rotate connection admin credential: administrator tag missing: %w",
						adapter.ErrAdminCredentialAuthorityChanged)
				}
				var overview apiOverview
				if _, err := client.getJSON(ctx, "/api/overview", &overview); err != nil ||
					overview.ClusterName == "" || "rabbitmq:cluster:"+overview.ClusterName != oldProof.TargetIdentity {
					return fmt.Errorf("rabbitmq: rotate connection admin credential: target identity changed: %w",
						adapter.ErrTargetIdentityConflict)
				}
				if err := client.putUserPassword(ctx, user.Name, string(credential.Secret), tags); err != nil {
					return errors.New("rabbitmq: rotate connection admin credential: target response is ambiguous")
				}
				return nil
			},
		})
}

func (a *Adapter) proveConnectionAdminCredential(ctx context.Context, cfg adapter.Connection,
	credential adapter.Credential,
) (rabbitAdminCredentialState, error) {
	if credential.Kind != "password" || credential.Username == "" || len(credential.Secret) == 0 {
		return rabbitAdminCredentialState{}, errors.New("rabbitmq: admin username and password are required")
	}
	probe := cfg
	probe.AdminCredential = credential
	client, err := a.newClient(probe)
	if err != nil {
		return rabbitAdminCredentialState{}, errors.New("rabbitmq: prove admin credential: invalid connection")
	}
	status, body, err := client.do(ctx, http.MethodGet, "/api/whoami", nil)
	if err != nil {
		return rabbitAdminCredentialState{}, errors.New("rabbitmq: prove admin credential: target unavailable")
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		if isManagementAccessDenied(body) {
			return rabbitAdminCredentialState{}, fmt.Errorf("rabbitmq: administrator tag missing: %w",
				adapter.ErrAdminCredentialAuthorityChanged)
		}
		return rabbitAdminCredentialState{}, fmt.Errorf("rabbitmq: admin credential rejected: %w",
			adapter.ErrAdminCredentialRejected)
	}
	if status != http.StatusOK {
		return rabbitAdminCredentialState{}, fmt.Errorf("rabbitmq: admin proof is ambiguous: %w",
			adapter.ErrAdminCredentialProofAmbiguous)
	}
	var who apiWhoami
	if err := json.Unmarshal(body, &who); err != nil || who.Name != credential.Username {
		return rabbitAdminCredentialState{}, fmt.Errorf("rabbitmq: admin identity is ambiguous: %w",
			adapter.ErrAdminCredentialProofAmbiguous)
	}
	tags := parseTags(who.Tags)
	if !hasTag(tags, tagAdministrator) {
		return rabbitAdminCredentialState{}, fmt.Errorf("rabbitmq: administrator tag missing: %w",
			adapter.ErrAdminCredentialAuthorityChanged)
	}
	user, found, err := client.getUser(ctx, who.Name)
	if err != nil {
		return rabbitAdminCredentialState{}, fmt.Errorf("rabbitmq: read internal admin user: %w", err)
	}
	internal := found && user.Name == who.Name
	if internal {
		tags = parseTags(user.Tags)
		if !hasTag(tags, tagAdministrator) {
			return rabbitAdminCredentialState{}, fmt.Errorf("rabbitmq: administrator tag missing: %w",
				adapter.ErrAdminCredentialAuthorityChanged)
		}
	}

	wrong, err := adapterutil.RandomPassword(negativeProbePasswordLength)
	if err != nil {
		return rabbitAdminCredentialState{}, fmt.Errorf("rabbitmq: generate negative admin proof: %w", err)
	}
	defer clear(wrong)
	result, _, err := a.probeCredential(ctx, cfg, credential.Username, wrong)
	if err != nil {
		return rabbitAdminCredentialState{}, fmt.Errorf("rabbitmq: negative admin proof is ambiguous: %w",
			adapter.ErrAdminCredentialProofAmbiguous)
	}
	if result != probeRejected {
		return rabbitAdminCredentialState{}, fmt.Errorf("rabbitmq: password authentication is not enforced: %w",
			adapter.ErrAdminCredentialProofAmbiguous)
	}

	var overview apiOverview
	if _, err := client.getJSON(ctx, "/api/overview", &overview); err != nil {
		return rabbitAdminCredentialState{}, fmt.Errorf("rabbitmq: read target identity: %w", err)
	}
	slices.Sort(tags)
	facts := make([]string, 0, len(tags))
	for _, tag := range tags {
		facts = append(facts, "tag="+tag)
	}
	targetIdentity := ""
	if overview.ClusterName != "" {
		targetIdentity = "rabbitmq:cluster:" + overview.ClusterName
	}
	return rabbitAdminCredentialState{
		proof: adapter.AdminCredentialProof{
			CanonicalIdentity:    who.Name,
			AuthorityFingerprint: adapter.AdminCredentialAuthorityFingerprint(facts...),
			TargetIdentity:       targetIdentity,
		},
		internal: internal, tags: tags,
	}, nil
}

func (a *Adapter) CapabilitiesFor(_ adapter.Connection, topology map[string]any) []adapter.Capability {
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
