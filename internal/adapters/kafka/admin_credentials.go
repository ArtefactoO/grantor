package kafka

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/twmb/franz-go/pkg/kadm"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

var _ adapter.ConnectionAdminCredentialManager = (*Adapter)(nil)

type kafkaAdminCredentialState struct {
	proof      adapter.AdminCredentialProof
	auth       authConfig
	mechanisms []kadm.ScramMechanism
}

func (a *Adapter) AssessConnectionAdminCredential(ctx context.Context, cfg adapter.Connection) (adapter.AdminCredentialAssessment, error) {
	state, err := a.proveConnectionAdminCredential(ctx, cfg, cfg.AdminCredential)
	if err != nil {
		return adapter.AdminCredentialAssessment{}, err
	}
	expected, expectedOK := configuredSCRAMMechanism(state.auth)
	rotate := expectedOK && len(state.mechanisms) == 1 && state.mechanisms[0] == expected &&
		state.proof.TargetIdentity != ""
	reason := ""
	switch {
	case !expectedOK:
		reason = "requires_configured_scram_sha256_or_sha512"
	case len(state.mechanisms) != 1:
		reason = "requires_exactly_one_scram_mechanism"
	case state.mechanisms[0] != expected:
		reason = "configured_scram_mechanism_mismatch"
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
	return adapter.RunCandidateFirstAdminCredentialRotation(ctx, cfg.AdminCredential, candidate, expected,
		adapter.AdminCredentialRotationHooks{
			Prove: func(ctx context.Context, credential adapter.Credential) (adapter.AdminCredentialProof, error) {
				return a.ProveConnectionAdminCredential(ctx, cfg, credential)
			},
			Apply: func(ctx context.Context, credential adapter.Credential, oldProof adapter.AdminCredentialProof) error {
				client, err := a.newClient(cfg)
				if err != nil {
					return errors.New("kafka: rotate connection admin credential: target unavailable")
				}
				defer client.close()
				expected, ok := configuredSCRAMMechanism(client.auth)
				if !ok {
					return fmt.Errorf("kafka: rotate connection admin credential: mechanism changed: %w",
						adapter.ErrAdminCredentialRotationUnsupported)
				}
				mechanisms, found, err := client.scramMechanisms(ctx, cfg.AdminCredential.Username)
				if err != nil || !found || len(mechanisms) != 1 || mechanisms[0] != expected {
					return fmt.Errorf("kafka: rotate connection admin credential: SCRAM state changed: %w",
						adapter.ErrAdminCredentialRotationUnsupported)
				}
				reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
				meta, err := client.adm.Metadata(reqCtx)
				cancel()
				if err != nil || meta.Cluster == "" || "kafka:cluster:"+meta.Cluster != oldProof.TargetIdentity {
					return fmt.Errorf("kafka: rotate connection admin credential: target identity changed: %w",
						adapter.ErrTargetIdentityConflict)
				}
				return upsertAdminSCRAM(ctx, client, cfg.AdminCredential.Username,
					string(credential.Secret), expected)
			},
		})
}

func (a *Adapter) proveConnectionAdminCredential(ctx context.Context, cfg adapter.Connection,
	credential adapter.Credential,
) (kafkaAdminCredentialState, error) {
	if credential.Kind != "password" || credential.Username == "" || len(credential.Secret) == 0 {
		return kafkaAdminCredentialState{}, errors.New("kafka: admin username and password are required")
	}
	probe := cfg
	probe.AdminCredential = credential
	auth, err := parseAuthConfig(probe)
	if err != nil {
		return kafkaAdminCredentialState{}, fmt.Errorf("kafka: invalid admin auth configuration: %w", err)
	}
	if err := a.probeCredential(ctx, cfg, credential.Username, credential.Secret); err != nil {
		if isAuthenticationFailure(err) {
			return kafkaAdminCredentialState{}, fmt.Errorf("kafka: admin credential rejected: %w",
				adapter.ErrAdminCredentialRejected)
		}
		return kafkaAdminCredentialState{}, errors.New("kafka: prove admin credential: target unavailable")
	}
	client, err := a.newClient(probe)
	if err != nil {
		return kafkaAdminCredentialState{}, fmt.Errorf("kafka: build admin proof client: %w", err)
	}
	defer client.close()
	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	meta, err := client.adm.Metadata(reqCtx)
	cancel()
	if err != nil {
		return kafkaAdminCredentialState{}, fmt.Errorf("kafka: read cluster metadata: %w", err)
	}
	entries, disabled, err := client.describeACLsTolerant(ctx)
	if err != nil {
		return kafkaAdminCredentialState{}, fmt.Errorf("kafka: read admin ACL authority: %w", err)
	}
	var mechanisms []kadm.ScramMechanism
	if auth.managesScram() {
		var found bool
		mechanisms, found, err = client.scramMechanisms(ctx, credential.Username)
		if err != nil {
			return kafkaAdminCredentialState{}, fmt.Errorf("kafka: read admin SCRAM state: %w", err)
		}
		if !found {
			return kafkaAdminCredentialState{}, fmt.Errorf("kafka: configured admin SCRAM identity is absent: %w",
				adapter.ErrAdminCredentialProofAmbiguous)
		}
	}
	wrong, err := randomCredentialProbePassword()
	if err != nil {
		return kafkaAdminCredentialState{}, fmt.Errorf("kafka: generate negative admin proof: %w", err)
	}
	defer clear(wrong)
	negativeErr := a.probeCredential(ctx, cfg, credential.Username, wrong)
	if negativeErr == nil {
		return kafkaAdminCredentialState{}, fmt.Errorf("kafka: password authentication is not enforced: %w",
			adapter.ErrAdminCredentialProofAmbiguous)
	}
	if !isAuthenticationFailure(negativeErr) {
		return kafkaAdminCredentialState{}, fmt.Errorf("kafka: negative admin proof is ambiguous: %w",
			adapter.ErrAdminCredentialProofAmbiguous)
	}
	facts := []string{"mechanism=" + string(auth.mechanism), fmt.Sprintf("acl_disabled=%t", disabled)}
	for _, entry := range entries {
		if entry.principal == userPrincipal(credential.Username) {
			facts = append(facts, fmt.Sprintf("acl=%s:%s:%s:%s:%s",
				entry.resourceType, entry.pattern, entry.name, entry.op, entry.perm))
		}
	}
	for _, mechanism := range mechanisms {
		facts = append(facts, fmt.Sprintf("scram=%d", mechanism))
	}
	targetIdentity := ""
	if meta.Cluster != "" {
		targetIdentity = "kafka:cluster:" + meta.Cluster
	}
	return kafkaAdminCredentialState{
		proof: adapter.AdminCredentialProof{
			CanonicalIdentity:    credential.Username,
			AuthorityFingerprint: adapter.AdminCredentialAuthorityFingerprint(facts...),
			TargetIdentity:       targetIdentity,
		},
		auth: auth, mechanisms: slices.Clone(mechanisms),
	}, nil
}

func configuredSCRAMMechanism(auth authConfig) (kadm.ScramMechanism, bool) {
	switch auth.mechanism {
	case mechScramSha256:
		return kadm.ScramSha256, true
	case mechScramSha512:
		return kadm.ScramSha512, true
	default:
		return 0, false
	}
}

func upsertAdminSCRAM(ctx context.Context, client *adminClient, user, password string,
	mechanism kadm.ScramMechanism,
) error {
	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	altered, err := client.adm.AlterUserSCRAMs(reqCtx, nil, []kadm.UpsertSCRAM{{
		User: user, Mechanism: mechanism, Iterations: scramIterations, Password: password,
	}})
	if err != nil {
		return err
	}
	return altered.Error()
}

func publishAdminCredentialAssessment(ctx context.Context, a *Adapter, cfg adapter.Connection, topology map[string]any) {
	assessment, err := a.AssessConnectionAdminCredential(ctx, cfg)
	if err != nil {
		adapter.PublishAdminCredentialAssessment(topology, adapter.AdminCredentialAssessment{BlockedReason: "assessment_failed"})
		return
	}
	adapter.PublishAdminCredentialAssessment(topology, assessment)
}
