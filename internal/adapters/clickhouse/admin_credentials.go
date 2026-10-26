package clickhouse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
)

var (
	_ adapter.ConnectionAdminCredentialManager = (*Adapter)(nil)
	_ adapter.ConnectionCapabilityScoper       = (*Adapter)(nil)
)

type clickHouseAdminCredentialState struct {
	proof    adapter.AdminCredentialProof
	storage  string
	auth     []string
	topology string
}

func (a *Adapter) AssessConnectionAdminCredential(ctx context.Context, cfg adapter.Connection) (adapter.AdminCredentialAssessment, error) {
	state, err := a.proveConnectionAdminCredential(ctx, cfg, cfg.AdminCredential)
	if err != nil {
		return adapter.AdminCredentialAssessment{}, err
	}
	supportedStorage := state.storage == "replicated" || state.storage == "local_directory" && state.topology == "standalone"
	exactAuth := slices.Equal(state.auth, []string{"sha256_password"})
	rotate := supportedStorage && exactAuth && state.proof.TargetIdentity != ""
	reason := ""
	switch {
	case !supportedStorage:
		reason = "unsupported_access_storage_topology"
	case !exactAuth:
		reason = "requires_single_sha256_password"
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
					return errors.New("clickhouse: rotate connection admin credential: target unavailable")
				}
				users, err := client.listUsers(ctx)
				if err != nil {
					return fmt.Errorf("clickhouse: rotate connection admin credential: %w", err)
				}
				var current *chUser
				for i := range users {
					if users[i].Name == cfg.AdminCredential.Username {
						current = &users[i]
						break
					}
				}
				if current == nil || !slices.Equal(current.AuthTypes, []string{"sha256_password"}) {
					return fmt.Errorf("clickhouse: rotate connection admin credential: authentication changed: %w",
						adapter.ErrAdminCredentialRotationUnsupported)
				}
				hosts, err := client.clusterHosts(ctx)
				if err != nil {
					return fmt.Errorf("clickhouse: rotate connection admin credential: read topology: %w", err)
				}
				topology, _ := topologyFromClusters(hosts)[adapterutil.TopologyKey].(string)
				storageSupported := current.Storage == "replicated" ||
					current.Storage == "local_directory" && topology == "standalone"
				if !storageSupported {
					return fmt.Errorf("clickhouse: rotate connection admin credential: storage/topology changed: %w",
						adapter.ErrAdminCredentialRotationUnsupported)
				}
				rows, err := client.query(ctx, `SELECT toString(serverUUID()) AS server_uuid`, nil)
				if err != nil || len(rows) != 1 {
					return fmt.Errorf("clickhouse: rotate connection admin credential: target identity unavailable: %w",
						adapter.ErrTargetIdentityConflict)
				}
				var serverUUID string
				raw, ok := rows[0]["server_uuid"]
				if !ok || json.Unmarshal(raw, &serverUUID) != nil ||
					"clickhouse:server:"+serverUUID != oldProof.TargetIdentity {
					return fmt.Errorf("clickhouse: rotate connection admin credential: target identity changed: %w",
						adapter.ErrTargetIdentityConflict)
				}
				lit, err := quoteLiteral(string(credential.Secret))
				if err != nil {
					return fmt.Errorf("clickhouse: rotate connection admin credential: %w", err)
				}
				stmt := "ALTER USER " + quoteIdent(current.Name) + " IDENTIFIED WITH sha256_password BY " + lit
				if err := client.exec(ctx, stmt, true); err != nil {
					return errors.New("clickhouse: rotate connection admin credential: target response is ambiguous")
				}
				return nil
			},
		})
}

func (a *Adapter) proveConnectionAdminCredential(ctx context.Context, cfg adapter.Connection,
	credential adapter.Credential,
) (clickHouseAdminCredentialState, error) {
	if credential.Kind != "password" || credential.Username == "" || len(credential.Secret) == 0 {
		return clickHouseAdminCredentialState{}, errors.New("clickhouse: admin username and password are required")
	}
	probe := cfg
	probe.AdminCredential = credential
	client, err := a.newClient(probe)
	if err != nil {
		return clickHouseAdminCredentialState{}, errors.New("clickhouse: prove admin credential: invalid connection")
	}
	current, err := a.probeIdentity(ctx, cfg, credential.Username, credential.Secret)
	if err != nil {
		if isAuthenticationFailure(err) {
			return clickHouseAdminCredentialState{}, fmt.Errorf("clickhouse: admin credential rejected: %w",
				adapter.ErrAdminCredentialRejected)
		}
		return clickHouseAdminCredentialState{}, errors.New("clickhouse: prove admin credential: target unavailable")
	}
	if current != credential.Username {
		return clickHouseAdminCredentialState{}, fmt.Errorf("clickhouse: authenticated as another identity: %w",
			adapter.ErrAdminCredentialRejected)
	}
	users, err := client.listUsers(ctx)
	if err != nil {
		return clickHouseAdminCredentialState{}, fmt.Errorf("clickhouse: read admin user metadata: %w", err)
	}
	var user *chUser
	for i := range users {
		if users[i].Name == current {
			user = &users[i]
			break
		}
	}
	if user == nil {
		return clickHouseAdminCredentialState{}, fmt.Errorf("clickhouse: admin user is absent: %w",
			adapter.ErrAdminCredentialProofAmbiguous)
	}
	grantRows, err := client.query(ctx, `SHOW GRANTS`, nil)
	if err != nil {
		return clickHouseAdminCredentialState{}, fmt.Errorf("clickhouse: read admin grants: %w", err)
	}
	grants := grantLines(grantRows)
	if !adminHasAccessManagement(grants) {
		return clickHouseAdminCredentialState{}, fmt.Errorf("clickhouse: admin authority is insufficient: %w",
			adapter.ErrAdminCredentialAuthorityChanged)
	}
	wrong, err := adapterutil.RandomPassword(negativeProbePasswordLength)
	if err != nil {
		return clickHouseAdminCredentialState{}, fmt.Errorf("clickhouse: generate negative admin proof: %w", err)
	}
	defer clear(wrong)
	if _, err := a.probeIdentity(ctx, cfg, credential.Username, wrong); err == nil {
		return clickHouseAdminCredentialState{}, fmt.Errorf("clickhouse: password authentication is not enforced: %w",
			adapter.ErrAdminCredentialProofAmbiguous)
	} else if !isAuthenticationFailure(err) {
		return clickHouseAdminCredentialState{}, fmt.Errorf("clickhouse: negative admin proof is ambiguous: %w",
			adapter.ErrAdminCredentialProofAmbiguous)
	}
	hosts, err := client.clusterHosts(ctx)
	if err != nil {
		return clickHouseAdminCredentialState{}, fmt.Errorf("clickhouse: read topology: %w", err)
	}
	topology, _ := topologyFromClusters(hosts)[adapterutil.TopologyKey].(string)
	targetIdentity := ""
	if rows, targetErr := client.query(ctx, `SELECT toString(serverUUID()) AS server_uuid`, nil); targetErr == nil && len(rows) == 1 {
		var serverUUID string
		if raw, ok := rows[0]["server_uuid"]; ok && json.Unmarshal(raw, &serverUUID) == nil && serverUUID != "" {
			targetIdentity = "clickhouse:server:" + serverUUID
		}
	}
	slices.Sort(grants)
	facts := append([]string{"storage=" + user.Storage}, grants...)
	for _, authType := range user.AuthTypes {
		facts = append(facts, "auth="+authType)
	}
	return clickHouseAdminCredentialState{
		proof: adapter.AdminCredentialProof{
			CanonicalIdentity:    current,
			AuthorityFingerprint: adapter.AdminCredentialAuthorityFingerprint(facts...),
			TargetIdentity:       targetIdentity,
		},
		storage: user.Storage, auth: slices.Clone(user.AuthTypes), topology: topology,
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
