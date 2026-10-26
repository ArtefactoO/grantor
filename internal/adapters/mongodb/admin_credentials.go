package mongodb

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

var _ adapter.ConnectionAdminCredentialManager = (*Adapter)(nil)

type mongoAdminCredentialState struct {
	proof        adapter.AdminCredentialProof
	localSCRAM   bool
	writable     bool
	targetProven bool
}

func (a *Adapter) AssessConnectionAdminCredential(ctx context.Context, cfg adapter.Connection) (adapter.AdminCredentialAssessment, error) {
	state, err := a.proveConnectionAdminCredential(ctx, cfg, cfg.AdminCredential)
	if err != nil {
		return adapter.AdminCredentialAssessment{}, err
	}
	rotate := state.localSCRAM && state.writable && state.targetProven
	reason := ""
	switch {
	case !state.localSCRAM:
		reason = "requires_local_scram_user"
	case !state.writable:
		reason = "read_only_target"
	case !state.targetProven:
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
				client, err := a.connect(ctx, cfg)
				if err != nil {
					return errors.New("mongodb: rotate connection admin credential: target unavailable")
				}
				defer disconnect(client)
				hello, err := runHello(ctx, client)
				if err != nil {
					return fmt.Errorf("mongodb: rotate connection admin credential: %w", err)
				}
				writable, _ := hello["isWritablePrimary"].(bool)
				if !writable {
					return fmt.Errorf("mongodb: rotate connection admin credential: target is not writable: %w",
						adapter.ErrAdminCredentialRotationUnsupported)
				}
				actualTarget, _, identityErr := discoverMongoTargetIdentity(ctx, client, hello)
				if identityErr != nil || actualTarget == "" || actualTarget != oldProof.TargetIdentity {
					return fmt.Errorf("mongodb: rotate connection admin credential: target identity unavailable: %w",
						adapter.ErrTargetIdentityConflict)
				}
				info, found, err := fetchAdminUserInfo(ctx, client, cfg.AdminCredential.Username, authSource(cfg))
				if err != nil || !found || !mongoUserHasLocalSCRAM(info) {
					return fmt.Errorf("mongodb: rotate connection admin credential: admin identity changed: %w",
						adapter.ErrAdminCredentialRotationUnsupported)
				}
				cmd := mongoAdminUpdateUserCommand(cfg.AdminCredential.Username, credential.Secret)
				if err := client.Database(authSource(cfg)).RunCommand(ctx, cmd).Err(); err != nil {
					return fmt.Errorf("mongodb: rotate connection admin credential: updateUser failed")
				}
				return nil
			},
		})
}

func mongoAdminUpdateUserCommand(username string, password []byte) bson.D {
	return bson.D{{Key: "updateUser", Value: username},
		{Key: "pwd", Value: string(password)},
		{Key: "writeConcern", Value: bson.D{{Key: "w", Value: "majority"}}}}
}

type mongoAdminUserInfo struct {
	User           string    `bson:"user"`
	DB             string    `bson:"db"`
	Roles          []roleRef `bson:"roles"`
	InheritedRoles []roleRef `bson:"inheritedRoles"`
	Mechanisms     []string  `bson:"mechanisms"`
}

func fetchAdminUserInfo(ctx context.Context, client *mongo.Client, user, database string) (mongoAdminUserInfo, bool, error) {
	var result struct {
		Users []mongoAdminUserInfo `bson:"users"`
	}
	cmd := bson.D{{Key: "usersInfo", Value: user}, {Key: "showPrivileges", Value: true}}
	if err := client.Database(database).RunCommand(ctx, cmd).Decode(&result); err != nil {
		return mongoAdminUserInfo{}, false, fmt.Errorf("read admin user metadata: %w", err)
	}
	if len(result.Users) == 0 {
		return mongoAdminUserInfo{}, false, nil
	}
	if len(result.Users) != 1 || result.Users[0].User != user || result.Users[0].DB != database {
		return mongoAdminUserInfo{}, false, errors.New("read admin user metadata: ambiguous identity")
	}
	return result.Users[0], true, nil
}

func mongoUserHasLocalSCRAM(info mongoAdminUserInfo) bool {
	if info.DB == "$external" || len(info.Mechanisms) == 0 {
		return false
	}
	for _, mechanism := range info.Mechanisms {
		if mechanism != "SCRAM-SHA-1" && mechanism != "SCRAM-SHA-256" {
			return false
		}
	}
	return true
}

func (a *Adapter) proveConnectionAdminCredential(ctx context.Context, cfg adapter.Connection,
	credential adapter.Credential,
) (mongoAdminCredentialState, error) {
	if credential.Kind != "password" || credential.Username == "" || len(credential.Secret) == 0 {
		return mongoAdminCredentialState{}, errors.New("mongodb: admin username and password are required")
	}
	database := authSource(cfg)
	probe := credentialConnection(cfg, credential.Username, database, credential.Secret)
	client, err := a.connect(ctx, probe)
	if err != nil {
		if isMongoAuthenticationFailure(err) {
			return mongoAdminCredentialState{}, fmt.Errorf("mongodb: admin credential rejected: %w",
				adapter.ErrAdminCredentialRejected)
		}
		return mongoAdminCredentialState{}, errors.New("mongodb: prove admin credential: target unavailable")
	}
	defer disconnect(client)

	var status struct {
		AuthInfo struct {
			AuthenticatedUsers []struct {
				User string `bson:"user"`
				DB   string `bson:"db"`
			} `bson:"authenticatedUsers"`
			AuthenticatedUserRoles      []roleRef       `bson:"authenticatedUserRoles"`
			AuthenticatedUserPrivileges []rolePrivilege `bson:"authenticatedUserPrivileges"`
		} `bson:"authInfo"`
	}
	cmd := bson.D{{Key: "connectionStatus", Value: 1}, {Key: "showPrivileges", Value: true}}
	if err := client.Database(adminDatabase).RunCommand(ctx, cmd).Decode(&status); err != nil {
		if isMongoAuthenticationFailure(err) {
			return mongoAdminCredentialState{}, fmt.Errorf("mongodb: admin credential rejected: %w",
				adapter.ErrAdminCredentialRejected)
		}
		return mongoAdminCredentialState{}, fmt.Errorf("mongodb: read admin authority: %w", err)
	}
	users := status.AuthInfo.AuthenticatedUsers
	if len(users) != 1 || users[0].User != credential.Username || users[0].DB != database {
		return mongoAdminCredentialState{}, fmt.Errorf("mongodb: authenticated as another identity: %w",
			adapter.ErrAdminCredentialRejected)
	}
	granted := make(map[string]bool)
	var facts []string
	for _, role := range status.AuthInfo.AuthenticatedUserRoles {
		facts = append(facts, "role="+role.DB+"."+role.Role)
	}
	for _, privilege := range normalizeObservedPrivileges(status.AuthInfo.AuthenticatedUserPrivileges) {
		resource := observedResourceKey(privilege.Resource)
		for _, action := range privilege.Actions {
			granted[action] = true
			facts = append(facts, "privilege="+resource+":"+action)
		}
	}
	for _, action := range userManagementActions {
		if !granted[action] {
			return mongoAdminCredentialState{}, fmt.Errorf("mongodb: admin authority is insufficient: %w",
				adapter.ErrAdminCredentialAuthorityChanged)
		}
	}
	info, found, err := fetchAdminUserInfo(ctx, client, credential.Username, database)
	if err != nil {
		return mongoAdminCredentialState{}, fmt.Errorf("mongodb: read admin identity: %w", err)
	}
	if !found {
		return mongoAdminCredentialState{}, fmt.Errorf("mongodb: admin identity disappeared: %w",
			adapter.ErrAdminCredentialProofAmbiguous)
	}
	for _, role := range append(slices.Clone(info.Roles), info.InheritedRoles...) {
		facts = append(facts, "user_role="+role.DB+"."+role.Role)
	}

	wrong, err := mongodbProbePassword()
	if err != nil {
		return mongoAdminCredentialState{}, fmt.Errorf("mongodb: generate negative admin proof: %w", err)
	}
	defer clear(wrong)
	negative := credentialConnection(cfg, credential.Username, database, wrong)
	negativeErr := a.proveAuthenticatedIdentity(ctx, negative, credential.Username, database)
	if negativeErr == nil {
		return mongoAdminCredentialState{}, fmt.Errorf("mongodb: password authentication is not enforced: %w",
			adapter.ErrAdminCredentialProofAmbiguous)
	}
	if !errors.Is(negativeErr, adapter.ErrExternalIdentityConflict) {
		return mongoAdminCredentialState{}, fmt.Errorf("mongodb: negative admin proof is ambiguous: %w",
			adapter.ErrAdminCredentialProofAmbiguous)
	}

	hello, err := runHello(ctx, client)
	if err != nil {
		return mongoAdminCredentialState{}, fmt.Errorf("mongodb: read admin target topology: %w", err)
	}
	writable, _ := hello["isWritablePrimary"].(bool)
	targetIdentity, _, identityErr := discoverMongoTargetIdentity(ctx, client, hello)
	return mongoAdminCredentialState{
		proof: adapter.AdminCredentialProof{
			CanonicalIdentity:    engineIdentity(credential.Username, database),
			AuthorityFingerprint: adapter.AdminCredentialAuthorityFingerprint(facts...),
			TargetIdentity:       targetIdentity,
		},
		localSCRAM: mongoUserHasLocalSCRAM(info), writable: writable, targetProven: identityErr == nil,
	}, nil
}

func publishAdminCredentialAssessment(ctx context.Context, a *Adapter, cfg adapter.Connection, topology map[string]any) {
	assessment, err := a.AssessConnectionAdminCredential(ctx, cfg)
	if err != nil {
		adapter.PublishAdminCredentialAssessment(topology, adapter.AdminCredentialAssessment{BlockedReason: "assessment_failed"})
		return
	}
	adapter.PublishAdminCredentialAssessment(topology, assessment)
}
