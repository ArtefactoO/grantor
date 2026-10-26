package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/locks"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/rolepolicies"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/postgresconfig"
)

type postgresProfilesRequest struct {
	RequestID              uuid.UUID `json:"request_id"`
	Database               string    `json:"database"`
	Schemas                []string  `json:"schemas"`
	OwnerRoles             []string  `json:"owner_roles"`
	CreatorRoles           []string  `json:"creator_roles"`
	Profiles               []string  `json:"profiles"`
	ExpectedTargetIdentity string    `json:"expected_target_identity"`
}

type postgresProfilesIntent struct {
	Request           postgresProfilesRequest `json:"request"`
	ConfigIncarnation string                  `json:"config_incarnation"`
	TemplateKeys      []string                `json:"template_keys"`
}

type postgresProfilesPayload struct {
	Intent postgresProfilesIntent `json:"postgres_standard_profiles"`
}

func (req *postgresProfilesRequest) normalizeAndValidate() error {
	if req.RequestID == uuid.Nil || req.Database == "" || strings.TrimSpace(req.ExpectedTargetIdentity) == "" {
		return errors.New("request_id, database and expected_target_identity are required")
	}
	if req.ExpectedTargetIdentity != strings.TrimSpace(req.ExpectedTargetIdentity) {
		return errors.New("expected_target_identity must not have surrounding whitespace")
	}
	if len(req.Schemas) == 0 {
		req.Schemas = []string{"public"}
	}
	if len(req.Profiles) == 0 {
		req.Profiles = []string{postgresconfig.ProfileRead, postgresconfig.ProfileReadWrite}
	}
	seen := make(map[string]bool, len(req.Profiles))
	for _, profile := range req.Profiles {
		if (profile != postgresconfig.ProfileRead && profile != postgresconfig.ProfileReadWrite) || seen[profile] {
			return errors.New("profiles must contain unique read/read_write values")
		}
		seen[profile] = true
	}
	// Validate optional lists before normalization so duplicate identifiers are
	// rejected consistently with the existing catalog contract.
	if _, err := standardPostgresTemplates(*req, "profile_owner"); err != nil {
		return err
	}
	slices.Sort(req.Schemas)
	slices.Sort(req.OwnerRoles)
	slices.Sort(req.CreatorRoles)
	slices.Sort(req.Profiles)
	if len(req.OwnerRoles) == 0 {
		req.OwnerRoles = nil
	}
	if len(req.CreatorRoles) == 0 {
		req.CreatorRoles = nil
	}
	return nil
}

func standardPostgresTemplates(req postgresProfilesRequest, databaseOwner string) ([]postgresconfig.RolePolicyTemplate, error) {
	owners := req.OwnerRoles
	if len(owners) == 0 {
		owners = []string{databaseOwner}
	}
	creators := req.CreatorRoles
	if len(creators) == 0 {
		creators = slices.Clone(owners)
	}
	hash := sha256.Sum256([]byte(req.Database))
	prefix := "database-" + hex.EncodeToString(hash[:6])
	templates := make([]postgresconfig.RolePolicyTemplate, 0, len(req.Profiles))
	for _, profile := range req.Profiles {
		rolePrefix, suffix := "r_", "read"
		if profile == postgresconfig.ProfileReadWrite {
			rolePrefix, suffix = "rw_", "rw"
		}
		templates = append(templates, postgresconfig.RolePolicyTemplate{
			Key: prefix + "-" + suffix, Name: req.Database + " " + strings.ToUpper(suffix),
			Description: "Standard database access profile", RoleName: rolePrefix + req.Database,
			Database: req.Database, Schemas: req.Schemas, OwnerRoles: owners, CreatorRoles: creators, Profile: profile,
		})
	}
	if err := postgresconfig.Validate(templates); err != nil {
		return nil, err
	}
	for i := range templates {
		templates[i] = postgresconfig.Normalize(templates[i])
	}
	return templates, nil
}

func postgresProfilesReplay(op operations.Operation, req postgresProfilesRequest, c connections.Connection) (postgresProfilesIntent, error) {
	var payload postgresProfilesPayload
	if op.Kind != jobs.KindConnectionDiscover || op.ConnectionID == nil || *op.ConnectionID != c.ID ||
		json.Unmarshal(op.Payload, &payload) != nil || payload.Intent.ConfigIncarnation == "" {
		return postgresProfilesIntent{}, errors.New("request_id is already associated with a different operation")
	}
	if !reflect.DeepEqual(payload.Intent.Request, req) {
		return postgresProfilesIntent{}, errors.New("request_id is already associated with a different profile specification")
	}
	if payload.Intent.ConfigIncarnation != connections.ConfigIncarnation(c) {
		return postgresProfilesIntent{}, errors.New("connection configuration changed since the accepted profile request")
	}
	if target := connections.TargetIdentity(c); target != "" && target != req.ExpectedTargetIdentity {
		return postgresProfilesIntent{}, errors.New("target identity changed since the accepted profile request")
	}
	return payload.Intent, nil
}

// This route only appends fixed READ/RW specifications. Operational connection
// PATCH remains unavailable to delegated API keys.
func (s *Server) configurePostgresProfiles(w http.ResponseWriter, r *http.Request) {
	var req postgresProfilesRequest
	if !decodeStrictJSON(w, r, &req) {
		return
	}
	if err := req.normalizeAndValidate(); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err = locks.AcquireTx(ctx, tx, id); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	c, err := s.connections.Get(ctx, tx, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if s.respondScopeError(ctx, w, s.checkConnectionScope(ctx, sess, c.Environment)) {
		return
	}
	key := "postgres-standard-profiles:" + id.String() + ":" + req.RequestID.String()
	if op, lookupErr := s.operations.GetByIdempotencyKey(ctx, tx, key); lookupErr == nil {
		intent, replayErr := postgresProfilesReplay(op, req, c)
		if replayErr != nil {
			respondError(w, http.StatusConflict, replayErr.Error())
			return
		}
		respondJSON(w, http.StatusAccepted, map[string]any{
			"operation_id": op.ID, "template_keys": intent.TemplateKeys, "roles_created": false,
		})
		return
	} else if !errors.Is(lookupErr, operations.ErrNotFound) {
		respondStoreError(ctx, w, lookupErr)
		return
	}
	if c.Engine != "postgres" || c.Status != connections.StatusActive || c.LastDiscoveryAt == nil ||
		connections.TargetIdentity(c) != req.ExpectedTargetIdentity {
		respondError(w, http.StatusConflict, "an active PostgreSQL connection with the reviewed target identity is required")
		return
	}
	resources, err := s.inventory.ListResources(ctx, tx, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	var database *inventory.Resource
	for i := range resources {
		if resources[i].Kind == "database" && resources[i].Name == req.Database && resources[i].Status == inventory.ResourceObserved {
			database = &resources[i]
			break
		}
	}
	if database == nil {
		respondError(w, http.StatusConflict, "database is not present in the current inventory")
		return
	}
	databaseOwner, _ := decodeAttributes(database.Attributes)["owner"].(string)
	additions, err := standardPostgresTemplates(req, databaseOwner)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	knownSchemas, owners := map[string]bool{}, map[string]bool{}
	scope := map[uuid.UUID]bool{database.ID: true}
	for changed := true; changed; {
		changed = false
		for _, res := range resources {
			if res.Status == inventory.ResourceObserved && res.ParentID != nil && scope[*res.ParentID] && !scope[res.ID] {
				scope[res.ID], changed = true, true
			}
		}
	}
	for _, res := range resources {
		if !scope[res.ID] || res.Status != inventory.ResourceObserved {
			continue
		}
		if res.Kind == "schema" {
			knownSchemas[res.Name] = true
		}
		if owner, _ := decodeAttributes(res.Attributes)["owner"].(string); owner != "" {
			owners[owner] = true
		}
	}
	accounts, err := s.inventory.ListAccounts(ctx, tx, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	liveRoles := make(map[string]bool, len(accounts))
	for _, account := range accounts {
		if inventory.IsLiveAccountStatus(account.Status) {
			liveRoles[account.EngineIdentity] = true
		}
	}
	for _, schema := range req.Schemas {
		if !knownSchemas[schema] {
			respondError(w, http.StatusConflict, "schema is not present in the selected database")
			return
		}
	}
	for _, roles := range [][]string{additions[0].OwnerRoles, additions[0].CreatorRoles} {
		for _, owner := range roles {
			if !owners[owner] || !liveRoles[owner] {
				respondError(w, http.StatusConflict, "owner and creator roles must be observed object owners in the selected database")
				return
			}
		}
	}
	var config map[string]json.RawMessage
	if len(c.DiscoveryConfig) > 0 && json.Unmarshal(c.DiscoveryConfig, &config) != nil {
		respondError(w, http.StatusConflict, "stored discovery configuration is invalid")
		return
	}
	if config == nil {
		config = map[string]json.RawMessage{}
	}
	var attributes map[string]any
	if err = json.Unmarshal(c.DiscoveryConfig, &attributes); err != nil {
		respondError(w, http.StatusConflict, "stored discovery configuration is invalid")
		return
	}
	templates, err := postgresconfig.FromAttributes(attributes)
	if err != nil {
		respondError(w, http.StatusConflict, "stored role-policy configuration is invalid")
		return
	}
	policies, err := rolepolicies.NewStore().List(ctx, tx, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	for _, policy := range policies {
		_, active, checkErr := rolepolicies.NewStore().Repairability(ctx, tx, policy)
		if checkErr != nil {
			respondStoreError(ctx, w, checkErr)
			return
		}
		if active {
			respondError(w, http.StatusConflict, "role-policy transition must finish before changing profile configuration")
			return
		}
	}
	keys := make([]string, 0, len(additions))
	for _, addition := range additions {
		keys = append(keys, addition.Key)
		exists := false
		for _, old := range templates {
			if old.Key == addition.Key || old.RoleName == addition.RoleName {
				if !reflect.DeepEqual(postgresconfig.Normalize(old), addition) {
					respondError(w, http.StatusConflict, "a role or template with a different specification already exists")
					return
				}
				exists = true
			}
		}
		for _, policy := range policies {
			if (policy.TemplateKey == addition.Key || policy.DesiredSpec.RoleName == addition.RoleName) &&
				(!exists || policy.TemplateKey != addition.Key || policy.DesiredSpec.RoleName != addition.RoleName) {
				respondError(w, http.StatusConflict, "the profile identity is already associated with another role policy")
				return
			}
		}
		if !exists {
			templates = append(templates, addition)
		}
	}
	if err = postgresconfig.Validate(templates); err != nil {
		respondError(w, http.StatusConflict, err.Error())
		return
	}
	config[postgresconfig.AttributeRolePolicyTemplates], err = json.Marshal(templates)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	next, err := json.Marshal(config)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	specs, err := postgresRolePolicySpecs(next)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err = rolepolicies.NewStore().ValidateTemplateChange(ctx, tx, id, specs); err != nil {
		s.respondRolePolicyError(ctx, w, err)
		return
	}
	updated, err := s.connections.PatchCAS(ctx, tx, id, connections.PatchParams{
		DisplayName: c.DisplayName, Environment: c.Environment, Tags: c.Tags, Endpoints: c.Endpoints,
		TLSConfig: c.TLSConfig, DiscoveryConfig: next, ExpectedUpdatedAt: c.UpdatedAt,
		ExpectedStatus: c.Status, Operational: true,
	})
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	payload, err := json.Marshal(postgresProfilesPayload{Intent: postgresProfilesIntent{
		Request: req, ConfigIncarnation: connections.ConfigIncarnation(updated), TemplateKeys: keys,
	}})
	if err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: marshal profile intent: %w", err))
		return
	}
	op, _, err := s.operations.Create(ctx, tx, operations.CreateParams{
		Kind: jobs.KindConnectionDiscover, IdempotencyKey: &key, ConnectionID: &id, Payload: payload,
		ActorType: sess.ActorType(), ActorID: sess.ActorID(), CorrelationID: req.RequestID.String(),
	})
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err = s.dispatcher.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err = s.writeAudit(ctx, tx, audit.Event{
		Action: "postgres.standard_profiles_requested", ActorType: sess.ActorType(), ActorID: sess.ActorID(),
		ConnectionID: &id, OperationID: &op.ID, Result: audit.ResultSuccess,
	}, map[string]any{"database": req.Database, "template_keys": keys}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err = tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	respondJSON(w, http.StatusAccepted, map[string]any{
		"operation_id": op.ID, "template_keys": keys, "roles_created": false, "inventory_status": "refresh_pending",
	})
}
