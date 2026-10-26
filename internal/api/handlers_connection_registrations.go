package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connectionregistration"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/locks"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/readscope"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/netguard"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
)

type connectionRegistrationRequest struct {
	RegistrationKey         string          `json:"registration_key"`
	RequestID               uuid.UUID       `json:"request_id"`
	DisplayName             string          `json:"display_name"`
	Engine                  string          `json:"engine"`
	AuthMode                string          `json:"auth_mode,omitempty"`
	Environment             string          `json:"environment"`
	Tags                    []string        `json:"tags"`
	Endpoints               []string        `json:"endpoints"`
	ExecutionMode           string          `json:"execution_mode"`
	TLSConfig               json.RawMessage `json:"tls_config"`
	DiscoveryConfig         json.RawMessage `json:"discovery_config"`
	CredentialSourceID      uuid.UUID       `json:"credential_source_id"`
	CredentialSourceVersion int             `json:"credential_source_version"`
}

var connectionRegistrationKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// Credential use is bound to the approved destination and transport. Machines
// may change display fields, but cannot redirect a delegated credential or
// disable certificate verification after an admin approves its source.
type connectionRegistrationTarget struct {
	Engine          string          `json:"engine"`
	AuthMode        string          `json:"auth_mode,omitempty"`
	Endpoints       []string        `json:"endpoints"`
	ExecutionMode   string          `json:"execution_mode"`
	TLSConfig       json.RawMessage `json:"tls_config"`
	DiscoveryConfig json.RawMessage `json:"discovery_config"`
	NetworkGuard    string          `json:"network_guard,omitempty"`
}

func (target connectionRegistrationTarget) derivedNetworkGuard() string {
	tls, err := validateTLSConfig(target.TLSConfig)
	if err != nil {
		return ""
	}
	return netguard.KubernetesDNSNetworkGuard(target.ExecutionMode, tls.Mode, target.Endpoints)
}

func (target *connectionRegistrationTarget) validate(engines []string) error {
	if err := validateConnectionAuthMode(target.Engine, target.AuthMode); err != nil {
		return err
	}
	if !slices.Contains(engines, target.Engine) {
		return errors.New("engine is not supported")
	}
	if target.ExecutionMode == "" {
		target.ExecutionMode = connections.ExecutionModeDirect
	}
	if !connections.ValidExecutionMode(target.ExecutionMode) {
		return errors.New("execution_mode must be direct or connector")
	}
	if len(target.Endpoints) == 0 {
		return errors.New("endpoints must be a non-empty list")
	}
	for _, endpoint := range target.Endpoints {
		if err := validateEndpoint(endpoint); err != nil {
			return err
		}
	}
	if len(bytes.TrimSpace(target.TLSConfig)) == 0 {
		target.TLSConfig = json.RawMessage(`{}`)
	}
	if len(bytes.TrimSpace(target.DiscoveryConfig)) == 0 {
		target.DiscoveryConfig = json.RawMessage(`{}`)
	}
	tls, err := validateTLSConfig(target.TLSConfig)
	if err != nil {
		return err
	}
	if err := validateDiscoveryConfig(target.DiscoveryConfig, target.Engine, tls); err != nil {
		return err
	}
	target.NetworkGuard = target.derivedNetworkGuard()
	return nil
}

func (req connectionRegistrationRequest) target() connectionRegistrationTarget {
	target := connectionRegistrationTarget{Engine: req.Engine, AuthMode: req.AuthMode, Endpoints: req.Endpoints, ExecutionMode: req.ExecutionMode, TLSConfig: req.TLSConfig, DiscoveryConfig: req.DiscoveryConfig}
	if target.AuthMode == "password" {
		target.AuthMode = ""
	}
	target.NetworkGuard = target.derivedNetworkGuard()
	return target
}

func (req *connectionRegistrationRequest) validate(engines []string) error {
	if !connectionRegistrationKeyPattern.MatchString(req.RegistrationKey) {
		return errors.New("registration_key must be 1 to 128 ASCII letters, digits or . _ : -")
	}
	if req.RequestID == uuid.Nil || (req.AuthMode != "none" && (req.CredentialSourceID == uuid.Nil || req.CredentialSourceVersion <= 0)) {
		return errors.New("request_id and a versioned credential_source_id are required")
	}
	if req.AuthMode == "none" && (req.CredentialSourceID != uuid.Nil || req.CredentialSourceVersion != 0) {
		return errors.New("credential source must be omitted in no-auth mode")
	}
	if strings.TrimSpace(req.DisplayName) == "" {
		return errors.New("display_name is required")
	}
	if strings.TrimSpace(req.Environment) == "" || len(req.Environment) > 160 {
		return errors.New("environment is required and must fit 160 bytes")
	}
	target := req.target()
	if err := target.validate(engines); err != nil {
		return err
	}
	req.ExecutionMode, req.TLSConfig, req.DiscoveryConfig = target.ExecutionMode, target.TLSConfig, target.DiscoveryConfig
	if req.Tags == nil {
		req.Tags = []string{}
	}
	return nil
}

// The persisted comparison document is deliberately constructed, rather than
// serializing a credential-bearing DTO or retaining arbitrary request fields.
func (req connectionRegistrationRequest) spec() (json.RawMessage, error) {
	return json.Marshal(struct {
		DisplayName     string          `json:"display_name"`
		Engine          string          `json:"engine"`
		AuthMode        string          `json:"auth_mode,omitempty"`
		Environment     string          `json:"environment"`
		Tags            []string        `json:"tags"`
		Endpoints       []string        `json:"endpoints"`
		ExecutionMode   string          `json:"execution_mode"`
		TLSConfig       json.RawMessage `json:"tls_config"`
		DiscoveryConfig json.RawMessage `json:"discovery_config"`
		NetworkGuard    string          `json:"network_guard,omitempty"`
	}{req.DisplayName, req.Engine, req.target().AuthMode, req.Environment, req.Tags, req.Endpoints, req.ExecutionMode, req.TLSConfig, req.DiscoveryConfig, req.target().NetworkGuard})
}

type connectionRegistrationJSON struct {
	ID                      uuid.UUID `json:"id"`
	RegistrationKey         string    `json:"registration_key"`
	Environment             string    `json:"environment"`
	ConnectionID            uuid.UUID `json:"connection_id"`
	OperationID             uuid.UUID `json:"operation_id"`
	Phase                   string    `json:"phase"`
	Status                  string    `json:"status"`
	Replayed                bool      `json:"replayed,omitempty"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
	OwnerType               string    `json:"owner_type"`
	OwnerID                 uuid.UUID `json:"owner_id"`
	CredentialSourceID      uuid.UUID `json:"credential_source_id"`
	CredentialSourceVersion int       `json:"credential_source_version"`
}

func (s *Server) connectionRegistrationReadScope(ctx context.Context, sess auth.Session) (*readscope.Scope, error) {
	if registrationMaintenanceAdmin(ctx, sess) {
		return nil, nil
	}
	environments, allowAll, err := s.allowedEnvironments(ctx, sess)
	if err != nil {
		return nil, err
	}
	return &readscope.Scope{Environments: environments, AllowAll: allowAll, ActorType: sess.ActorType(), ActorID: sess.ActorID()}, nil
}

func (s *Server) connectionRegistrationJSON(ctx context.Context, sess auth.Session, reg connectionregistration.Registration, replayed bool) (connectionRegistrationJSON, error) {
	readScope, err := s.connectionRegistrationReadScope(ctx, sess)
	if err != nil {
		return connectionRegistrationJSON{}, err
	}
	if reg.Phase == "registered" {
		exists, err := s.connectionRegistrations.OperationExists(ctx, s.pool, reg.OperationID)
		if err != nil {
			return connectionRegistrationJSON{}, err
		}
		if exists {
			// The general scope helper may query policies through the pool.
			// Run it before acquiring a transaction connection; the predicate
			// below independently rechecks the full graph inside the snapshot.
			if err := s.checkOperationReadScope(ctx, sess, reg.OperationID); err != nil {
				return connectionRegistrationJSON{}, err
			}
		}
	}
	// Authorization and the projected status use one database snapshot. A
	// concurrent admin reconfigure cannot move the connection after the scope
	// check and lend the caller an outcome from a newly foreign environment.
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return connectionRegistrationJSON{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	allowed, err := s.connectionRegistrations.ReadAllowed(ctx, tx, reg.ID, readScope)
	if err != nil {
		return connectionRegistrationJSON{}, err
	}
	if !allowed {
		return connectionRegistrationJSON{}, errScopeForbidden
	}
	status := reg.Phase
	if reg.Phase == "registered" {
		op, err := s.operations.Get(ctx, tx, reg.OperationID)
		switch {
		case errors.Is(err, operations.ErrNotFound):
			status = "expired"
		case err != nil:
			return connectionRegistrationJSON{}, err
		default:
			status = string(op.Status)
		}
	}
	return connectionRegistrationJSON{ID: reg.ID, RegistrationKey: reg.RegistrationKey, Environment: reg.Environment, ConnectionID: reg.ConnectionID, OperationID: reg.OperationID, Phase: reg.Phase, Status: status, Replayed: replayed, CreatedAt: reg.CreatedAt, UpdatedAt: reg.UpdatedAt, OwnerType: reg.Owner.Type, OwnerID: reg.Owner.ID, CredentialSourceID: reg.CredentialSourceID, CredentialSourceVersion: reg.CredentialSourceVersion}, nil
}

func credentialOwner(sess auth.Session) (connectionregistration.Owner, bool) {
	typeName, id, ok := SessionCredentialOwner(sess)
	parsed, err := uuid.Parse(id)
	owner := connectionregistration.Owner{Type: typeName, ID: parsed}
	return owner, ok && err == nil && owner.Valid()
}

func registrationMaintenanceAdmin(ctx context.Context, sess auth.Session) bool {
	return !sess.Service && sess.Role.Allows(auth.RoleAdmin) && !auth.IsTokenAuth(ctx)
}

func (s *Server) createConnectionRegistration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	owner, ok := credentialOwner(sess)
	if !ok {
		respondError(w, http.StatusForbidden, "registration requires a Grantor API credential")
		return
	}
	allowed, err := s.canRegisterConnections(ctx, sess)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if !allowed {
		respondError(w, http.StatusForbidden, "connection registration is not allowed")
		return
	}
	var req connectionRegistrationRequest
	if !decodeConnectionOnboardingJSON(w, r, &req) {
		return
	}
	if err := req.validate(adapter.Engines()); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.checkRegistrationScope(ctx, sess, req.Environment); err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}
	for _, endpoint := range req.Endpoints {
		if err := checkEndpointPolicy(ctx, s.netPolicy, s.resolver, endpoint); err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	spec, err := req.spec()
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := s.connectionRegistrations.LockOwner(ctx, tx, owner); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	// Return the same denial for an unknown or foreign source; do not turn a
	// foreign-key failure into an existence oracle or an internal-error result.
	if req.AuthMode != "none" {
		if _, err := s.connectionRegistrations.GetSource(ctx, tx, req.CredentialSourceID, false); err != nil {
			if errors.Is(err, connectionregistration.ErrNotFound) {
				respondError(w, http.StatusForbidden, "forbidden")
			} else {
				respondStoreError(ctx, w, err)
			}
			return
		}
	}
	reg, created, err := s.connectionRegistrations.Reserve(ctx, tx, connectionregistration.ReserveParams{Owner: owner, RequestID: req.RequestID, RegistrationKey: req.RegistrationKey, Environment: req.Environment, Spec: spec, CredentialSourceID: req.CredentialSourceID, CredentialSourceVersion: req.CredentialSourceVersion})
	if err != nil {
		respondConnectionRegistrationError(ctx, w, err)
		return
	}
	if reg.Phase == "cancelled" || reg.Phase == "canceling" {
		respondError(w, http.StatusConflict, "registration is cancelled; use a new registration key and request id")
		return
	}
	if reg.Phase == "registered" {
		readScope, err := s.connectionRegistrationReadScope(ctx, sess)
		if err != nil {
			respondStoreError(ctx, w, err)
			return
		}
		allowed, err := s.connectionRegistrations.ReadAllowed(ctx, tx, reg.ID, readScope)
		if err != nil {
			respondStoreError(ctx, w, err)
			return
		}
		if !allowed {
			respondError(w, http.StatusForbidden, "forbidden")
			return
		}
	}
	if reg.Phase != "registered" && req.AuthMode != "none" {
		if _, err := s.approvedConnectionCredentialSource(ctx, tx, reg); err != nil {
			s.respondScopeError(ctx, w, err)
			return
		}
		if s.vault == nil {
			respondError(w, http.StatusServiceUnavailable, "credential storage is unavailable")
			return
		}
	}
	if created {
		if err := s.writeAudit(ctx, tx, audit.Event{ActorType: sess.ActorType(), ActorID: sess.ActorID(), Action: "connection_registration.requested", Result: audit.ResultSuccess}, map[string]any{"registration_id": reg.ID, "registration_key": reg.RegistrationKey, "environment": reg.Environment, "credential_source_id": reg.CredentialSourceID, "credential_source_version": reg.CredentialSourceVersion}); err != nil {
			respondStoreError(ctx, w, err)
			return
		}
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if reg.Phase != "registered" {
		reg, err = s.completeConnectionRegistration(ctx, sess, reg)
		if err != nil {
			if errors.Is(err, errOnboardingCredentialUnavailable) {
				respondJSON(w, http.StatusBadGateway, map[string]any{"error": "credential registration could not be confirmed; retry the same request", "registration_id": reg.ID})
				return
			}
			if errors.Is(err, errScopeForbidden) {
				s.respondScopeError(ctx, w, err)
				return
			}
			respondConnectionRegistrationError(ctx, w, err)
			return
		}
	}
	out, err := s.connectionRegistrationJSON(ctx, sess, reg, !created)
	if err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}
	respondJSON(w, http.StatusAccepted, out)
}

var errOnboardingCredentialUnavailable = errors.New("connection registration credential is unavailable")

func (s *Server) approvedConnectionCredentialSource(ctx context.Context, q connectionregistration.Querier, reg connectionregistration.Registration) (connectionregistration.Source, error) {
	source, err := s.connectionRegistrations.GetSource(ctx, q, reg.CredentialSourceID, true)
	if errors.Is(err, connectionregistration.ErrNotFound) {
		return connectionregistration.Source{}, errScopeForbidden
	}
	if err != nil {
		return connectionregistration.Source{}, err
	}
	if source.Owner != reg.Owner || source.Environment != reg.Environment || source.Status != "active" || source.Version != reg.CredentialSourceVersion {
		return connectionregistration.Source{}, errScopeForbidden
	}
	var target connectionRegistrationTarget
	if json.Unmarshal(reg.Spec, &target) != nil {
		return connectionregistration.Source{}, errScopeForbidden
	}
	if target.NetworkGuard != target.derivedNetworkGuard() {
		return connectionregistration.Source{}, errScopeForbidden
	}
	bound, err := json.Marshal(target)
	if err != nil {
		return connectionregistration.Source{}, err
	}
	if !rawJSONEqual(bound, source.TargetSpec) {
		return connectionregistration.Source{}, errScopeForbidden
	}
	return source, nil
}

func (s *Server) completeConnectionRegistration(ctx context.Context, sess auth.Session, reg connectionregistration.Registration) (connectionregistration.Registration, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return reg, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := s.connectionRegistrations.LockOwner(ctx, tx, reg.Owner); err != nil {
		return reg, err
	}
	reg, err = s.connectionRegistrations.Get(ctx, tx, reg.ID)
	if err != nil {
		return reg, err
	}
	if reg.Phase == "registered" {
		return reg, nil
	}
	if reg.Phase == "canceling" || reg.Phase == "cancelled" {
		return reg, connectionregistration.ErrConflict
	}
	if err := s.checkRegistrationScope(ctx, sess, reg.Environment); err != nil {
		return reg, err
	}
	allowed, err := s.canRegisterConnections(ctx, sess)
	if err != nil {
		return reg, err
	}
	if !allowed {
		return reg, errScopeForbidden
	}
	var spec createConnectionRequest
	if err := json.Unmarshal(reg.Spec, &spec); err != nil {
		return reg, errors.New("connection registration spec is invalid")
	}
	if err := validateConnectionAuthMode(spec.Engine, spec.AuthMode); err != nil {
		return reg, err
	}
	canonicalPath := ""
	if spec.AuthMode != "none" {
		source, err := s.approvedConnectionCredentialSource(ctx, tx, reg)
		if err != nil {
			return reg, err
		}
		data, err := s.vault.GetVersion(ctx, connectionregistration.SourcePath(source.ID), reg.CredentialSourceVersion)
		if err != nil {
			return reg, errOnboardingCredentialUnavailable
		}
		username, userOK := data["username"].(string)
		password, passwordOK := data["password"].(string)
		if !userOK || !passwordOK || username == "" || password == "" {
			return reg, errOnboardingCredentialUnavailable
		}
		canonicalPath, err = vault.ConnectionAdminPath(reg.ConnectionID.String())
		if err != nil {
			return reg, err
		}
		version, err := s.putOnboardingCredential(ctx, canonicalPath, map[string]any{"username": username, "password": password})
		if err != nil {
			return reg, errOnboardingCredentialUnavailable
		}
		if reg.CanonicalVersion == 0 {
			reg, err = s.connectionRegistrations.SetCanonicalVersion(ctx, tx, reg.ID, version)
			if err != nil {
				return reg, err
			}
		} else if reg.CanonicalVersion != version {
			return reg, connectionregistration.ErrConflict
		}
	} else if reg.Phase == "preparing" {
		if reg.CredentialSourceID != uuid.Nil || reg.CredentialSourceVersion != 0 {
			return reg, connectionregistration.ErrConflict
		}
		reg, err = s.connectionRegistrations.SetNoAuthReady(ctx, tx, reg.ID)
		if err != nil {
			return reg, err
		}
	}
	ad, err := adapter.New(spec.Engine)
	if err != nil {
		return reg, err
	}
	if err := locks.AcquireTx(ctx, tx, reg.ConnectionID); err != nil {
		return reg, err
	}
	conn, err := s.connections.Create(ctx, tx, connections.CreateParams{ID: &reg.ConnectionID, DisplayName: spec.DisplayName, Engine: spec.Engine, AuthMode: spec.AuthMode, Environment: spec.Environment, Tags: spec.Tags, Endpoints: spec.Endpoints, ExecutionMode: spec.ExecutionMode, TLSConfig: spec.TLSConfig, DiscoveryConfig: spec.DiscoveryConfig, Capabilities: ad.Manifest().CapabilityNames(), VaultAdminPath: canonicalPath})
	if err != nil {
		return reg, err
	}
	if _, err := tx.Exec(ctx, `update connections set admin_credential_set_at=case when auth_mode='none' then null else now() end where id=$1`, conn.ID); err != nil {
		return reg, err
	}
	chain, err := refreshTransitions(conn.Status)
	if err != nil {
		return reg, err
	}
	from := conn.Status
	for _, to := range chain {
		if _, err := s.connections.Transition(ctx, tx, conn.ID, from, to); err != nil {
			return reg, err
		}
		from = to
	}
	key := "connection.registration.discover:" + reg.ID.String()
	op, created, err := s.operations.Create(ctx, tx, operations.CreateParams{ID: &reg.OperationID, Kind: jobs.KindConnectionDiscover, IdempotencyKey: &key, ConnectionID: &conn.ID, ActorType: sess.ActorType(), ActorID: sess.ActorID(), CorrelationID: uuid.NewString()})
	if err != nil {
		return reg, err
	}
	if !created || op.ID != reg.OperationID {
		return reg, fmt.Errorf("connection registration discovery identity conflict: %w", connectionregistration.ErrConflict)
	}
	if err := s.dispatcher.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
		return reg, err
	}
	auditMetadata := map[string]any{"registration_id": reg.ID, "display_name": conn.DisplayName, "engine": conn.Engine, "environment": conn.Environment, "endpoints": conn.Endpoints, "tls_mode": effectiveTLSMode(parseTLSConfigView(conn.TLSConfig))}
	if findings := securityFindings(conn); len(findings) > 0 {
		auditMetadata["security_findings"] = findings
	}
	if err := s.writeAudit(ctx, tx, audit.Event{ActorType: sess.ActorType(), ActorID: sess.ActorID(), Action: auditActionConnectionCreated, ConnectionID: &conn.ID, OperationID: &op.ID, Result: audit.ResultSuccess}, auditMetadata); err != nil {
		return reg, err
	}
	reg, err = s.connectionRegistrations.MarkRegistered(ctx, tx, reg.ID)
	if err != nil {
		return reg, err
	}
	if err := tx.Commit(ctx); err != nil {
		return reg, err
	}
	return reg, nil
}

func (s *Server) getConnectionRegistration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	owner, ok := credentialOwner(sess)
	maintenanceAdmin := registrationMaintenanceAdmin(ctx, sess)
	if !ok && !maintenanceAdmin {
		respondError(w, http.StatusForbidden, "registration requires a Grantor API credential")
		return
	}
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	if !rejectUnknownQuery(w, r) {
		return
	}
	reg, err := s.connectionRegistrations.Get(ctx, s.pool, id)
	if err != nil {
		respondConnectionRegistrationError(ctx, w, err)
		return
	}
	if reg.Owner != owner && !maintenanceAdmin {
		respondError(w, http.StatusForbidden, "forbidden")
		return
	}
	if err := s.checkRegistrationScope(ctx, sess, reg.Environment); err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}
	out, err := s.connectionRegistrationJSON(ctx, sess, reg, false)
	if err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}
	respondJSON(w, http.StatusOK, out)
}

func (s *Server) listConnectionRegistrations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	owner, ok := credentialOwner(sess)
	maintenanceAdmin := registrationMaintenanceAdmin(ctx, sess)
	if !ok && !maintenanceAdmin {
		respondError(w, http.StatusForbidden, "registration requires a Grantor API credential")
		return
	}
	if !rejectUnknownQuery(w, r, "limit", "offset") {
		return
	}
	limit, err := queryLimit(r, "limit", 100)
	if err != nil || limit <= 0 {
		respondError(w, http.StatusBadRequest, "limit must be positive")
		return
	}
	offset, err := queryInt(r, "offset", 0)
	if err != nil || offset < 0 {
		respondError(w, http.StatusBadRequest, "offset must be non-negative")
		return
	}
	readScope, err := s.connectionRegistrationReadScope(ctx, sess)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	var ownerFilter *connectionregistration.Owner
	if !maintenanceAdmin {
		ownerFilter = &owner
	}
	regs, err := s.connectionRegistrations.ListVisible(ctx, s.pool, ownerFilter, readScope, limit, offset)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	out := make([]connectionRegistrationJSON, 0, len(regs))
	for _, reg := range regs {
		if err := s.checkRegistrationScope(ctx, sess, reg.Environment); err != nil {
			if errors.Is(err, errScopeForbidden) {
				continue
			}
			respondStoreError(ctx, w, err)
			return
		}
		entry, err := s.connectionRegistrationJSON(ctx, sess, reg, false)
		if err != nil {
			if errors.Is(err, errScopeForbidden) {
				continue
			}
			respondStoreError(ctx, w, err)
			return
		}
		out = append(out, entry)
	}
	respondJSON(w, http.StatusOK, map[string]any{"registrations": out})
}

// Canceling an unfinished registration never touches a target cluster. The
// durable phase blocks new writes before deleting a password canonical path.
// No-auth cancellation is metadata-only. Repeated DELETE resumes cleanup.
func (s *Server) deleteConnectionRegistration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	owner, ok := credentialOwner(sess)
	maintenanceAdmin := registrationMaintenanceAdmin(ctx, sess)
	if !ok && !maintenanceAdmin {
		respondError(w, http.StatusForbidden, "registration requires a Grantor API credential")
		return
	}
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	reg, err := s.connectionRegistrations.Get(ctx, tx, id)
	if err != nil {
		respondConnectionRegistrationError(ctx, w, err)
		return
	}
	if reg.Owner != owner && !maintenanceAdmin {
		respondError(w, http.StatusForbidden, "forbidden")
		return
	}
	if err := s.checkRegistrationScope(ctx, sess, reg.Environment); err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}
	if err := s.connectionRegistrations.LockOwner(ctx, tx, reg.Owner); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	reg, err = s.connectionRegistrations.Get(ctx, tx, id)
	if err != nil {
		respondConnectionRegistrationError(ctx, w, err)
		return
	}
	if reg.Phase == "registered" {
		respondError(w, http.StatusConflict, "registration is finalized; use connection lifecycle endpoints")
		return
	}
	if reg.Phase != "cancelled" {
		wasCanceling := reg.Phase == "canceling"
		reg, err = s.connectionRegistrations.BeginCancellation(ctx, tx, id)
		if err != nil {
			respondConnectionRegistrationError(ctx, w, err)
			return
		}
		if !wasCanceling {
			if err := s.writeAudit(ctx, tx, audit.Event{ActorType: sess.ActorType(), ActorID: sess.ActorID(), Action: "connection_registration.cancel_requested", Result: audit.ResultSuccess}, map[string]any{"registration_id": id}); err != nil {
				respondStoreError(ctx, w, err)
				return
			}
		}
		// A no-auth receipt never reserved a Vault credential. Finish it in
		// this transaction so a crash or Vault outage cannot strand cleanup.
		if registrationUsesNoAuth(reg) {
			reg, err = s.connectionRegistrations.FinishCancellation(ctx, tx, id)
			if err != nil {
				respondConnectionRegistrationError(ctx, w, err)
				return
			}
		}

	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	status := http.StatusOK
	if reg.Phase != "cancelled" {
		path, pathErr := vault.ConnectionAdminPath(reg.ConnectionID.String())
		if pathErr != nil {
			respondStoreError(ctx, w, pathErr)
			return
		}
		if s.vault == nil || s.vault.DeleteMetadata(ctx, path) != nil {
			status = http.StatusAccepted
		} else {
			reg, err = s.connectionRegistrations.FinishCancellation(ctx, s.pool, id)
			if err != nil {
				respondConnectionRegistrationError(ctx, w, err)
				return
			}
		}
	}
	out, err := s.connectionRegistrationJSON(ctx, sess, reg, false)
	if err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}
	respondJSON(w, status, out)
}

func registrationUsesNoAuth(reg connectionregistration.Registration) bool {
	if reg.CredentialSourceID != uuid.Nil || reg.CredentialSourceVersion != 0 || reg.CanonicalVersion != 0 {
		return false
	}
	var target struct {
		Engine   string `json:"engine"`
		AuthMode string `json:"auth_mode"`
	}
	return json.Unmarshal(reg.Spec, &target) == nil && target.Engine == "redis" && target.AuthMode == "none"
}
