package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connectionregistration"
)

type createConnectionCredentialSourceRequest struct {
	Name            string          `json:"name"`
	Environment     string          `json:"environment"`
	OwnerType       string          `json:"owner_type"`
	OwnerID         string          `json:"owner_id"`
	Username        string          `json:"username"`
	Password        string          `json:"password"`
	Engine          string          `json:"engine"`
	Endpoints       []string        `json:"endpoints"`
	ExecutionMode   string          `json:"execution_mode"`
	TLSConfig       json.RawMessage `json:"tls_config"`
	DiscoveryConfig json.RawMessage `json:"discovery_config"`
}

type connectionCredentialSourceJSON struct {
	ID             uuid.UUID       `json:"id"`
	Name           string          `json:"name"`
	Environment    string          `json:"environment"`
	OwnerType      string          `json:"owner_type"`
	OwnerID        uuid.UUID       `json:"owner_id"`
	Version        int             `json:"version"`
	Status         string          `json:"status"`
	CleanupPending bool            `json:"cleanup_pending"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
	RevokedAt      *time.Time      `json:"revoked_at"`
	Target         json.RawMessage `json:"target"`
}

func toConnectionCredentialSourceJSON(s connectionregistration.Source) connectionCredentialSourceJSON {
	return connectionCredentialSourceJSON{ID: s.ID, Name: s.Name, Environment: s.Environment, OwnerType: s.Owner.Type, OwnerID: s.Owner.ID, Version: s.Version, Status: s.Status, CleanupPending: s.CleanupPending, CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt, RevokedAt: s.RevokedAt, Target: s.TargetSpec}
}

// Onboarding accepts only an exact DTO, including a single JSON value. In
// particular, raw Vault paths/mounts cannot be silently ignored as success.
func decodeConnectionOnboardingJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(dst) != nil {
		respondError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		respondError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

func (req *createConnectionCredentialSourceRequest) validate() (connectionregistration.Owner, error) {
	req.Name = strings.TrimSpace(req.Name)
	req.Environment = strings.TrimSpace(req.Environment)
	id, err := uuid.Parse(req.OwnerID)
	owner := connectionregistration.Owner{Type: req.OwnerType, ID: id}
	if err != nil || !owner.Valid() {
		return owner, errors.New("owner_type and a valid owner_id are required")
	}
	if len(req.Name) == 0 || len(req.Name) > 160 {
		return owner, errors.New("name must be between 1 and 160 bytes")
	}
	if len(req.Environment) == 0 || len(req.Environment) > 160 {
		return owner, errors.New("environment must be between 1 and 160 bytes")
	}
	if req.Username == "" || req.Password == "" || len(req.Username) > 1024 || len(req.Password) > 65536 {
		return owner, errors.New("username and password are required and must fit credential limits")
	}
	return owner, nil
}

// A source is durably reserved before Vault IO. Failed/ambiguous writes remain
// addressable in the admin list and can be revoked and cleaned up by ID.
func (s *Server) createConnectionCredentialSource(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	var req createConnectionCredentialSourceRequest
	if !decodeConnectionOnboardingJSON(w, r, &req) {
		return
	}
	owner, err := req.validate()
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.requireCanManageCredentialSource(ctx, sess, owner.Type, owner.ID.String(), req.Environment); err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}
	if err := s.requireCredentialSourceOwnerActive(ctx, owner.Type, owner.ID.String()); err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}
	target := connectionRegistrationTarget{Engine: req.Engine, Endpoints: req.Endpoints, ExecutionMode: req.ExecutionMode, TLSConfig: req.TLSConfig, DiscoveryConfig: req.DiscoveryConfig}
	if err := target.validate(adapter.Engines()); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	for _, endpoint := range target.Endpoints {
		if err := checkEndpointPolicy(ctx, s.netPolicy, s.resolver, endpoint); err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if err := validateCredentialSourceTransport(target); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	boundTarget, err := json.Marshal(target)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if s.vault == nil {
		respondError(w, http.StatusServiceUnavailable, "credential storage is unavailable")
		return
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	source, err := s.connectionRegistrations.CreateSource(ctx, tx, connectionregistration.Source{ID: uuid.New(), Name: req.Name, Owner: owner, Environment: req.Environment, TargetSpec: boundTarget})
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.writeAudit(ctx, tx, audit.Event{ActorType: sess.ActorType(), ActorID: sess.ActorID(), Action: "connection_credential_source.reserved", Result: audit.ResultSuccess}, map[string]any{"source_id": source.ID, "owner_type": owner.Type, "owner_id": owner.ID, "environment": source.Environment}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	finalTx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer finalTx.Rollback(ctx) //nolint:errcheck
	lockedSource, err := s.connectionRegistrations.GetSource(ctx, finalTx, source.ID, true)
	if err != nil {
		respondConnectionRegistrationError(ctx, w, err)
		return
	}
	if lockedSource.Status != "preparing" {
		respondError(w, http.StatusConflict, "credential source was revoked before storage")
		return
	}
	data := map[string]any{"username": req.Username, "password": req.Password}
	version, err := s.putOnboardingCredential(ctx, connectionregistration.SourcePath(source.ID), data)
	// Provider errors may carry request/response details. Expose only a safe
	// code and the durable reservation ID, never the underlying error text.
	if err != nil {
		respondJSON(w, http.StatusBadGateway, map[string]any{"error": "credential source could not be stored; revoke the reserved source before retrying", "source_id": source.ID})
		return
	}
	source, err = s.connectionRegistrations.FinalizeSource(ctx, finalTx, source.ID, version)
	if err != nil {
		respondConnectionRegistrationError(ctx, w, err)
		return
	}
	if err := s.writeAudit(ctx, finalTx, audit.Event{ActorType: sess.ActorType(), ActorID: sess.ActorID(), Action: "connection_credential_source.created", Result: audit.ResultSuccess}, map[string]any{"source_id": source.ID, "version": source.Version}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := finalTx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	respondJSON(w, http.StatusCreated, toConnectionCredentialSourceJSON(source))
}

func (s *Server) listConnectionCredentialSources(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	if !rejectUnknownQuery(w, r) {
		return
	}
	var ownerFilter *connectionregistration.Owner
	if owner, ok := credentialOwner(sess); ok && owner.Type == "user" {
		ownerFilter = &owner
	}
	sources, err := s.connectionRegistrations.ListSources(ctx, s.pool, ownerFilter)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	out := make([]connectionCredentialSourceJSON, 0, len(sources))
	for _, source := range sources {
		if err := s.requireCanManageCredentialSource(ctx, sess, source.Owner.Type, source.Owner.ID.String(), source.Environment); err != nil {
			if errors.Is(err, errScopeForbidden) {
				continue
			}
			respondStoreError(ctx, w, err)
			return
		}
		out = append(out, toConnectionCredentialSourceJSON(source))
	}
	respondJSON(w, http.StatusOK, map[string]any{"credential_sources": out})
}

func (s *Server) deleteConnectionCredentialSource(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess, ok := s.session(w, r)
	if !ok {
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
	source, err := s.connectionRegistrations.GetSource(ctx, tx, id, true)
	if err != nil {
		respondConnectionRegistrationError(ctx, w, err)
		return
	}
	if err := s.requireCanManageCredentialSource(ctx, sess, source.Owner.Type, source.Owner.ID.String(), source.Environment); err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}
	if source.Status != "revoked" {
		source, err = s.connectionRegistrations.RevokeSource(ctx, tx, id)
		if err != nil {
			respondConnectionRegistrationError(ctx, w, err)
			return
		}
		if err := s.writeAudit(ctx, tx, audit.Event{ActorType: sess.ActorType(), ActorID: sess.ActorID(), Action: "connection_credential_source.revoked", Result: audit.ResultSuccess}, map[string]any{"source_id": id}); err != nil {
			respondStoreError(ctx, w, err)
			return
		}
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	status := http.StatusOK
	if source.CleanupPending {
		if s.vault == nil || s.vault.DeleteMetadata(ctx, connectionregistration.SourcePath(id)) != nil {
			status = http.StatusAccepted
		} else {
			if err := s.connectionRegistrations.ClearSourceCleanup(ctx, s.pool, id); err != nil {
				respondStoreError(ctx, w, err)
				return
			}
			source.CleanupPending = false
		}
	}
	respondJSON(w, status, toConnectionCredentialSourceJSON(source))
}

// CAS=0 makes retries unable to replace any existing canonical credential.
// A failed response is ambiguous: equality is checked only in memory.
func (s *Server) putOnboardingCredential(ctx context.Context, path string, data map[string]any) (int, error) {
	version, err := s.vault.PutCAS(ctx, path, data, 0)
	if err == nil {
		return version, nil
	}
	stored, storedVersion, readErr := s.vault.Get(ctx, path)
	if readErr == nil && storedVersion == 1 && stored["username"] == data["username"] && stored["password"] == data["password"] {
		return storedVersion, nil
	}
	return 0, errors.New("credential write could not be confirmed")
}

func respondConnectionRegistrationError(ctx context.Context, w http.ResponseWriter, err error) {
	if errors.Is(err, connectionregistration.ErrNotFound) {
		respondError(w, http.StatusNotFound, "not found")
		return
	}
	if errors.Is(err, connectionregistration.ErrConflict) {
		respondError(w, http.StatusConflict, "registration intent conflicts with the existing request or registration key")
		return
	}
	respondStoreError(ctx, w, err)
}

// A literal private destination can preserve an explicitly approved internal
// TLS configuration. Public and general DNS destinations verify the server name:
// hostname approval alone cannot fence a subsequent DNS change.
func validateCredentialSourceTransport(target connectionRegistrationTarget) error {
	tls, err := validateTLSConfig(target.TLSConfig)
	if err != nil {
		return err
	}
	if tls.Mode == "verify-full" && !tls.InsecureSkipVerify {
		return nil
	}
	// Kubernetes plaintext is permitted only with the immutable derived
	// connector profile enforced at every runtime dial, including discovered
	// broker addresses. The caller cannot select or remove this profile.
	if guard := target.derivedNetworkGuard(); guard != "" && target.NetworkGuard == guard {
		return nil
	}
	for _, endpoint := range target.Endpoints {
		host, _, err := splitEndpoint(endpoint)
		if err != nil {
			return err
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsPrivate() {
			return errors.New("credential sources for public or DNS endpoints require tls_config.mode verify-full without insecure_skip_verify")
		}
	}
	return nil
}
