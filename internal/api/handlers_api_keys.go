package api

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/apikey"
	"github.com/ArtefactoO/grantor/internal/core/audit"
)

type apiKeyJSON struct {
	ID           uuid.UUID  `json:"id"`
	UserID       uuid.UUID  `json:"user_id"`
	Name         string     `json:"name"`
	Role         auth.Role  `json:"role"`
	Environments []string   `json:"environments"`
	ExpiresAt    time.Time  `json:"expires_at"`
	CreatedAt    time.Time  `json:"created_at"`
	LastUsedAt   *time.Time `json:"last_used_at"`
	RevokedAt    *time.Time `json:"revoked_at"`
}

func toAPIKeyJSON(k apikey.Key) apiKeyJSON {
	return apiKeyJSON{ID: k.ID, UserID: k.UserID, Name: k.Name, Role: k.Role, Environments: k.Environments,
		ExpiresAt: k.ExpiresAt, CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt, RevokedAt: k.RevokedAt}
}

func (s *Server) apiKeySessionUser(w http.ResponseWriter, r *http.Request) (auth.Session, apikey.User, bool) {
	w.Header().Set("Cache-Control", "no-store")
	sess, ok := s.session(w, r)
	if !ok {
		return auth.Session{}, apikey.User{}, false
	}
	if auth.IsTokenAuth(r.Context()) || sess.Service || sess.APIKeyID != "" {
		respondError(w, http.StatusForbidden, "API keys can be managed only in an authenticated browser session")
		return auth.Session{}, apikey.User{}, false
	}
	if s.apiKeyIdentity == nil {
		respondError(w, http.StatusServiceUnavailable, "API key owner verification is unavailable")
		return auth.Session{}, apikey.User{}, false
	}
	u, err := s.apiKeyIdentity.SessionUser(r.Context(), sess)
	if err != nil {
		if errors.Is(err, apikey.ErrOwnerUnavailable) || errors.Is(err, apikey.ErrNotFound) {
			respondError(w, http.StatusForbidden, "sign in again to verify API key ownership")
		} else {
			respondStoreError(r.Context(), w, err)
		}
		return auth.Session{}, apikey.User{}, false
	}
	return sess, u, true
}

func apiKeyAllowedRoles(role auth.Role) []auth.Role {
	roles := make([]auth.Role, 0, 3)
	for _, candidate := range []auth.Role{auth.RoleViewer, auth.RoleOperator, auth.RoleAdmin} {
		if role.Allows(candidate) {
			roles = append(roles, candidate)
		}
	}
	return roles
}

func (s *Server) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	sess, user, ok := s.apiKeySessionUser(w, r)
	if !ok {
		return
	}
	keys, err := s.apiKeys.List(r.Context(), s.pool, user.ID)
	if err != nil {
		respondStoreError(r.Context(), w, err)
		return
	}
	out := make([]apiKeyJSON, 0, len(keys))
	for _, key := range keys {
		out = append(out, toAPIKeyJSON(key))
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"api_keys": out, "user_id": user.ID, "max_expires_at": s.apiKeyIdentity.MaxExpiry(sess, time.Now()),
		"allowed_roles": apiKeyAllowedRoles(apikey.EffectiveRole(user.Role, sess.Role)),
	})
}

type createAPIKeyRequest struct {
	Name         string    `json:"name"`
	Role         auth.Role `json:"role"`
	ExpiresAt    time.Time `json:"expires_at"`
	Environments *[]string `json:"environments"`
}

func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request) {
	sess, user, ok := s.apiKeySessionUser(w, r)
	if !ok {
		return
	}
	var req createAPIKeyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || utf8.RuneCountInString(name) > 128 {
		respondError(w, http.StatusBadRequest, "name must contain 1 to 128 characters")
		return
	}
	ownerRole := apikey.EffectiveRole(user.Role, sess.Role)
	if req.Role == "" {
		req.Role = ownerRole
	}
	if !ownerRole.Allows(req.Role) {
		respondError(w, http.StatusForbidden, "API key role must not exceed the owner role")
		return
	}
	now := time.Now()
	if !req.ExpiresAt.After(now) || req.ExpiresAt.After(s.apiKeyIdentity.MaxExpiry(sess, now)) {
		respondError(w, http.StatusBadRequest, "expires_at must be in the future and within the owner authorization limit")
		return
	}
	var environments []string
	if req.Environments != nil {
		if len(*req.Environments) == 0 || len(*req.Environments) > 64 {
			respondError(w, http.StatusBadRequest, "environments must contain 1 to 64 values")
			return
		}
		for _, environment := range *req.Environments {
			if environment == "" || environment == "*" || environment != strings.TrimSpace(environment) || len(environment) > 128 {
				respondError(w, http.StatusBadRequest, "environment values must be explicit nonempty names")
				return
			}
			if !slices.Contains(environments, environment) {
				environments = append(environments, environment)
			}
		}
	}
	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		respondStoreError(r.Context(), w, err)
		return
	}
	defer tx.Rollback(r.Context()) //nolint:errcheck
	locked, err := s.apiKeys.LockUser(r.Context(), tx, user.ID)
	if err != nil {
		respondStoreError(r.Context(), w, err)
		return
	}
	if !locked.Active || !locked.AuthorizedUntil.After(now) || !locked.Role.Allows(req.Role) ||
		!locked.IdentityBoundAt.Equal(user.IdentityBoundAt) {
		respondError(w, http.StatusForbidden, "API key owner authorization must be refreshed before issuance")
		return
	}
	// Owner scope is always checked again at use time. This validation prevents
	// issuance from advertising access that the current owner does not possess.
	if environments != nil && s.scopeApplies(sess) {
		allowed, all, err := s.allowedEnvironments(r.Context(), sess)
		if err != nil {
			respondStoreError(r.Context(), w, err)
			return
		}
		for _, environment := range environments {
			if !environmentAllowed(allowed, all, environment) {
				respondError(w, http.StatusForbidden, "environment is outside the owner scope")
				return
			}
		}
	}
	plaintext, key, err := s.apiKeys.Create(r.Context(), tx, apikey.CreateParams{UserID: user.ID, Name: name, Role: req.Role,
		Environments: environments, ExpiresAt: req.ExpiresAt})
	if err != nil {
		if errors.Is(err, apikey.ErrOwnerUnavailable) {
			respondError(w, http.StatusForbidden, "API key owner authorization unavailable")
		} else {
			respondStoreError(r.Context(), w, err)
		}
		return
	}
	if err := s.writeAudit(r.Context(), tx, audit.Event{ActorType: sess.ActorType(), ActorID: sess.ActorID(),
		Action: "api_key.created", Result: audit.ResultSuccess}, map[string]any{"api_key_id": key.ID, "user_id": user.ID, "name": key.Name, "role": key.Role, "expires_at": key.ExpiresAt}); err != nil {
		respondStoreError(r.Context(), w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		respondStoreError(r.Context(), w, err)
		return
	}
	respondJSON(w, http.StatusCreated, map[string]any{"api_key": toAPIKeyJSON(key), "token": plaintext})
}

func (s *Server) revokeAPIKey(w http.ResponseWriter, r *http.Request) {
	sess, user, ok := s.apiKeySessionUser(w, r)
	if !ok {
		return
	}
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		respondStoreError(r.Context(), w, err)
		return
	}
	defer tx.Rollback(r.Context()) //nolint:errcheck
	if err := s.apiKeys.Revoke(r.Context(), tx, user.ID, id); err != nil {
		if errors.Is(err, apikey.ErrNotFound) {
			respondError(w, http.StatusNotFound, "API key not found")
		} else {
			respondStoreError(r.Context(), w, err)
		}
		return
	}
	if err := s.writeAudit(r.Context(), tx, audit.Event{ActorType: sess.ActorType(), ActorID: sess.ActorID(), Action: "api_key.revoked", Result: audit.ResultSuccess},
		map[string]any{"api_key_id": id, "user_id": user.ID}); err != nil {
		respondStoreError(r.Context(), w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		respondStoreError(r.Context(), w, err)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"revoked": id})
}
