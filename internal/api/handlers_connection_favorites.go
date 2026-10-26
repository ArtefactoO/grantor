package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/apikey"
	"github.com/ArtefactoO/grantor/internal/core/connectionfavorites"
	"github.com/ArtefactoO/grantor/internal/core/connections"
)

func (s *Server) favoriteOwner(w http.ResponseWriter, r *http.Request) (auth.Session, connectionfavorites.Owner, bool) {
	w.Header().Set("Cache-Control", "no-store")
	sess, ok := s.session(w, r)
	if !ok {
		return auth.Session{}, connectionfavorites.Owner{}, false
	}
	if sess.Service {
		id, err := uuid.Parse(sess.Subject)
		if err != nil || id == uuid.Nil {
			respondError(w, http.StatusForbidden, "favorite owner is unavailable")
			return auth.Session{}, connectionfavorites.Owner{}, false
		}
		return sess, connectionfavorites.Owner{ServicePrincipalID: &id}, true
	}
	var user apikey.User
	var err error
	switch {
	case sess.APIKeyID != "":
		id, parseErr := uuid.Parse(sess.APIUserID)
		if parseErr != nil || id == uuid.Nil {
			respondError(w, http.StatusForbidden, "favorite owner is unavailable")
			return auth.Session{}, connectionfavorites.Owner{}, false
		}
		user, err = s.apiKeys.GetUserByID(r.Context(), s.pool, id)
	case s.apiKeyIdentity != nil:
		user, err = s.apiKeyIdentity.SessionUser(r.Context(), sess)
	default:
		respondError(w, http.StatusServiceUnavailable, "favorite owner verification is unavailable")
		return auth.Session{}, connectionfavorites.Owner{}, false
	}
	if err != nil {
		if errors.Is(err, apikey.ErrOwnerUnavailable) || errors.Is(err, apikey.ErrNotFound) {
			respondError(w, http.StatusForbidden, "sign in again to verify favorite ownership")
		} else {
			respondStoreError(r.Context(), w, err)
		}
		return auth.Session{}, connectionfavorites.Owner{}, false
	}
	if !user.Active || !user.AuthorizedUntil.After(time.Now()) {
		respondError(w, http.StatusForbidden, "favorite owner is unavailable")
		return auth.Session{}, connectionfavorites.Owner{}, false
	}
	return sess, connectionfavorites.Owner{UserID: &user.ID, UserIdentityBoundAt: &user.IdentityBoundAt}, true
}

func (s *Server) listFavoriteConnections(w http.ResponseWriter, r *http.Request) {
	sess, owner, ok := s.favoriteOwner(w, r)
	if !ok {
		return
	}
	var environments []string
	all := true
	if s.scopeApplies(sess) {
		var err error
		environments, all, err = s.allowedEnvironments(r.Context(), sess)
		if err != nil {
			respondStoreError(r.Context(), w, err)
			return
		}
	}
	ids, err := connectionfavorites.NewStore().List(r.Context(), s.pool, owner, environments, all)
	if err != nil {
		respondStoreError(r.Context(), w, err)
		return
	}
	respondJSON(w, http.StatusOK, struct {
		ConnectionIDs []uuid.UUID `json:"connection_ids"`
	}{ConnectionIDs: ids})
}

func (s *Server) setFavoriteConnection(w http.ResponseWriter, r *http.Request) {
	sess, owner, ok := s.favoriteOwner(w, r)
	if !ok {
		return
	}
	id, ok := pathUUID(w, r, "id")
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
	// Keep environment changes and deletion from racing the scope decision.
	var environment string
	err = tx.QueryRow(ctx, `select environment from connections where id=$1 for share`, id).Scan(&environment)
	if errors.Is(err, pgx.ErrNoRows) {
		err = connections.ErrNotFound
	}
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if s.respondScopeError(ctx, w, s.checkConnectionScope(ctx, sess, environment)) {
		return
	}
	if err := connectionfavorites.NewStore().Set(ctx, tx, owner, id, r.Method == http.MethodPut); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
