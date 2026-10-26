package api

// Service tokens (машинный доступ к API; ADR-0007, R10). Выпуск и список — по
// принципалу type=service; отзыв — по id токена. Все endpoints — admin.
//
// Инвариант секретов: plaintext-токен возвращается ровно один раз в ответе на
// выпуск и нигде не сохраняется и не логируется; в audit пишется только факт
// создания/отзыва (id токена и имя), но не сам токен и не его хеш.

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ArtefactoO/grantor/internal/auth"

	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/principals"
	"github.com/ArtefactoO/grantor/internal/core/servicetoken"
)

// Audit actions управления service tokens.
const (
	auditActionServiceTokenCreated = "service_token.created"
	auditActionServiceTokenRevoked = "service_token.revoked"
)

// serviceTokenJSON — представление токена в ответах API. Ни plaintext-токен,
// ни его хеш в модель не входят.
type serviceTokenJSON struct {
	ID          uuid.UUID  `json:"id"`
	PrincipalID uuid.UUID  `json:"principal_id"`
	Name        string     `json:"name"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	RevokedAt   *time.Time `json:"revoked_at"`
	Permissions []string   `json:"permissions"`
}

// serviceTokenListResponse — тело ответа GET /api/v1/principals/{id}/tokens.
type serviceTokenListResponse struct {
	Tokens []serviceTokenJSON `json:"tokens"`
}

// toServiceTokenJSON собирает serviceTokenJSON из доменной модели.
func toServiceTokenJSON(t servicetoken.Token) serviceTokenJSON {
	return serviceTokenJSON{
		ID:          t.ID,
		PrincipalID: t.PrincipalID,
		Name:        t.Name,
		CreatedAt:   t.CreatedAt,
		LastUsedAt:  t.LastUsedAt,
		RevokedAt:   t.RevokedAt,
		Permissions: t.Permissions,
	}
}

// createServiceTokenRequest — тело POST /api/v1/principals/{id}/tokens.
type createServiceTokenRequest struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

// createServiceToken — POST /api/v1/principals/{id}/tokens (admin): выпускает
// service token для принципала type=service. Принципал не service → 409.
// Ответ 201 несёт plaintext-токен ОДИН раз; в audit — только факт создания.
func (s *Server) createServiceToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if auth.IsTokenAuth(ctx) {
		respondError(w, http.StatusForbidden, "service token issuance requires an interactive session")
		return
	}
	principalID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req createServiceTokenRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		respondError(w, http.StatusBadRequest, "name is required")
		return
	}
	for _, permission := range req.Permissions {
		if permission != servicetoken.PermissionCreateConnections {
			respondError(w, http.StatusBadRequest, "unknown service token permission")
			return
		}
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}

	principal, err := s.principals.Get(ctx, s.pool, principalID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if principal.Type != principals.TypeService {
		respondError(w, http.StatusConflict,
			"service tokens can be issued only for service principals")
		return
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	plaintext, token, err := s.serviceTokens.Create(ctx, tx, principal.ID, req.Name, req.Permissions)
	if err != nil {
		if errors.Is(err, servicetoken.ErrPrincipalNotFound) {
			respondError(w, http.StatusNotFound, "principal not found")
			return
		}
		respondStoreError(ctx, w, err)
		return
	}

	// В audit — только факт выпуска: id токена и имя, без plaintext и хеша.
	if err := s.writeAudit(ctx, tx, audit.Event{
		ActorType:   sess.ActorType(),
		ActorID:     sess.ActorID(),
		Action:      auditActionServiceTokenCreated,
		PrincipalID: &principal.ID,
		Result:      audit.ResultSuccess,
	}, map[string]any{
		"token_id":    token.ID,
		"name":        token.Name,
		"permissions": token.Permissions,
	}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: commit create service token: %w", err))
		return
	}
	// token возвращается ровно один раз: клиент обязан сохранить его сам.
	w.Header().Set("Cache-Control", "no-store")
	respondJSON(w, http.StatusCreated, map[string]any{
		"id":           token.ID,
		"principal_id": token.PrincipalID,
		"name":         token.Name,
		"token":        plaintext,
		"permissions":  token.Permissions,
	})
}

// listServiceTokens — GET /api/v1/principals/{id}/tokens (admin): токены
// принципала без секретов (id, имя, created/last_used/revoked).
func (s *Server) listServiceTokens(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	principalID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	if _, err := s.principals.Get(ctx, s.pool, principalID); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	tokens, err := s.serviceTokens.List(ctx, s.pool, &principalID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	out := make([]serviceTokenJSON, 0, len(tokens))
	for i := range tokens {
		out = append(out, toServiceTokenJSON(tokens[i]))
	}
	respondJSON(w, http.StatusOK, serviceTokenListResponse{Tokens: out})
}

// revokeServiceToken — DELETE /api/v1/tokens/{id} (admin): отзывает токен и
// пишет audit-событие одной транзакцией. Отзыв идемпотентен; несуществующий
// id — 404.
func (s *Server) revokeServiceToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := s.serviceTokens.Revoke(ctx, tx, id); err != nil {
		if errors.Is(err, servicetoken.ErrNotFound) {
			respondError(w, http.StatusNotFound, "service token not found")
			return
		}
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.writeAudit(ctx, tx, audit.Event{
		ActorType: sess.ActorType(),
		ActorID:   sess.ActorID(),
		Action:    auditActionServiceTokenRevoked,
		Result:    audit.ResultSuccess,
	}, map[string]any{"token_id": id}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: commit revoke service token: %w", err))
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"revoked": id})
}
