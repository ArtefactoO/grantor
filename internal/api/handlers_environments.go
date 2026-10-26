package api

// Реестр окружений. Окружение можно завести до первого подключения — чтобы
// заранее подготовить env-credential принципала; списки окружений в API
// строятся объединением реестра и фактических connections.

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/environments"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
)

const auditActionEnvironmentCreated = "environment.created"

type environmentJSON struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type environmentListResponse struct {
	Environments []environmentJSON `json:"environments"`
}

type createEnvironmentRequest struct {
	Name string `json:"name"`
}

// validate нормализует имя и проверяет, что оно пригодно как сегмент
// Vault-пути principals/<id>/environments/<env>/credential.
func (req *createEnvironmentRequest) validate() error {
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		return errors.New("name is required")
	}
	if err := vault.ValidateID(req.Name); err != nil {
		return errors.New(`name must not contain "/"`)
	}
	return nil
}

// listEnvironments — GET /api/v1/environments (viewer): реестр окружений.
func (s *Server) listEnvironments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !rejectUnknownQuery(w, r) {
		return
	}
	items, err := s.environments.List(ctx, s.pool)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	out := make([]environmentJSON, 0, len(items))
	for i := range items {
		out = append(out, environmentJSON{Name: items[i].Name, CreatedAt: items[i].CreatedAt})
	}
	respondJSON(w, http.StatusOK, environmentListResponse{Environments: out})
}

// createEnvironment — POST /api/v1/environments (admin): добавляет окружение
// в реестр и пишет audit-событие одной транзакцией.
func (s *Server) createEnvironment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req createEnvironmentRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := req.validate(); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
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

	created, err := s.environments.Create(ctx, tx, req.Name)
	if err != nil {
		if errors.Is(err, environments.ErrAlreadyExists) {
			respondError(w, http.StatusConflict, "environment already exists")
			return
		}
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.writeAudit(ctx, tx, audit.Event{
		ActorType: sess.ActorType(),
		ActorID:   sess.ActorID(),
		Action:    auditActionEnvironmentCreated,
		Result:    audit.ResultSuccess,
	}, map[string]any{"environment": created.Name}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	respondJSON(w, http.StatusCreated, environmentJSON{Name: created.Name, CreatedAt: created.CreatedAt})
}
