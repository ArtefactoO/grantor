package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/policy"
)

// Audit actions управления scope policies.
const (
	auditActionScopePolicyCreated = "scope_policy.created"
	auditActionScopePolicyDeleted = "scope_policy.deleted"
)

// scopePolicyJSON — представление scope policy в ответах API.
type scopePolicyJSON struct {
	ID          uuid.UUID `json:"id"`
	SubjectKind string    `json:"subject_kind"`
	Subject     string    `json:"subject"`
	Environment string    `json:"environment"`
	CreatedAt   time.Time `json:"created_at"`
}

// scopePolicyListResponse — тело ответа GET /api/v1/scope-policies.
type scopePolicyListResponse struct {
	Policies []scopePolicyJSON `json:"policies"`
}

// toScopePolicyJSON собирает scopePolicyJSON из доменной модели.
func toScopePolicyJSON(p policy.ScopePolicy) scopePolicyJSON {
	return scopePolicyJSON{
		ID:          p.ID,
		SubjectKind: p.SubjectKind,
		Subject:     p.Subject,
		Environment: p.Environment,
		CreatedAt:   p.CreatedAt,
	}
}

// listScopePolicies — GET /api/v1/scope-policies (admin): все политики.
func (s *Server) listScopePolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	items, err := s.policy.List(ctx, s.pool)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	out := make([]scopePolicyJSON, 0, len(items))
	for i := range items {
		out = append(out, toScopePolicyJSON(items[i]))
	}
	respondJSON(w, http.StatusOK, scopePolicyListResponse{Policies: out})
}

// createScopePolicyRequest — тело POST /api/v1/scope-policies.
type createScopePolicyRequest struct {
	SubjectKind string `json:"subject_kind"`
	Subject     string `json:"subject"`
	Environment string `json:"environment"`
}

// validate проверяет тело создания политики. Для subject_kind='principal'
// subject обязан быть валидным uuid; для 'role' — непустой строкой (обычно
// "operator": scope-политики имеют смысл только для operator).
func (req *createScopePolicyRequest) validate() error {
	if !policy.ValidSubjectKind(req.SubjectKind) {
		return fmt.Errorf("subject_kind must be %q or %q", policy.SubjectRole, policy.SubjectPrincipal)
	}
	req.Subject = strings.TrimSpace(req.Subject)
	if req.Subject == "" {
		return errors.New("subject is required")
	}
	if req.SubjectKind == policy.SubjectPrincipal {
		if _, err := uuid.Parse(req.Subject); err != nil {
			return errors.New("subject must be a principal uuid for subject_kind=principal")
		}
	}
	req.Environment = strings.TrimSpace(req.Environment)
	if req.Environment == "" {
		return errors.New("environment is required")
	}
	return nil
}

// createScopePolicy — POST /api/v1/scope-policies (admin): создаёт политику
// и audit-событие одной транзакцией. Для subject_kind='principal' проверяется
// существование принципала (404, если его нет).
func (s *Server) createScopePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req createScopePolicyRequest
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

	if req.SubjectKind == policy.SubjectPrincipal {
		principalID, err := uuid.Parse(req.Subject)
		if err != nil {
			respondError(w, http.StatusBadRequest, "subject must be a principal uuid")
			return
		}
		if _, err := s.principals.Get(ctx, s.pool, principalID); err != nil {
			respondStoreError(ctx, w, err)
			return
		}
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	created, err := s.policy.Create(ctx, tx, policy.CreateParams{
		SubjectKind: req.SubjectKind,
		Subject:     req.Subject,
		Environment: req.Environment,
	})
	if err != nil {
		if errors.Is(err, policy.ErrAlreadyExists) {
			respondError(w, http.StatusConflict, "scope policy already exists")
			return
		}
		respondStoreError(ctx, w, err)
		return
	}

	if err := s.writeAudit(ctx, tx, audit.Event{
		ActorType: sess.ActorType(),
		ActorID:   sess.ActorID(),
		Action:    auditActionScopePolicyCreated,
		Result:    audit.ResultSuccess,
	}, map[string]any{
		"subject_kind": created.SubjectKind,
		"subject":      created.Subject,
		"environment":  created.Environment,
	}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: commit create scope policy: %w", err))
		return
	}
	respondJSON(w, http.StatusCreated, toScopePolicyJSON(created))
}

// deleteScopePolicy — DELETE /api/v1/scope-policies/{id} (admin): удаляет
// политику и пишет audit-событие одной транзакцией.
func (s *Server) deleteScopePolicy(w http.ResponseWriter, r *http.Request) {
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

	if err := s.policy.Delete(ctx, tx, id); err != nil {
		if errors.Is(err, policy.ErrNotFound) {
			respondError(w, http.StatusNotFound, "scope policy not found")
			return
		}
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.writeAudit(ctx, tx, audit.Event{
		ActorType: sess.ActorType(),
		ActorID:   sess.ActorID(),
		Action:    auditActionScopePolicyDeleted,
		Result:    audit.ResultSuccess,
	}, map[string]any{"scope_policy_id": id}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: commit delete scope policy: %w", err))
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"deleted": id})
}
