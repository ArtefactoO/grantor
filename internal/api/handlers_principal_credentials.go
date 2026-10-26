package api

// Предварительная подготовка общего credential принципала по окружениям.
// Окружения — объединение реестра environments и фактических connections:
// реестр позволяет подготовить credential до первого подключения. Секреты
// остаются в Vault; API возвращает лишь факт наличия.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/credentials"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
)

const auditActionPrincipalCredentialCreated = "principal.credential_created"

type principalCredentialEnvironmentJSON struct {
	Environment string `json:"environment"`
	Connections int    `json:"connections"`
	// Configured nil означает «неизвестно»: метаданные окружения не
	// прочитались, но остальные строки списка это не роняет.
	Configured *bool `json:"configured"`
}

type principalCredentialListResponse struct {
	Credentials []principalCredentialEnvironmentJSON `json:"credentials"`
}

type createPrincipalCredentialRequest struct {
	Environment string `json:"environment"`
	Mode        string `json:"mode"`
	Password    string `json:"password"`
}

func (req *createPrincipalCredentialRequest) validate() error {
	if req.Environment == "" {
		return errors.New("environment is required")
	}
	switch req.Mode {
	case "generated":
		if req.Password != "" {
			return errors.New("password must be empty in generated mode")
		}
	case "provided":
		if len(req.Password) < 12 || len(req.Password) > 256 {
			return errors.New("password length must be between 12 and 256 characters")
		}
	default:
		return errors.New(`mode must be "generated" or "provided"`)
	}
	return nil
}

// principalCredentialEnvironments возвращает окружения, видимые текущей
// сессии: объединение реестра environments и окружений connections с числом
// подключений в каждом. Registry-окружения без подключений проверяются на
// scope напрямую по имени — подключения для косвенной проверки нет.
func (s *Server) principalCredentialEnvironments(ctxReq *http.Request, sess auth.Session) ([]principalCredentialEnvironmentJSON, error) {
	ctx := ctxReq.Context()
	conns, err := s.connections.List(ctx, s.pool)
	if err != nil {
		return nil, err
	}
	conns, err = s.filterConnectionsByScope(ctx, sess, conns)
	if err != nil {
		return nil, err
	}
	counts := make(map[string]int)
	for i := range conns {
		counts[environmentOf(conns[i])]++
	}
	registry, err := s.environments.List(ctx, s.pool)
	if err != nil {
		return nil, err
	}
	for i := range registry {
		name := registry[i].Name
		if _, seen := counts[name]; seen {
			continue
		}
		switch err := s.checkConnectionScope(ctx, sess, name); {
		case err == nil:
			counts[name] = 0
		case errors.Is(err, errScopeForbidden):
			// Окружение вне scope сессии — просто не показывается.
		default:
			return nil, err
		}
	}
	envs := make([]string, 0, len(counts))
	for env := range counts {
		envs = append(envs, env)
	}
	sort.Strings(envs)
	out := make([]principalCredentialEnvironmentJSON, 0, len(envs))
	for _, env := range envs {
		out = append(out, principalCredentialEnvironmentJSON{Environment: env, Connections: counts[env]})
	}
	return out, nil
}

// fillConfigured проставляет Configured по метаданным Vault. Fail-open per
// строке: недоступность метаданных одного окружения оставляет его
// configured=null, не роняя весь список (образец — credentialcheck).
// Единственная фатальная ошибка — ErrVaultNotConfigured: без Vault ответ
// целиком не имеет смысла.
func fillConfigured(ctx context.Context, principalID uuid.UUID, items []principalCredentialEnvironmentJSON,
	exists func(context.Context, uuid.UUID, string) (bool, error)) error {
	for i := range items {
		configured, err := exists(ctx, principalID, items[i].Environment)
		if err != nil {
			if errors.Is(err, credentials.ErrVaultNotConfigured) {
				return err
			}
			slog.WarnContext(ctx, "api: inspect principal credential metadata",
				"principal_id", principalID, "environment", items[i].Environment, "error", err)
			continue
		}
		items[i].Configured = &configured
	}
	return nil
}

func credentialEnvironmentExists(items []principalCredentialEnvironmentJSON, environment string) bool {
	for i := range items {
		if items[i].Environment == environment {
			return true
		}
	}
	return false
}

func (s *Server) listPrincipalCredentials(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	principalID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	if _, err := s.principals.Get(ctx, s.pool, principalID); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	items, err := s.principalCredentialEnvironments(r, sess)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := fillConfigured(ctx, principalID, items, s.credentials.PrincipalCredentialExists); err != nil {
		respondError(w, http.StatusServiceUnavailable, "vault is not configured")
		return
	}
	respondJSON(w, http.StatusOK, principalCredentialListResponse{Credentials: items})
}

func (s *Server) createPrincipalCredential(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	principalID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req createPrincipalCredentialRequest
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
	principal, err := s.principals.Get(ctx, s.pool, principalID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if msg := principalStatusBlocks(principal.Status, true); msg != "" {
		respondError(w, http.StatusConflict, msg)
		return
	}
	envs, err := s.principalCredentialEnvironments(r, sess)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if !credentialEnvironmentExists(envs, req.Environment) {
		respondError(w, http.StatusBadRequest,
			"environment is not registered and no visible connection uses it")
		return
	}

	provided := []byte(req.Password)
	req.Password = ""
	defer clear(provided)
	generate := func() ([]byte, error) {
		if req.Mode == "provided" {
			password := make([]byte, len(provided))
			copy(password, provided)
			return password, nil
		}
		return credentials.GeneratePassword(credentials.DefaultPasswordLength)
	}
	_, created, err := s.credentials.EnsurePrincipalCredential(ctx, principalID, req.Environment, generate)
	if err != nil {
		switch {
		case errors.Is(err, credentials.ErrVaultNotConfigured):
			respondError(w, http.StatusServiceUnavailable, "vault is not configured")
		case errors.Is(err, vault.ErrNotFound):
			respondError(w, http.StatusBadGateway, "failed to create credential in vault")
		default:
			slog.ErrorContext(ctx, "api: create principal credential",
				"principal_id", principalID, "environment", req.Environment, "error", err)
			respondError(w, http.StatusBadGateway, "failed to create credential in vault")
		}
		return
	}
	if created {
		if err := s.writeAudit(ctx, s.pool, audit.Event{
			ActorType: sess.ActorType(), ActorID: sess.ActorID(),
			Action: auditActionPrincipalCredentialCreated, PrincipalID: &principalID,
			Result: audit.ResultSuccess,
		}, map[string]any{"environment": req.Environment, "mode": req.Mode}); err != nil {
			respondStoreError(ctx, w, fmt.Errorf("api: audit principal credential creation: %w", err))
			return
		}
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	respondJSON(w, status, map[string]any{
		"environment": req.Environment,
		"configured":  true,
		"created":     created,
	})
}
