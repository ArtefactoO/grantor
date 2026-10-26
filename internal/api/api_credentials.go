package api

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/servicetoken"
)

func SessionCredentialOwner(sess auth.Session) (string, string, bool) {
	if sess.Service {
		_, err := uuid.Parse(sess.Subject)
		return "service", sess.Subject, err == nil
	}
	if sess.APIKeyID != "" {
		_, err := uuid.Parse(sess.APIUserID)
		return "user", sess.APIUserID, err == nil
	}
	return "", "", false
}

func (s *Server) canRegisterConnections(_ context.Context, sess auth.Session) (bool, error) {
	if sess.Service {
		return slices.Contains(sess.Permissions, servicetoken.PermissionCreateConnections), nil
	}
	return sess.APIKeyID != "" && sess.Role == auth.RoleAdmin, nil
}

// A delegated permission never exempts registration from environment policies.
func (s *Server) checkRegistrationScope(ctx context.Context, sess auth.Session, environment string) error {
	if strings.TrimSpace(environment) == "" {
		return errScopeForbidden
	}
	allowed, all, err := s.allowedEnvironments(ctx, sess)
	if err != nil {
		return err
	}
	if !environmentAllowed(allowed, all, environment) {
		return errScopeForbidden
	}
	return nil
}

func (s *Server) requireCanManageCredentialSource(ctx context.Context, sess auth.Session, ownerType, ownerID, environment string) error {
	if sess.Service || !sess.Role.Allows(auth.RoleAdmin) {
		return errScopeForbidden
	}
	if err := s.checkRegistrationScope(ctx, sess, environment); err != nil {
		return err
	}
	if sess.APIKeyID != "" && (ownerType != "user" || ownerID != sess.APIUserID) {
		return errScopeForbidden
	}
	if ownerType != "service" && ownerType != "user" {
		return errScopeForbidden
	}
	if _, err := uuid.Parse(ownerID); err != nil {
		return errScopeForbidden
	}
	return nil
}

// Owner availability is an issuance condition, never a barrier to revocation.
func (s *Server) requireCredentialSourceOwnerActive(ctx context.Context, ownerType, ownerID string) error {
	id, err := uuid.Parse(ownerID)
	if err != nil {
		return errScopeForbidden
	}
	var valid bool
	switch ownerType {
	case "service":
		err = s.pool.QueryRow(ctx, `select exists(select 1 from principals where id=$1 and type='service' and status='active')`, id).Scan(&valid)
	case "user":
		err = s.pool.QueryRow(ctx, `select exists(select 1 from api_users where id=$1 and active and authorized_until>now())`, id).Scan(&valid)
	default:
		return errScopeForbidden
	}
	if err != nil {
		return errors.New("credential source owner validation unavailable")
	}
	if !valid {
		return errScopeForbidden
	}
	return nil
}

// Delegated keys cannot change the policies or mint credentials determining
// their own authority. Cluster management retains the ordinary role checks.
func (s *Server) credentialScopeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := auth.FromContext(r.Context())
		if !ok || (!sess.Service && sess.APIKeyID == "") {
			next.ServeHTTP(w, r)
			return
		}
		path := r.URL.Path
		if strings.HasPrefix(path, "/api/v1/scope-policies") || strings.HasPrefix(path, "/api/v1/tokens") || strings.HasSuffix(path, "/tokens") || strings.HasPrefix(path, "/api/v1/directory") || strings.HasPrefix(path, "/api/v1/connectors") {
			respondError(w, http.StatusForbidden, "API key cannot manage control-plane authority")
			return
		}
		if r.Method != http.MethodGet && strings.HasPrefix(path, "/api/v1/principals/") {
			action := path[strings.LastIndex(path, "/")+1:]
			if action != "access" && action != "rotate" && action != "share" && action != "credential" {
				respondError(w, http.StatusForbidden, "principal lifecycle requires an interactive session")
				return
			}
		}
		if strings.HasPrefix(path, "/api/v1/connections/") && s.scopeApplies(sess) {
			id, err := uuid.Parse(r.PathValue("id"))
			if err == nil && s.respondScopeError(r.Context(), w, s.checkConnectionScopeByID(r.Context(), sess, id)) {
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) managementRole(required auth.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return s.auth.RequireRole(required)(s.credentialScopeMiddleware(next))
	}
}

// CLI clients can discover their authenticated owner without a browser cookie.
func (s *Server) getAPIIdentity(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	ownerType, ownerID, credential := SessionCredentialOwner(sess)
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
	w.Header().Set("Cache-Control", "no-store")
	respondJSON(w, http.StatusOK, map[string]any{"actor_type": sess.ActorType(), "actor_id": sess.ActorID(), "email": sess.Email, "role": sess.Role, "owner_type": ownerType, "owner_id": ownerID, "credential_authenticated": credential, "permissions": sess.Permissions, "environments": environments, "all_environments": all})
}
