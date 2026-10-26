package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/apikey"
	"github.com/ArtefactoO/grantor/internal/directory"
)

const DefaultAPIKeyIdentityFreshness = 5 * time.Minute

// APIKeyIdentityManager renews local authorization leases in bounded batches.
// Authentication reads PostgreSQL only; IdP failures do not renew a lease.
type APIKeyIdentityManager struct {
	pool      *pgxpool.Pool
	store     *apikey.Store
	provider  directory.APIIdentityProvider
	freshness time.Duration
	issuer    string
	roleFor   func(string, []string) (auth.Role, bool)
}

func NewAPIKeyIdentityManager(pool *pgxpool.Pool, store *apikey.Store, provider directory.APIIdentityProvider, freshness time.Duration) *APIKeyIdentityManager {
	if freshness <= 0 {
		freshness = DefaultAPIKeyIdentityFreshness
	}
	return &APIKeyIdentityManager{pool: pool, store: store, provider: provider, freshness: freshness}
}

func (m *APIKeyIdentityManager) SetIssuer(issuer string) { m.issuer = issuer }
func (m *APIKeyIdentityManager) SetRoleResolver(resolver func(string, []string) (auth.Role, bool)) {
	m.roleFor = resolver
}

// MaxExpiry exposes the effective issuance bound, including the fail-closed
// fallback when the configured directory cannot refresh owner roles safely.
func (m *APIKeyIdentityManager) MaxExpiry(sess auth.Session, now time.Time) time.Time {
	maximum := now.Add(apikey.MaximumLifetime)
	if m == nil || m.provider == nil || m.roleFor == nil || sess.AuthenticatedAt.IsZero() {
		if sess.ExpiresAt.Before(maximum) {
			maximum = sess.ExpiresAt
		}
	}
	return maximum
}

func (m *APIKeyIdentityManager) sessionIdentity(sess auth.Session) (issuer, username string, err error) {
	issuer = sess.Issuer
	if issuer == "" {
		issuer = m.issuer
	}
	username = sess.Username
	if username == "" {
		username = sess.Subject
	}
	if issuer == "" || sess.Subject == "" || sess.Email == "" || sess.Service || sess.APIKeyID != "" || !sess.Role.Allows(auth.RoleViewer) {
		return "", "", apikey.ErrOwnerUnavailable
	}
	if m.issuer != "" && issuer != m.issuer {
		return "", "", apikey.ErrOwnerUnavailable
	}
	return issuer, username, nil
}

func (m *APIKeyIdentityManager) ObserveSession(ctx context.Context, sess auth.Session) error {
	issuer, username, err := m.sessionIdentity(sess)
	if err != nil {
		return err
	}
	tx, err := m.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("api key identity: begin login: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `select pg_advisory_xact_lock(hashtextextended($1,0))`, "api-user:"+issuer+"\n"+sess.Subject); err != nil {
		return fmt.Errorf("api key identity: lock login: %w", err)
	}
	previous, err := m.store.GetUser(ctx, tx, issuer, sess.Subject)
	if err != nil && !errors.Is(err, apikey.ErrNotFound) {
		return err
	}
	if err == nil && !sess.AuthenticatedAt.Truncate(time.Microsecond).After(previous.AuthenticatedAt) {
		return nil
	}
	// A legacy signed cookie has no login timestamp and may seed an owner once,
	// but never rebind an existing owner or extend its original lifetime.
	loginAt := sess.AuthenticatedAt.Truncate(time.Microsecond)
	if loginAt.IsZero() {
		loginAt = time.Unix(0, 0).UTC()
	}
	u := apikey.User{Issuer: issuer, Subject: sess.Subject, Username: username, Email: sess.Email,
		Role: sess.Role, Active: true, AuthorizedUntil: sess.ExpiresAt, AuthenticatedAt: loginAt, IdentityBoundAt: loginAt}
	if m.provider != nil && m.roleFor != nil {
		identity, err := m.provider.APIIdentity(ctx, username)
		if err != nil {
			return fmt.Errorf("api key identity: verify login: %w", err)
		}
		role, allowed := m.roleFor(identity.Email, identity.Groups)
		if identity.Status != directory.StatusActive || identity.Username != username || identity.UID == "" || !allowed {
			u.Active = false
			u.Role = ""
		} else {
			u.Role = apikey.EffectiveRole(sess.Role, role)
			u.Email = identity.Email
		}
		u.DirectoryUID = identity.UID
		u.DirectoryManaged = true
		u.AuthorizedUntil = time.Now().Add(m.freshness)
	}
	if _, err := m.store.SaveLogin(ctx, tx, u); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("api key identity: commit login: %w", err)
	}
	return nil
}

func (m *APIKeyIdentityManager) SessionUser(ctx context.Context, sess auth.Session) (apikey.User, error) {
	issuer, _, err := m.sessionIdentity(sess)
	if err != nil {
		return apikey.User{}, err
	}
	u, err := m.store.GetUser(ctx, m.pool, issuer, sess.Subject)
	if errors.Is(err, apikey.ErrNotFound) || err == nil && sess.AuthenticatedAt.Truncate(time.Microsecond).After(u.AuthenticatedAt) {
		if err := m.ObserveSession(ctx, sess); err != nil {
			return apikey.User{}, err
		}
		u, err = m.store.GetUser(ctx, m.pool, issuer, sess.Subject)
	}
	if err != nil {
		return apikey.User{}, err
	}
	if u.DirectoryManaged && !u.AuthorizedUntil.After(time.Now()) && m.provider != nil && m.roleFor != nil {
		// A still-valid browser may open key settings long after login without
		// owning any key yet. Renew the same immutable identity, never rebind it.
		identity, err := m.provider.APIIdentity(ctx, u.Username)
		if err != nil {
			return apikey.User{}, fmt.Errorf("api key identity: refresh browser owner: %w", err)
		}
		if err := m.applyRefresh(ctx, u, identity); err != nil {
			return apikey.User{}, err
		}
		u, err = m.store.GetUser(ctx, m.pool, issuer, sess.Subject)
		if err != nil {
			return apikey.User{}, err
		}
	}
	// Reject pre-rebinding cookies even when their issuer/subject was reused.
	if !sess.AuthenticatedAt.IsZero() && sess.AuthenticatedAt.Before(u.IdentityBoundAt) ||
		sess.AuthenticatedAt.IsZero() && u.IdentityBoundAt.After(time.Unix(0, 0)) {
		return apikey.User{}, apikey.ErrOwnerUnavailable
	}
	return u, nil
}

func (m *APIKeyIdentityManager) Refresh(ctx context.Context) error {
	if m.provider == nil || m.roleFor == nil || m.issuer == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, m.freshness/2)
	defer cancel()
	users, err := m.store.ListManagedUsers(ctx, m.pool, m.issuer)
	if err != nil {
		return err
	}
	var failures []error
	for _, u := range users {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		identity, err := m.provider.APIIdentity(ctx, u.Username)
		if err != nil {
			failures = append(failures, fmt.Errorf("api key identity: refresh dependency: %w", err))
			continue
		}
		if err := m.applyRefresh(ctx, u, identity); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (m *APIKeyIdentityManager) applyRefresh(ctx context.Context, u apikey.User, identity directory.APIIdentity) error {
	tx, err := m.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	locked, err := m.store.LockUser(ctx, tx, u.ID)
	if err != nil {
		return err
	}
	if locked.DirectoryUID != u.DirectoryUID || !locked.AuthenticatedAt.Equal(u.AuthenticatedAt) {
		return nil
	}
	role, allowed := m.roleFor(identity.Email, identity.Groups)
	active := identity.Status == directory.StatusActive && identity.Username == u.Username && identity.UID == u.DirectoryUID && identity.UID != "" && allowed
	if !active {
		role = ""
	}
	if identity.UID != u.DirectoryUID {
		if err := m.store.RevokeUser(ctx, tx, u.ID); err != nil {
			return err
		}
	}
	email := identity.Email
	if email == "" {
		email = u.Email
	}
	if err := m.store.Refresh(ctx, tx, u, active, role, email, time.Now().Add(m.freshness)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (m *APIKeyIdentityManager) Run(ctx context.Context, interval time.Duration) {
	if m.provider == nil {
		return
	}
	if interval <= 0 || interval >= m.freshness {
		interval = m.freshness / 4
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := m.Refresh(ctx); err != nil && ctx.Err() == nil {
			slog.ErrorContext(ctx, "api key owner refresh failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
