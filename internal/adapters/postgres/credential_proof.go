package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/ArtefactoO/grantor/internal/adapter"
)

// Candidate databases come from the same target's catalog. CONNECT is not a
// prerequisite for password authentication: initial grants may wait for account
// creation. No database privilege is granted by the proof.
func (a *Adapter) credentialProofDatabases(ctx context.Context, cfg adapter.Connection, account adapter.Account) ([]string, error) {
	conn, err := a.connect(ctx, cfg, maintenanceDatabase(cfg))
	if err != nil {
		return nil, errors.New("postgres: credential verification catalog is unavailable")
	}
	defer closeQuietly(ctx, conn)
	var canLogin bool
	if err := conn.QueryRow(ctx, `select rolcanlogin and (rolvaliduntil is null or rolvaliduntil > now()) from pg_roles where rolname=$1`, account.EngineIdentity).Scan(&canLogin); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, proofAccessDenied(account.EngineIdentity)
		}
		return nil, errors.New("postgres: credential verification login lookup is unavailable")
	}
	if !canLogin {
		return nil, adapter.ErrCredentialProofAccessDenied
	}
	return credentialProofCandidateDatabases(ctx, conn, maintenanceDatabase(cfg))
}

// The same catalog lookup also serves a planned, still absent LOGIN. It does
// not infer HBA admission or require the account to hold CONNECT privileges.
func credentialProofCandidateDatabases(ctx context.Context, q rolePolicyQuerier, maintenance string) ([]string, error) {
	rows, err := q.Query(ctx, `select datname from pg_database
		where datallowconn and not datistemplate
		order by (datname=$1) desc, datname`, maintenance)
	if err != nil {
		return nil, errors.New("postgres: credential verification database lookup failed")
	}
	defer rows.Close()
	var databases []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, errors.New("postgres: credential verification database lookup failed")
		}
		databases = append(databases, name)
	}
	if rows.Err() != nil {
		return nil, errors.New("postgres: credential verification database lookup failed")
	}
	return databases, nil
}

func isProofDatabaseDenied(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && (pgErr.Code == "28000" || pgErr.Code == "42501" || pgErr.Code == "3D000")
}

func proofAccessDenied(name string) error {
	return fmt.Errorf("postgres: no database admits password authentication for role %q; check LOGIN and pg_hba.conf: %w", name, adapter.ErrCredentialProofAccessDenied)
}

// CheckCredentialProofAccess uses a random negative probe only. An actual
// password rejection (28P01) proves a password-authentication route exists;
// HBA/authorization refusals (28000) do not. No target object is modified.
func (a *Adapter) CheckCredentialProofAccess(ctx context.Context, cfg adapter.Connection, account adapter.Account) error {
	databases, err := a.credentialProofDatabases(ctx, cfg, account)
	if err != nil {
		return err
	}
	wrong, err := randomProbePassword()
	if err != nil {
		return err
	}
	defer clear(wrong)
	probe := cfg
	probe.AdminCredential = adapter.Credential{Kind: "password", Username: account.EngineIdentity, Secret: wrong}
	unsupported := false
	for _, database := range databases {
		conn, err := a.connect(ctx, probe, database)
		if err == nil {
			closeQuietly(ctx, conn)
			unsupported = true
			continue
		}
		if isAuthenticationFailure(err) {
			return nil
		}
		if isProofDatabaseDenied(err) {
			continue
		}
		return errors.New("postgres: credential verification preflight target is unavailable")
	}
	if unsupported {
		return adapter.ErrCredentialProofUnsupported
	}
	return proofAccessDenied(account.EngineIdentity)
}

// ProveCredential requires both an exact positive identity and a password
// rejection for a fresh random credential in the SAME admitted database.
func (a *Adapter) ProveCredential(ctx context.Context, cfg adapter.Connection, account adapter.Account, credential adapter.Credential) error {
	name := account.EngineIdentity
	if name == "" || len(credential.Secret) == 0 {
		return errors.New("postgres: credential verification requires identity and password")
	}
	databases, err := a.credentialProofDatabases(ctx, cfg, account)
	if err != nil {
		return err
	}
	wrong, err := randomProbePassword()
	if err != nil {
		return err
	}
	defer clear(wrong)
	probe := cfg
	probe.AdminCredential = adapter.Credential{Kind: "password", Username: name, Secret: credential.Secret}
	negative := cfg
	negative.AdminCredential = adapter.Credential{Kind: "password", Username: name, Secret: wrong}
	unsupported := false
	for _, database := range databases {
		conn, observation, err := a.connectForCredentialProof(ctx, probe, database)
		if err != nil {
			if authenticatedWithoutConnect(observation, err) {
				wrongConn, wrongErr := a.connect(ctx, negative, database)
				if wrongErr == nil {
					closeQuietly(ctx, wrongConn)
					unsupported = true
					continue
				}
				if isAuthenticationFailure(wrongErr) {
					return nil
				}
				return fmt.Errorf("postgres: negative credential probe is ambiguous: %w", adapter.ErrCredentialProofUnsupported)
			}
			if isProofDatabaseDenied(err) {
				continue
			}
			if isAuthenticationFailure(err) {
				return fmt.Errorf("postgres: password rejected for role %q: %w", name, adapter.ErrExternalIdentityConflict)
			}
			return errors.New("postgres: credential verification target is unavailable")
		}
		if !observation.passwordAuthenticated() {
			closeQuietly(ctx, conn)
			unsupported = true
			continue
		}
		var current string
		err = conn.QueryRow(ctx, `select current_user`).Scan(&current)
		closeQuietly(ctx, conn)
		if err != nil {
			return errors.New("postgres: credential verification identity is unavailable")
		}
		if current != name {
			return adapter.ErrExternalIdentityConflict
		}
		wrongConn, wrongErr := a.connect(ctx, negative, database)
		if wrongErr == nil {
			closeQuietly(ctx, wrongConn)
			unsupported = true
			continue
		}
		if !isAuthenticationFailure(wrongErr) {
			return fmt.Errorf("postgres: negative credential probe is ambiguous: %w", adapter.ErrCredentialProofUnsupported)
		}
		return nil
	}
	if unsupported {
		return adapter.ErrCredentialProofUnsupported
	}
	return proofAccessDenied(name)
}
