package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/ArtefactoO/grantor/internal/adapter"
)

var _ adapter.AccountCreationProvisioner = (*Adapter)(nil)

func validateAccountCreationIntent(change adapter.DesiredChange) error {
	if change.Kind != adapter.ChangePostgresAccountCreateV2 {
		return fmt.Errorf("postgres: proof-carrying account creation kind is unsupported: %w", adapter.ErrUnsupportedChange)
	}
	if err := validateDirectProvisioningIntent(change); err != nil {
		return err
	}
	name := change.Account.EngineIdentity
	if change.Account.Kind != "login" || change.Account.AuthenticationScope != "" ||
		name == "" || len(name) > maxIdentifierBytes || !utf8.ValidString(name) || strings.ContainsRune(name, '\x00') ||
		strings.HasPrefix(strings.ToLower(name), "pg_") {
		return errors.New("postgres: account creation requires a valid non-system LOGIN identity")
	}
	if change.Credential.Kind != "password" || change.Credential.Username != name {
		return fmt.Errorf("postgres: account creation credential identity does not match LOGIN: %w", adapter.ErrExternalIdentityConflict)
	}
	if change.Resource != nil || change.RolePolicySpec != nil || change.Permission != "" ||
		change.Scope != "" || len(change.AccountPermissions) != 0 || len(change.Attributes) != 0 ||
		change.ExpectedDatabaseOID != 0 {
		return errors.New("postgres: account creation carries unrelated mutation fields")
	}
	return nil
}

func requireAbsentCreationRole(ctx context.Context, q rolePolicyQuerier, name string) error {
	var exists bool
	if err := q.QueryRow(ctx, `select exists (select 1 from pg_catalog.pg_roles where rolname=$1)`, name).Scan(&exists); err != nil {
		return errors.New("postgres: account creation role lookup is unavailable")
	}
	if exists {
		return fmt.Errorf("postgres: account creation identity already exists: %w", adapter.ErrExternalIdentityConflict)
	}
	return nil
}

// A rejection is useful for an absent role only when the server actually
// selected a supported password protocol. Bare 28P01 could come from another
// authenticator and cannot attest to HBA admission for password verification.
func classifyAccountCreationProbe(o *authenticationObservation, err error) error {
	if err == nil {
		return adapter.ErrCredentialProofUnsupported
	}
	if isAuthenticationFailure(err) {
		if o != nil && o.password && !o.authenticationOK && !o.invalid {
			return nil
		}
		return adapter.ErrCredentialProofUnsupported
	}
	if o != nil && (o.unsupported || o.authenticationOK) {
		return adapter.ErrCredentialProofUnsupported
	}
	if isProofDatabaseDenied(err) {
		return adapter.ErrCredentialProofAccessDenied
	}
	return errors.New("postgres: account creation authentication probe target is unavailable")
}

// PreflightAccountCreation probes the exact proposed identity over the real
// transport, including its TLS and dial-time routing policy. No test role,
// CONNECT grant or HBA mutation is needed. External HBA changes and membership
// based HBA rules may alter admission after CREATE; Verify remains mandatory.
func (a *Adapter) PreflightAccountCreation(ctx context.Context, change adapter.DesiredChange) error {
	if err := validateAccountCreationIntent(change); err != nil {
		return err
	}
	conn, err := a.connect(ctx, change.Connection, maintenanceDatabase(change.Connection))
	if err != nil {
		return errors.New("postgres: account creation preflight catalog is unavailable")
	}
	defer closeQuietly(ctx, conn)
	if err := requireLiveProvisioningAuthority(ctx, conn, change); err != nil {
		return err
	}
	if err := requireAbsentCreationRole(ctx, conn, change.Account.EngineIdentity); err != nil {
		return err
	}
	databases, err := credentialProofCandidateDatabases(ctx, conn, maintenanceDatabase(change.Connection))
	if err != nil {
		return err
	}
	wrong, err := randomProbePassword()
	if err != nil {
		return err
	}
	defer clear(wrong)
	probe := change.Connection
	probe.AdminCredential = adapter.Credential{Kind: "password", Username: change.Account.EngineIdentity, Secret: wrong}
	unsupported := false
	for _, database := range databases {
		attempt, observed, connectErr := a.connectForCredentialProof(ctx, probe, database)
		if attempt != nil {
			closeQuietly(ctx, attempt)
		}
		err := classifyAccountCreationProbe(observed, connectErr)
		if err == nil {
			// Catalog reads and admission probes use separate sockets. Recheck
			// authority and absence after the probes, without claiming a fence.
			if err := requireLiveProvisioningAuthority(ctx, conn, change); err != nil {
				return err
			}
			return requireAbsentCreationRole(ctx, conn, change.Account.EngineIdentity)
		}
		if errors.Is(err, adapter.ErrCredentialProofUnsupported) {
			unsupported = true
			continue
		}
		if errors.Is(err, adapter.ErrCredentialProofAccessDenied) {
			continue
		}
		return err
	}
	if unsupported {
		return adapter.ErrCredentialProofUnsupported
	}
	return proofAccessDenied(change.Account.EngineIdentity)
}

// CreateAccountWithProof returns a role OID only after an acknowledged commit.
// The caller must persist this proof before attempting password verification;
// an error after CREATE, including a lost commit response, never supplies proof.
func (a *Adapter) CreateAccountWithProof(ctx context.Context, change adapter.DesiredChange) (*adapter.AccountCreationProof, error) {
	if err := validateAccountCreationIntent(change); err != nil {
		return nil, err
	}
	conn, err := a.connect(ctx, change.Connection, maintenanceDatabase(change.Connection))
	if err != nil {
		return nil, errors.New("postgres: account creation target is unavailable")
	}
	defer closeQuietly(ctx, conn)
	tx, err := conn.Begin(ctx)
	if err != nil {
		return nil, errors.New("postgres: account creation transaction is unavailable")
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := requireLiveProvisioningAuthority(ctx, tx, change); err != nil {
		return nil, err
	}
	name := change.Account.EngineIdentity
	if err := requireAbsentCreationRole(ctx, tx, name); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, "create role "+sanitizeIdent(name)+" login"); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgCodeDuplicateObject {
			return nil, fmt.Errorf("postgres: account creation identity already exists: %w", adapter.ErrExternalIdentityConflict)
		}
		return nil, errors.New("postgres: account creation statement failed")
	}
	if err := setRolePassword(ctx, tx, name, change.Credential.Secret); err != nil {
		return nil, err
	}
	var oid uint32
	if err := tx.QueryRow(ctx, `select oid from pg_catalog.pg_roles where rolname=$1 and rolcanlogin`, name).Scan(&oid); err != nil || oid == 0 {
		return nil, errors.New("postgres: account creation OID is unavailable")
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, errors.New("postgres: account creation commit was not acknowledged; creation proof is unavailable")
	}
	return &adapter.AccountCreationProof{EngineIdentity: name, RoleOID: oid, TargetIdentity: change.ExpectedTargetIdentity}, nil
}

func requireCreatedRole(ctx context.Context, q rolePolicyQuerier, proof adapter.AccountCreationProof) error {
	var oid uint32
	var login, valid bool
	if err := q.QueryRow(ctx, `select oid,rolcanlogin,(rolvaliduntil is null or rolvaliduntil > now())
		from pg_catalog.pg_roles where rolname=$1`, proof.EngineIdentity).Scan(&oid, &login, &valid); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return adapter.ErrExternalIdentityConflict
		}
		return errors.New("postgres: created account identity lookup is unavailable")
	}
	if oid != proof.RoleOID || !login || !valid {
		return adapter.ErrExternalIdentityConflict
	}
	return nil
}

// VerifyCreatedAccount is read-only and bound to the acknowledged CREATE's
// exact role incarnation. Rechecking OID before/after the existing positive and
// negative password proof rejects a same-name role dropped and recreated.
func (a *Adapter) VerifyCreatedAccount(ctx context.Context, change adapter.DesiredChange, proof adapter.AccountCreationProof) error {
	if err := validateAccountCreationIntent(change); err != nil {
		return err
	}
	if proof.RoleOID == 0 || proof.EngineIdentity != change.Account.EngineIdentity ||
		proof.TargetIdentity != change.ExpectedTargetIdentity {
		return adapter.ErrExternalIdentityConflict
	}
	conn, err := a.connect(ctx, change.Connection, maintenanceDatabase(change.Connection))
	if err != nil {
		return errors.New("postgres: created account verification target is unavailable")
	}
	defer closeQuietly(ctx, conn)
	if err := requireLiveProvisioningAuthority(ctx, conn, change); err != nil {
		return err
	}
	if err := requireCreatedRole(ctx, conn, proof); err != nil {
		return err
	}
	if err := a.ProveCredential(ctx, change.Connection, change.Account, *change.Credential); err != nil {
		return err
	}
	if err := requireLiveProvisioningAuthority(ctx, conn, change); err != nil {
		return err
	}
	return requireCreatedRole(ctx, conn, proof)
}
