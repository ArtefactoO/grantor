//go:build integration

package postgres_test

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
)

func accountCreationFixture(t *testing.T) (adapter.DesiredChange, *pgx.Conn, string) {
	t.Helper()
	dsn := targetDSN(t)
	admin := connectTarget(t.Context(), t, dsn, "")
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	var super bool
	if err := admin.QueryRow(t.Context(), `select rolsuper from pg_roles where rolname=session_user`).Scan(&super); err != nil {
		t.Fatal(err)
	}
	if !super {
		t.Skip("proof-carrying account creation requires a SUPERUSER integration target")
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
	name := "gr_creation_" + suffix
	var system string
	if err := admin.QueryRow(t.Context(), `select system_identifier::text from pg_control_system()`).Scan(&system); err != nil {
		t.Fatal(err)
	}
	cfg := targetConnection(t, dsn)
	cfg.ConfigIncarnation = "creation-test-" + suffix
	cfg.AdminCredentialIncarnation = 1
	change := adapter.DesiredChange{Kind: adapter.ChangePostgresAccountCreateV2, Connection: cfg,
		Account:               adapter.Account{Kind: "login", EngineIdentity: name},
		Credential:            &adapter.Credential{Kind: "password", Username: name, Secret: []byte("creation-fixture-" + suffix)},
		ExpectedAdminIdentity: cfg.AdminCredential.Username, ExpectedTargetIdentity: "postgres:system:" + system}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "drop role if exists "+pgx.Identifier{name}.Sanitize())
	})
	return change, admin, dsn
}

func assertCreationRoleAbsent(t *testing.T, admin *pgx.Conn, name string) {
	t.Helper()
	var exists bool
	if err := admin.QueryRow(t.Context(), `select exists (select 1 from pg_roles where rolname=$1)`, name).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("read-only or rejected creation stage created a role")
	}
}

func TestAccountCreationPreflightAndVerifyUseAdmittedDatabaseWithoutConnect(t *testing.T) {
	change, admin, dsn := accountCreationFixture(t)
	cc, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	database := change.Account.EngineIdentity + "_db"
	if _, err := admin.Exec(t.Context(), "create database "+pgx.Identifier{database}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "drop database "+pgx.Identifier{database}.Sanitize()+" with (force)")
	})
	if _, err := admin.Exec(t.Context(), "revoke connect on database "+pgx.Identifier{database}.Sanitize()+" from public"); err != nil {
		t.Fatal(err)
	}
	deny := &atomic.Bool{}
	change.Connection.Endpoints = []string{credentialGateProxy(t, net.JoinHostPort(cc.Host, strconv.Itoa(int(cc.Port))), change.Account.EngineIdentity, database, deny)}
	change.Connection.TLS.Mode = "disabled"
	ad := postgres.New()
	deny.Store(true)
	if err := ad.PreflightAccountCreation(t.Context(), change); !errors.Is(err, adapter.ErrCredentialProofAccessDenied) {
		t.Fatalf("absent-login HBA denial = %v", err)
	}
	assertCreationRoleAbsent(t, admin, change.Account.EngineIdentity)
	deny.Store(false)
	if err := ad.PreflightAccountCreation(t.Context(), change); err != nil {
		t.Fatalf("absent-login multi-database preflight = %v", err)
	}
	assertCreationRoleAbsent(t, admin, change.Account.EngineIdentity)
	proof, err := ad.CreateAccountWithProof(t.Context(), change)
	if err != nil || proof == nil || proof.RoleOID == 0 || proof.EngineIdentity != change.Account.EngineIdentity || proof.TargetIdentity != change.ExpectedTargetIdentity {
		t.Fatalf("acknowledged creation proof = %+v, %v", proof, err)
	}
	deny.Store(true)
	if err := ad.VerifyCreatedAccount(t.Context(), change, *proof); !errors.Is(err, adapter.ErrCredentialProofAccessDenied) {
		t.Fatalf("post-CREATE HBA race = %v", err)
	}
	deny.Store(false)
	for range 2 {
		if err := ad.VerifyCreatedAccount(t.Context(), change, *proof); err != nil {
			t.Fatalf("resumable proof without CONNECT = %v", err)
		}
	}
	var oid uint32
	var canConnect bool
	if err := admin.QueryRow(t.Context(), `select oid,has_database_privilege(rolname,$2,'CONNECT') from pg_roles where rolname=$1`, change.Account.EngineIdentity, database).Scan(&oid, &canConnect); err != nil {
		t.Fatal(err)
	}
	if oid != proof.RoleOID || canConnect {
		t.Fatal("verification recreated the account or granted CONNECT")
	}
	bad := change
	credential := *change.Credential
	credential.Secret = []byte("deliberately-wrong-creation-password")
	bad.Credential = &credential
	if err := ad.VerifyCreatedAccount(t.Context(), bad, *proof); !errors.Is(err, adapter.ErrExternalIdentityConflict) {
		t.Fatalf("wrong creation password = %v", err)
	}
	if err := ad.VerifyCreatedAccount(t.Context(), change, *proof); err != nil {
		t.Fatalf("verification changed the original password = %v", err)
	}
}

// For one fixture identity the gate emits only fixed authentication frames or
// changes its role incarnation before forwarding. Other identities, including
// the target administrator, always use the real target and its authority SQL.
func accountCreationProtocolProxy(t *testing.T, backend, login string, mode *atomic.Int32, beforeForward func()) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var once sync.Once
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer client.Close()
				_ = client.SetDeadline(time.Now().Add(10 * time.Second))
				var header [4]byte
				if _, err := io.ReadFull(client, header[:]); err != nil {
					return
				}
				size := binary.BigEndian.Uint32(header[:])
				if size < 8 || size > 10000 {
					return
				}
				body := make([]byte, size-4)
				if _, err := io.ReadFull(client, body); err != nil {
					return
				}
				fields := strings.Split(string(body[4:]), "\x00")
				params := map[string]string{}
				for i := 0; i+1 < len(fields); i += 2 {
					params[fields[i]] = fields[i+1]
				}
				if params["user"] == login {
					switch mode.Load() {
					case 1: // trust does not attest to any password.
						auth, _ := (&pgproto3.AuthenticationOk{}).Encode(nil)
						denied, _ := (&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28000", Message: "fixture role is absent"}).Encode(nil)
						_, _ = client.Write(append(auth, denied...))
						return
					case 2: // Bare SQLSTATE is not a password protocol proof.
						denied, _ := (&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28P01", Message: "fixture rejection"}).Encode(nil)
						_, _ = client.Write(denied)
						return
					case 3: // Transport failure must remain unavailable.
						return
					}
					if beforeForward != nil {
						once.Do(beforeForward)
					}
				}
				upstream, err := net.DialTimeout("tcp", backend, 5*time.Second)
				if err != nil {
					return
				}
				defer upstream.Close()
				_ = upstream.SetDeadline(time.Now().Add(10 * time.Second))
				if _, err := upstream.Write(append(header[:], body...)); err != nil {
					return
				}
				copied := make(chan struct{})
				go func() { _, _ = io.Copy(upstream, client); _ = upstream.Close(); close(copied) }()
				_, _ = io.Copy(client, upstream)
				_ = client.Close()
				<-copied
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); <-done; wg.Wait() })
	return ln.Addr().String()
}

func TestAccountCreationPreflightRejectsTrustBareSQLStateAndUnavailable(t *testing.T) {
	change, admin, dsn := accountCreationFixture(t)
	cc, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	mode := &atomic.Int32{}
	change.Connection.Endpoints = []string{accountCreationProtocolProxy(t, net.JoinHostPort(cc.Host, strconv.Itoa(int(cc.Port))), change.Account.EngineIdentity, mode, nil)}
	change.Connection.TLS.Mode = "disabled"
	for _, tc := range []struct {
		name string
		mode int32
		want error
	}{
		{"trust", 1, adapter.ErrCredentialProofUnsupported},
		{"bare SQLSTATE", 2, adapter.ErrCredentialProofUnsupported},
		{"transport failure", 3, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mode.Store(tc.mode)
			err := postgres.New().PreflightAccountCreation(t.Context(), change)
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("preflight = %v, want %v", err, tc.want)
			}
			if tc.want == nil && (errors.Is(err, adapter.ErrCredentialProofAccessDenied) || errors.Is(err, adapter.ErrCredentialProofUnsupported)) {
				t.Fatal("transport failure became admission failure")
			}
			assertCreationRoleAbsent(t, admin, change.Account.EngineIdentity)
		})
	}
}

func TestAccountCreationRejectsForeignRoleAndOIDReplacement(t *testing.T) {
	change, admin, _ := accountCreationFixture(t)
	ad := postgres.New()
	if err := ad.PreflightAccountCreation(t.Context(), change); err != nil {
		t.Fatal(err)
	}
	proof, err := ad.CreateAccountWithProof(t.Context(), change)
	if err != nil {
		t.Fatal(err)
	}
	if err := ad.PreflightAccountCreation(t.Context(), change); !errors.Is(err, adapter.ErrExternalIdentityConflict) {
		t.Fatalf("existing-role preflight = %v", err)
	}
	if repeated, err := ad.CreateAccountWithProof(t.Context(), change); repeated != nil || !errors.Is(err, adapter.ErrExternalIdentityConflict) {
		t.Fatalf("existing-role CREATE supplied proof = %+v, %v", repeated, err)
	}
	if _, err := admin.Exec(t.Context(), "drop role "+pgx.Identifier{change.Account.EngineIdentity}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(t.Context(), "create role "+pgx.Identifier{change.Account.EngineIdentity}.Sanitize()+" login"); err != nil {
		t.Fatal(err)
	}
	if err := ad.VerifyCreatedAccount(t.Context(), change, *proof); !errors.Is(err, adapter.ErrExternalIdentityConflict) {
		t.Fatalf("same-name replacement verification = %v", err)
	}
	var oid uint32
	if err := admin.QueryRow(t.Context(), `select oid from pg_roles where rolname=$1`, change.Account.EngineIdentity).Scan(&oid); err != nil || oid == proof.RoleOID {
		t.Fatal("OID replacement fixture did not replace the role")
	}
}

func TestAccountCreationRechecksOIDAfterPasswordProof(t *testing.T) {
	change, admin, dsn := accountCreationFixture(t)
	ad := postgres.New()
	proof, err := ad.CreateAccountWithProof(t.Context(), change)
	if err != nil {
		t.Fatal(err)
	}
	cc, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	mode := &atomic.Int32{}
	callbackErr := make(chan error, 1)
	change.Connection.Endpoints = []string{accountCreationProtocolProxy(t, net.JoinHostPort(cc.Host, strconv.Itoa(int(cc.Port))), change.Account.EngineIdentity, mode, func() {
		_, err := admin.Exec(t.Context(), "drop role "+pgx.Identifier{change.Account.EngineIdentity}.Sanitize())
		if err == nil {
			// Fixture passwords are generated from an alphanumeric UUID suffix.
			_, err = admin.Exec(t.Context(), fmt.Sprintf("create role %s login password '%s'", pgx.Identifier{change.Account.EngineIdentity}.Sanitize(), string(change.Credential.Secret)))
		}
		callbackErr <- err
	})}
	change.Connection.TLS.Mode = "disabled"
	if err := ad.VerifyCreatedAccount(t.Context(), change, *proof); !errors.Is(err, adapter.ErrExternalIdentityConflict) {
		t.Fatalf("concurrent same-password replacement verification = %v", err)
	}
	select {
	case err := <-callbackErr:
		if err != nil {
			t.Fatal("OID replacement fixture failed")
		}
	default:
		t.Fatal("verification did not exercise the concurrent OID replacement fixture")
	}
}

func TestAccountCreationTransactionFailureDoesNotSupplyProof(t *testing.T) {
	change, admin, _ := accountCreationFixture(t)
	credential := *change.Credential
	credential.Secret = []byte("transaction-fixture\x00invalid")
	change.Credential = &credential
	proof, err := postgres.New().CreateAccountWithProof(t.Context(), change)
	if err == nil || proof != nil {
		t.Fatalf("failed transaction supplied proof = %+v, error present %t", proof, err != nil)
	}
	if strings.Contains(err.Error(), string(credential.Secret)) {
		t.Fatal("account creation error retained a password")
	}
	assertCreationRoleAbsent(t, admin, change.Account.EngineIdentity)
}

func TestAccountCreationRejectsChangedLiveAuthorityAndTarget(t *testing.T) {
	change, admin, _ := accountCreationFixture(t)
	for _, tc := range []struct {
		name   string
		mutate func(*adapter.DesiredChange)
	}{
		{"target", func(c *adapter.DesiredChange) { c.ExpectedTargetIdentity = "postgres:system:1" }},
		{"admin", func(c *adapter.DesiredChange) { c.ExpectedAdminIdentity = "another_admin" }},
		{"credential incarnation", func(c *adapter.DesiredChange) { c.Connection.AdminCredentialIncarnation = 0 }},
		{"config incarnation", func(c *adapter.DesiredChange) { c.Connection.ConfigIncarnation = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := change
			tc.mutate(&candidate)
			if err := postgres.New().PreflightAccountCreation(t.Context(), candidate); !errors.Is(err, adapter.ErrTargetIdentityConflict) {
				t.Fatalf("authority preflight = %v", err)
			}
			if proof, err := postgres.New().CreateAccountWithProof(t.Context(), candidate); proof != nil || !errors.Is(err, adapter.ErrTargetIdentityConflict) {
				t.Fatalf("changed authority supplied creation proof = %+v, %v", proof, err)
			}
			assertCreationRoleAbsent(t, admin, change.Account.EngineIdentity)
		})
	}
	ad := postgres.New()
	proof, err := ad.CreateAccountWithProof(t.Context(), change)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*adapter.AccountCreationProof)
	}{
		{"OID", func(p *adapter.AccountCreationProof) { p.RoleOID++ }},
		{"identity", func(p *adapter.AccountCreationProof) { p.EngineIdentity += "_other" }},
		{"target", func(p *adapter.AccountCreationProof) { p.TargetIdentity = "postgres:system:1" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := *proof
			tc.mutate(&bad)
			if err := ad.VerifyCreatedAccount(t.Context(), change, bad); !errors.Is(err, adapter.ErrExternalIdentityConflict) {
				t.Fatalf("changed proof = %v", err)
			}
		})
	}
}
