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

// The proxy models database-specific HBA rejection for one fixture login;
// admitted traffic still uses real PostgreSQL SCRAM and catalog queries. It
// never changes the shared test server's HBA or any other login's routing.
func credentialGateProxy(t *testing.T, backend, login, allowedDB string, denyAll *atomic.Bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				header := make([]byte, 4)
				if _, err := io.ReadFull(conn, header); err != nil {
					return
				}
				n := binary.BigEndian.Uint32(header)
				if n < 8 || n > 10000 {
					return
				}
				body := make([]byte, n-4)
				if _, err := io.ReadFull(conn, body); err != nil {
					return
				}
				fields := strings.Split(string(body[4:]), "\x00")
				params := map[string]string{}
				for i := 0; i+1 < len(fields); i += 2 {
					params[fields[i]] = fields[i+1]
				}
				if params["user"] == login && (denyAll.Load() || params["database"] != allowedDB) {
					out, _ := (&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28000", Message: "no pg_hba.conf entry for fixture login and database"}).Encode(nil)
					_, _ = conn.Write(out)
					return
				}
				upstream, err := net.DialTimeout("tcp", backend, 5*time.Second)
				if err != nil {
					return
				}
				defer upstream.Close()
				_ = upstream.SetDeadline(time.Now().Add(10 * time.Second))
				if _, err := upstream.Write(append(header, body...)); err != nil {
					return
				}
				copied := make(chan struct{})
				go func() { _, _ = io.Copy(upstream, conn); _ = upstream.Close(); close(copied) }()
				_, _ = io.Copy(conn, upstream)
				_ = conn.Close()
				<-copied
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); <-done; wg.Wait() })
	return ln.Addr().String()
}

func TestCredentialProofUsesAnAdmittedDatabaseWithoutChangingPassword(t *testing.T) {
	dsn := targetDSN(t)
	cc, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	admin := connectTarget(ctx, t, dsn, cc.Database)
	defer admin.Close(ctx)
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
	login, database, password := "gr_proof_"+suffix, "gr_proof_db_"+suffix, "test-proof-"+suffix
	if _, err := admin.Exec(ctx, fmt.Sprintf(`create role %s login password '%s'`, login, password)); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `create database `+database); err != nil {
		t.Fatal(err)
	}
	// The account has just been created: its requested role grants (including
	// CONNECT) are still waiting for successful credential verification.
	if _, err := admin.Exec(ctx, `revoke connect on database `+database+` from public`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = admin.Exec(ctx, `drop database `+database+` with (force)`)
		_, _ = admin.Exec(ctx, `drop role `+login)
	}()
	denyAll := &atomic.Bool{}
	endpoint := credentialGateProxy(t, net.JoinHostPort(cc.Host, strconv.Itoa(int(cc.Port))), login, database, denyAll)
	cfg := adapter.Connection{Engine: postgres.Engine, Endpoints: []string{endpoint}, TLS: adapter.TLSConfig{Mode: "disabled"},
		AdminCredential: adapter.Credential{Kind: "password", Username: cc.User, Secret: []byte(cc.Password)}, Attributes: map[string]any{"database": cc.Database}}
	account := adapter.Account{Kind: "login", EngineIdentity: login}
	cred := adapter.Credential{Kind: "password", Username: login, Secret: []byte(password)}
	a := postgres.New()
	if err := a.CheckCredentialProofAccess(ctx, cfg, account); err != nil {
		t.Fatalf("preflight across HBA-denied maintenance: %v", err)
	}
	if err := a.ProveCredential(ctx, cfg, account, cred); err != nil {
		t.Fatalf("positive proof in admitted database: %v", err)
	}
	var canConnect bool
	if err := admin.QueryRow(ctx, `select has_database_privilege($1,$2,'CONNECT')`, login, database).Scan(&canConnect); err != nil || canConnect {
		t.Fatalf("proof changed CONNECT or fixture is invalid: %v %v", canConnect, err)
	}
	bad := cred
	bad.Secret = []byte("wrong-password")
	if err := a.ProveCredential(ctx, cfg, account, bad); !errors.Is(err, adapter.ErrExternalIdentityConflict) {
		t.Fatalf("wrong password: %v", err)
	}
	denyAll.Store(true)
	if err := a.CheckCredentialProofAccess(ctx, cfg, account); !errors.Is(err, adapter.ErrCredentialProofAccessDenied) {
		t.Fatalf("HBA was not distinguished: %v", err)
	}
	if err := a.ProveCredential(ctx, cfg, account, cred); !errors.Is(err, adapter.ErrCredentialProofAccessDenied) {
		t.Fatalf("HBA became wrong password: %v", err)
	}
	// Neither positive/negative proof nor denied preflight changed the password.
	denyAll.Store(false)
	if err := a.ProveCredential(ctx, cfg, account, cred); err != nil {
		t.Fatalf("original password no longer works: %v", err)
	}
	// The subsequent, separately authorized grant can now finish the flow.
	if _, err := admin.Exec(ctx, `grant connect on database `+database+` to `+login); err != nil {
		t.Fatal(err)
	}
	if err := a.ProveCredential(ctx, cfg, account, cred); err != nil {
		t.Fatalf("proof after CONNECT grant: %v", err)
	}
}
