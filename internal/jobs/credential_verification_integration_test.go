//go:build integration

package jobs_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/connector/gateway"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/credentials"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/principals"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

type verificationHookDispatcher struct {
	gateway     *gateway.Server
	after       func() error
	calls       int
	unsupported bool
}

func (d *verificationHookDispatcher) ActiveConnectorSupports(capability adapter.Capability) bool {
	return !d.unsupported && d.gateway.ActiveConnectorSupports(capability)
}

func (d *verificationHookDispatcher) Dispatch(ctx context.Context, job connector.Job, creds connector.JobCredentials) (connector.JobResult, error) {
	d.calls++
	if job.Kind != connector.JobProveCredential || creds.Account == nil || bytes.Contains(job.Payload, creds.Account.Secret) {
		return connector.JobResult{}, errors.New("verification crossed its read-only credential boundary")
	}
	result, err := d.gateway.Dispatch(ctx, job, creds)
	if err == nil && result.Status == connector.JobSuccess && d.after != nil {
		err = d.after()
	}
	return result, err
}

type credentialVerificationFixture struct {
	pool       *pgxpool.Pool
	vault      *vault.Client
	service    *credentials.Service
	admin      *pgx.Conn
	connection connections.Connection
	account    inventory.Account
	op         operations.Operation
	payload    jobs.CredentialVerifyPayload
	executor   *jobs.MainExecutor
	dispatcher *verificationHookDispatcher
	password   string
	canonical  string
	group      string
	database   string
	dsn        string
	roleState  string
}

func newCredentialVerificationFixture(t *testing.T, mode, scenario string) *credentialVerificationFixture {
	t.Helper()
	dsn := os.Getenv("GRANTOR_TEST_TARGET_PG_DSN")
	if dsn == "" {
		t.Skip("GRANTOR_TEST_TARGET_PG_DSN is not set")
	}
	f := &credentialVerificationFixture{pool: pgtest.Pool(t), vault: newTestVaultClient(t), dsn: dsn}
	f.service = credentials.NewService(f.vault, nil)
	cc, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	f.admin = connectMutTarget(t.Context(), t, dsn)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = f.admin.Close(ctx)
	})
	registerPostgresOnce.Do(func() { adapter.Register(postgres.Engine, func() adapter.Adapter { return postgres.New() }) })
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	login := "gr_verify_" + suffix
	f.group, f.database = "gr_verify_group_"+suffix, "gr_verify_db_"+suffix
	f.password = "fixture-current-" + suffix
	f.canonical = "fixture-stale-" + suffix
	if scenario == "verify" || scenario == "shared_verify" {
		f.canonical = f.password
	}
	for _, sql := range []string{
		fmt.Sprintf(`create role %s login password '%s'`, login, f.password),
		`create role ` + f.group + ` nologin`,
		`grant ` + f.group + ` to ` + login,
		`create database ` + f.database + ` owner ` + login,
	} {
		if _, err := f.admin.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, query := range []string{`drop database if exists ` + f.database + ` with (force)`, `drop role if exists ` + login, `drop role if exists ` + f.group} {
			if _, err := f.admin.Exec(ctx, query); err != nil {
				t.Errorf("clean credential worker target fixture: %v", err)
			}
		}
	})
	f.roleState = f.targetState(t)
	adminPath := "tests/credential-verification/" + suffix + "/admin"
	if _, err := f.vault.Put(t.Context(), adminPath, map[string]any{"username": cc.User, "password": cc.Password}); err != nil {
		t.Fatal("could not stage fixture admin")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := f.vault.DeleteMetadata(ctx, adminPath); err != nil {
			t.Error("clean worker admin secret failed")
		}
	})
	discoveryConfig, _ := json.Marshal(map[string]string{"database": cc.Database})
	f.connection, err = connections.NewStore().Create(t.Context(), f.pool, connections.CreateParams{DisplayName: "verify-" + suffix, Engine: "postgres", Environment: "itest",
		Endpoints: []string{fmt.Sprintf("%s:%d", cc.Host, cc.Port)}, TLSConfig: json.RawMessage(`{"mode":"disabled"}`), ExecutionMode: mode,
		DiscoveryConfig: discoveryConfig, AdminCredentialMode: "existing_vault_ref", VaultAdminPath: adminPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := f.pool.Exec(ctx, `delete from operations where connection_id=$1`, f.connection.ID); err != nil {
			t.Errorf("clean worker fixture operations: %v", err)
		}
		if _, err := f.pool.Exec(ctx, `delete from connections where id=$1`, f.connection.ID); err != nil {
			t.Errorf("clean worker fixture connection: %v", err)
		}
	})
	var systemID string
	if err := f.admin.QueryRow(t.Context(), `select system_identifier::text from pg_control_system()`).Scan(&systemID); err != nil {
		t.Fatal(err)
	}
	topology, _ := json.Marshal(map[string]any{"system_identifier": systemID})
	capabilities, _ := json.Marshal(postgres.New().Manifest().CapabilityNames())
	if _, err := f.pool.Exec(t.Context(), `update connections set status='active',topology=$2,capabilities=$3 where id=$1`, f.connection.ID, topology, capabilities); err != nil {
		t.Fatal(err)
	}
	f.connection, err = connections.NewStore().Get(t.Context(), f.pool, f.connection.ID)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := principals.NewStore().Create(t.Context(), f.pool, principals.CreateParams{Type: principals.TypeHuman, DisplayName: "verify-principal-" + suffix})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := f.pool.Exec(ctx, `delete from principals where id=$1`, principal.ID); err != nil {
			t.Errorf("clean worker fixture principal: %v", err)
		}
	})
	f.account, err = inventory.NewStore().CreateManagedAccount(t.Context(), f.pool, inventory.CreateManagedAccountParams{ConnectionID: f.connection.ID, EngineIdentity: login, PrincipalID: &principal.ID, CredentialMode: "provided"})
	if err != nil {
		t.Fatal(err)
	}
	path := "accounts/" + f.account.ID.String() + "/credential"
	if scenario == "shared_verify" || scenario == "shared_reconcile" {
		path = "principals/" + principal.ID.String() + "/environments/itest/credential"
	}
	if err := inventory.NewStore().SetAccountVaultPath(t.Context(), f.pool, f.account.ID, path); err != nil {
		t.Fatal(err)
	}
	canonicalData := map[string]any{"password": f.canonical}
	if scenario != "shared_verify" && scenario != "shared_reconcile" {
		canonicalData["username"] = login
	}
	version, err := f.vault.Put(t.Context(), path, canonicalData)
	if err != nil {
		t.Fatal("could not stage fixture canonical credential")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := f.vault.DeleteMetadata(ctx, path); err != nil {
			t.Error("clean worker canonical secret failed")
		}
	})
	if scenario == "absent" {
		if err := f.vault.DeleteMetadata(t.Context(), path); err != nil {
			t.Fatal(err)
		}
		version = 0
	}
	if scenario == "destroyed" {
		if err := f.vault.DestroyVersions(t.Context(), path, []int{version}); err != nil {
			t.Fatal(err)
		}
	}
	f.account, err = inventory.NewStore().ReserveAccountLifecycle(t.Context(), f.pool, f.account.ID, inventory.AccountActive)
	if err != nil {
		t.Fatal(err)
	}
	f.payload = jobs.CredentialVerifyPayload{AccountID: f.account.ID, RequestID: uuid.New(), Status: inventory.AccountActive, LifecycleVersion: f.account.LifecycleVersion,
		CanonicalVersion: version, Reconcile: scenario != "verify" && scenario != "shared_verify" && scenario != "verify_wrong_canonical", ConfigIncarnation: connections.ConfigIncarnation(f.connection),
		TargetIdentity: connections.TargetIdentity(f.connection), EngineIdentity: login, AuthenticationScope: f.account.AuthenticationScope, CredentialPath: path, PrincipalID: principal.ID}
	opID := uuid.New()
	if f.payload.Reconcile {
		candidate := f.password
		if scenario == "wrong_password" {
			candidate = "fixture-wrong-" + suffix
		}
		f.payload.ProofVersion, err = f.service.PutVerificationProof(t.Context(), f.account.ID, opID, login, []byte(candidate))
		if err != nil {
			t.Fatal("could not stage verification candidate")
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := f.service.DeleteVerificationProof(ctx, f.account.ID, opID); err != nil {
				t.Error("clean worker verification proof failed")
			}
		})
	}
	raw, _ := json.Marshal(f.payload)
	f.op, _, err = operations.NewStore().Create(t.Context(), f.pool, operations.CreateParams{ID: &opID, Kind: jobs.KindCredentialVerify, ConnectionID: &f.connection.ID, AccountID: &f.account.ID, Payload: raw, ActorType: "test", ActorID: t.Name()})
	if err != nil {
		t.Fatal(err)
	}
	f.executor = jobs.NewMainExecutor(jobs.DiscoveryDeps{Pool: f.pool, Connections: connections.NewStore(), Inventory: inventory.NewStore(), Audit: audit.NewWriter(), Vault: f.vault}).WithMutations(jobs.MutationDeps{Credentials: f.service})
	if mode == connections.ExecutionModeConnector {
		f.dispatcher = &verificationHookDispatcher{gateway: startAdoptProofConnector(t)}
		f.executor.WithConnector(jobs.ConnectorDeps{Dispatcher: f.dispatcher})
	}
	return f
}

func (f *credentialVerificationFixture) targetState(t *testing.T) string {
	t.Helper()
	var state string
	err := f.admin.QueryRow(t.Context(), `select json_build_object('password',r.rolpassword,'login',r.rolcanlogin,'super',r.rolsuper,
		'owner',d.datdba,'membership',exists(select 1 from pg_auth_members m join pg_roles g on g.oid=m.roleid where g.rolname=$2 and m.member=r.oid))::text
		from pg_authid r join pg_database d on d.datname=$1 where r.oid=d.datdba`, f.database, f.group).Scan(&state)
	if err != nil {
		t.Fatal("could not observe fixture role invariants")
	}
	return state
}

func (f *credentialVerificationFixture) assertPreserved(t *testing.T) {
	t.Helper()
	if f.targetState(t) != f.roleState {
		t.Fatal("verification changed target password, role flags, membership or database owner")
	}
	if err := targetLogin(t.Context(), t, f.dsn, f.account.EngineIdentity, f.password); err != nil {
		t.Fatal("original target login stopped working")
	}
	a, err := inventory.NewStore().GetAccount(t.Context(), f.pool, f.account.ID)
	if err != nil {
		t.Fatal(err)
	}
	if a.Ownership != f.account.Ownership || a.VaultPath != f.account.VaultPath || a.EngineIdentity != f.account.EngineIdentity || a.PrincipalID == nil || *a.PrincipalID != *f.account.PrincipalID {
		t.Fatal("verification changed account identity, ownership, principal or credential path")
	}
}

func TestCredentialVerificationRealPostgresVaultDirectAndConnector(t *testing.T) {
	for _, mode := range []string{connections.ExecutionModeDirect, connections.ExecutionModeConnector} {
		for _, scenario := range []string{"reconcile", "absent", "destroyed", "wrong_password", "verify", "verify_wrong_canonical", "shared_verify", "shared_reconcile"} {
			t.Run(mode+"/"+scenario, func(t *testing.T) {
				f := newCredentialVerificationFixture(t, mode, scenario)
				err := f.executor.Execute(t.Context(), f.op)
				wantSuccess := scenario != "wrong_password" && scenario != "shared_reconcile" && scenario != "verify_wrong_canonical"
				if (err == nil) != wantSuccess {
					t.Fatalf("unexpected verification result: %v", err)
				}
				if err != nil && (strings.Contains(err.Error(), f.password) || strings.Contains(err.Error(), f.canonical)) {
					t.Fatal("credential leaked in error")
				}
				f.assertPreserved(t)
				d, version, getErr := f.vault.Get(t.Context(), f.account.VaultPath)
				if getErr != nil {
					t.Fatal("canonical credential unavailable")
				}
				wantVersion, wantPassword := 1, f.canonical
				if f.payload.Reconcile && wantSuccess {
					wantVersion, wantPassword = f.payload.CanonicalVersion+1, f.password
				}
				if version != wantVersion || d["password"] != wantPassword {
					t.Fatal("canonical changed outside the successful reconcile CAS")
				}
				if f.payload.Reconcile {
					if _, _, err := f.service.GetVerificationProof(t.Context(), f.account.ID, f.op.ID, 1); err == nil {
						t.Fatal("finished operation retained its staged secret")
					}
				}
				if wantSuccess {
					if err := f.executor.Execute(t.Context(), f.op); err != nil {
						t.Fatalf("job acknowledgement retry failed: %v", err)
					}
					if _, err := f.pool.Exec(t.Context(), `update accounts set status='disabled',lifecycle_version=lifecycle_version+1 where id=$1`, f.account.ID); err != nil {
						t.Fatal(err)
					}
					if err := f.executor.Execute(t.Context(), f.op); err != nil {
						t.Fatalf("durable success receipt was lost after later lifecycle change: %v", err)
					}
					events, err := audit.NewWriter().List(t.Context(), f.pool, audit.Filter{OperationID: &f.op.ID, Actions: []string{"credential.verified"}}, 10, 0)
					if err != nil || len(events) != 1 {
						t.Fatal("job retry duplicated or lost success receipt")
					}
					artifact := f.executor.TakeOperationArtifacts(f.op.ID)
					if bytes.Contains(artifact.Result, []byte(f.password)) || bytes.Contains(events[0].Metadata, []byte(f.password)) || bytes.Contains(f.op.Payload, []byte(f.password)) {
						t.Fatal("credential crossed persisted operation/audit boundary")
					}
					if f.dispatcher != nil && f.dispatcher.calls != 1 {
						t.Fatal("durable receipt retry re-contacted target")
					}
				}
			})
		}
	}
}

func TestCredentialVerificationRaceAndConnectorAdmission(t *testing.T) {
	for _, scenario := range []string{"canonical_race", "lifecycle_race", "principal_race", "config_race", "missing_connector_marker"} {
		t.Run(scenario, func(t *testing.T) {
			f := newCredentialVerificationFixture(t, connections.ExecutionModeConnector, "reconcile")
			f.dispatcher.after = func() error {
				switch scenario {
				case "canonical_race":
					_, err := f.vault.Put(t.Context(), f.account.VaultPath, map[string]any{"username": f.account.EngineIdentity, "password": f.password, "verification_operation_id": uuid.NewString()})
					return err
				case "lifecycle_race":
					_, err := f.pool.Exec(t.Context(), `update accounts set lifecycle_version=lifecycle_version+1 where id=$1`, f.account.ID)
					return err
				case "principal_race":
					_, err := f.pool.Exec(t.Context(), `update accounts set principal_id=null where id=$1`, f.account.ID)
					return err
				case "config_race":
					_, err := f.pool.Exec(t.Context(), `update connections set endpoints='["foreign:5432"]' where id=$1`, f.connection.ID)
					return err
				}
				return nil
			}
			if scenario == "missing_connector_marker" {
				f.dispatcher.unsupported = true
			}
			if err := f.executor.Execute(t.Context(), f.op); err == nil {
				t.Fatal("race or incompatible connector was accepted")
			}
			if f.targetState(t) != f.roleState {
				t.Fatal("failed verification changed target")
			}
			d, version, err := f.vault.Get(t.Context(), f.account.VaultPath)
			if err != nil {
				t.Fatal("canonical unavailable")
			}
			if scenario == "canonical_race" {
				if version != 2 || d["password"] != f.password || d["verification_operation_id"] == f.op.ID.String() {
					t.Fatal("CAS overwrote or adopted a foreign operation's same-value write")
				}
			} else if version != 1 || d["password"] != f.canonical {
				t.Fatal("failed guards changed canonical")
			}
			events, err := audit.NewWriter().List(t.Context(), f.pool, audit.Filter{OperationID: &f.op.ID, Actions: []string{"credential.verified"}}, 10, 0)
			if err != nil || len(events) != 0 {
				t.Fatal("failed proof emitted a success receipt")
			}
			_, _, proofErr := f.service.GetVerificationProof(t.Context(), f.account.ID, f.op.ID, 1)
			if scenario == "missing_connector_marker" {
				if f.dispatcher.calls != 0 || proofErr != nil {
					t.Fatal("connector admission sent credentials or discarded retry proof")
				}
			} else if proofErr == nil {
				t.Fatal("terminal race retained staged secret")
			}
		})
	}
}

func TestCredentialVerificationRetriesCASAfterAuditCommitFailure(t *testing.T) {
	f := newCredentialVerificationFixture(t, connections.ExecutionModeConnector, "reconcile")
	name := "verify_fault_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	function := pgx.Identifier{name}.Sanitize()
	trigger := pgx.Identifier{name + "_trigger"}.Sanitize()
	sql := `create function ` + function + `() returns trigger language plpgsql as $$ begin
		if NEW.operation_id='` + f.op.ID.String() + `'::uuid and NEW.action='credential.verified' then
		 raise exception 'fixture credential verification audit commit failure'; end if; return NEW; end $$`
	if _, err := f.pool.Exec(t.Context(), sql); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := f.pool.Exec(ctx, `drop trigger if exists `+trigger+` on audit_events`); err != nil {
			t.Errorf("clean worker audit trigger: %v", err)
		}
		if _, err := f.pool.Exec(ctx, `drop function if exists `+function+`() `); err != nil {
			t.Errorf("clean worker audit function: %v", err)
		}
	})
	if _, err := f.pool.Exec(t.Context(), `create trigger `+trigger+` before insert on audit_events for each row execute function `+function+`() `); err != nil {
		t.Fatal(err)
	}
	if err := f.executor.Execute(t.Context(), f.op); err == nil {
		t.Fatal("audit fault was not exercised")
	}
	d, version, err := f.vault.Get(t.Context(), f.account.VaultPath)
	if err != nil || version != 2 || d["verification_operation_id"] != f.op.ID.String() || d["password"] != f.password {
		t.Fatal("fixture did not reach the committed canonical/uncommitted audit window")
	}
	_, proof, err := f.service.GetVerificationProof(t.Context(), f.account.ID, f.op.ID, 1)
	clear(proof)
	if err != nil {
		t.Fatal("retryable audit failure discarded the operation proof")
	}
	if artifact := f.executor.TakeOperationArtifacts(f.op.ID); len(artifact.Result) != 0 {
		t.Fatal("uncommitted audit produced a success artifact")
	}
	if _, err := f.pool.Exec(t.Context(), `drop trigger `+trigger+` on audit_events`); err != nil {
		t.Fatal(err)
	}
	if err := f.executor.Execute(t.Context(), f.op); err != nil {
		t.Fatalf("CAS retry could not recover its own exact canonical write: %v", err)
	}
	_, version, err = f.vault.Get(t.Context(), f.account.VaultPath)
	if err != nil || version != 2 || f.dispatcher.calls != 2 {
		t.Fatal("retry skipped fresh proof or wrote another canonical version")
	}
	if _, _, err := f.service.GetVerificationProof(t.Context(), f.account.ID, f.op.ID, 1); err == nil {
		t.Fatal("successful retry retained the staged secret")
	}
	f.assertPreserved(t)
}
