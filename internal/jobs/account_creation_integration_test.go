//go:build integration

package jobs_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/core/accountcreation"
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

type accountCreationStageObservation struct {
	stage, username, admin, config, target string
	version, adminVersion                  int
	oid                                    uint32
}

type accountCreationStageDispatcher struct {
	mu               sync.Mutex
	observations     []accountCreationStageObservation
	preflightCode    string
	verifyCode       string
	lostCreate       bool
	createOutcome    string
	beforeStage      func(string) error
	beforeVerifyDone func() error
}

func (*accountCreationStageDispatcher) ActiveConnectorSupports(capability adapter.Capability) bool {
	return capability == adapter.CapPostgresAccountCreationV1 || capability == adapter.CapPostgresSuperuserDirectV1
}

func (d *accountCreationStageDispatcher) Dispatch(_ context.Context, job connector.Job, creds connector.JobCredentials) (connector.JobResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if job.Kind != connector.JobAccountCreation || creds.Admin == nil || creds.Account == nil {
		return connector.JobResult{}, errors.New("creation workflow crossed into a generic target mutation")
	}
	p, err := connector.ParseAccountCreationPayload(job.Payload)
	if err != nil {
		return connector.JobResult{}, err
	}
	if bytes.Contains(job.Payload, creds.Account.Secret) || creds.Account.Username != p.Request.Change.Account.EngineIdentity {
		return connector.JobResult{}, errors.New("creation workflow crossed the credential boundary")
	}
	seen := accountCreationStageObservation{stage: p.Stage, username: creds.Account.Username, admin: creds.Admin.Username,
		config: p.Request.Connection.ConfigIncarnation, target: p.Request.Change.ExpectedTargetIdentity,
		version: creds.AccountVaultVersion, adminVersion: creds.AdminCredentialIncarnation}
	if p.Proof != nil {
		seen.oid = p.Proof.RoleOID
	}
	d.observations = append(d.observations, seen)
	if d.beforeStage != nil {
		if err := d.beforeStage(p.Stage); err != nil {
			return connector.JobResult{}, err
		}
	}
	code := ""
	if p.Stage == "preflight" {
		code = d.preflightCode
	}
	if p.Stage == "verify" {
		code = d.verifyCode
	}
	if code != "" {
		return connector.JobResult{JobID: job.ID, Status: connector.JobFailed, ErrorCode: code, Error: "creation-stage-error-canary"}, nil
	}
	if p.Stage == "create" && d.lostCreate {
		return connector.JobResult{}, errors.New("creation-stage-error-canary")
	}
	out := connector.AccountCreationOutcome{Stage: p.Stage, AccountID: p.AccountID, VaultVersion: creds.AccountVaultVersion, Confirmed: true}
	if p.Stage != "preflight" {
		out.Proof = &adapter.AccountCreationProof{EngineIdentity: p.Request.Change.Account.EngineIdentity, RoleOID: 16384, TargetIdentity: p.Request.Change.ExpectedTargetIdentity}
	}
	if p.Stage == "create" {
		switch d.createOutcome {
		case "foreign identity":
			out.Proof.EngineIdentity = "foreign_login"
		case "foreign target":
			out.Proof.TargetIdentity = "postgres:system:999"
		case "zero OID":
			out.Proof.RoleOID = 0
		case "missing proof":
			out.Proof = nil
		case "foreign account":
			out.AccountID = uuid.NewString()
		case "foreign version":
			out.VaultVersion++
		}
	}
	if p.Stage == "verify" && d.beforeVerifyDone != nil {
		if err := d.beforeVerifyDone(); err != nil {
			return connector.JobResult{}, err
		}
	}
	raw, err := json.Marshal(out)
	if p.Stage == "create" && d.createOutcome == "unknown field" {
		raw = append(raw[:len(raw)-1], []byte(`,"sql":"creation-stage-error-canary"}`)...)
	}
	return connector.JobResult{JobID: job.ID, Status: connector.JobSuccess, Result: raw}, err
}

func (d *accountCreationStageDispatcher) stages() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var stages []string
	for _, seen := range d.observations {
		stages = append(stages, seen.stage)
	}
	return strings.Join(stages, ",")
}

type accountCreationWorkerFixture struct {
	pool       *pgxpool.Pool
	vault      *vault.Client
	service    *credentials.Service
	connection connections.Connection
	account    inventory.Account
	principal  principals.Principal
	source     operations.Operation
	payload    jobs.AccountPayload
	executor   *jobs.MainExecutor
	dispatcher *accountCreationStageDispatcher
	adminPath  string
}

func newAccountCreationWorkerFixture(t *testing.T) *accountCreationWorkerFixture {
	t.Helper()
	f := &accountCreationWorkerFixture{pool: pgtest.Pool(t), vault: newTestVaultClient(t), dispatcher: &accountCreationStageDispatcher{}}
	f.service = credentials.NewService(f.vault, nil)
	registerPostgresOnce.Do(func() { adapter.Register(postgres.Engine, func() adapter.Adapter { return postgres.New() }) })
	suffix := uuid.NewString()
	f.adminPath = "tests/account-creation/" + suffix + "/admin"
	adminVersion, err := f.vault.Put(t.Context(), f.adminPath, map[string]any{"username": "grantor", "password": "creation-fixture-admin-canary"})
	if err != nil {
		t.Fatal("could not write the task-scoped fixture admin credential")
	}
	f.connection, err = connections.NewStore().Create(t.Context(), f.pool, connections.CreateParams{DisplayName: "creation-workflow-" + suffix,
		Engine: "postgres", Environment: "itest", Endpoints: []string{"isolated-postgres:5432"}, ExecutionMode: connections.ExecutionModeConnector,
		AdminCredentialMode: "existing_vault_ref", VaultAdminPath: f.adminPath})
	if err != nil {
		t.Fatal(err)
	}
	observed := time.Now().UTC().Truncate(time.Microsecond)
	topology, err := json.Marshal(map[string]any{"system_identifier": "42", "admin_credential_canonical_identity": "grantor",
		adapter.PostgresProvisioningAuthorityTopologyKey: adapter.ProvisioningAuthorityAssessment{Status: adapter.ProvisioningAuthorityConfirmed,
			Reason: adapter.ProvisioningAuthoritySuperuserConfirmed, ObservedAt: observed, ExpectedAdminIdentity: "grantor", ObservedAdminIdentity: "grantor",
			CredentialIncarnation: adminVersion, ConfigIncarnation: connections.ConfigIncarnation(f.connection), TargetIdentity: "postgres:system:42"}})
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err := json.Marshal(postgres.New().Manifest().CapabilityNames())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), `update connections set status='active',topology=$2,last_discovery_at=$3,capabilities=$4 where id=$1`,
		f.connection.ID, topology, observed, capabilities); err != nil {
		t.Fatal(err)
	}
	f.connection, err = connections.NewStore().Get(t.Context(), f.pool, f.connection.ID)
	if err != nil {
		t.Fatal(err)
	}
	f.principal, err = principals.NewStore().Create(t.Context(), f.pool, principals.CreateParams{Type: principals.TypeHuman, DisplayName: "creation-principal-" + suffix})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context()) //nolint:errcheck
	f.account, err = inventory.NewStore().CreateProvisioningAccount(t.Context(), tx, inventory.CreateManagedAccountParams{ConnectionID: f.connection.ID,
		Kind: "login", EngineIdentity: "creation_login", PrincipalID: &f.principal.ID, CredentialMode: "provided", VaultPath: "accounts/" + suffix + "/credential"})
	if err != nil {
		t.Fatal(err)
	}
	f.account, err = inventory.NewStore().ReserveAccountLifecycle(t.Context(), tx, f.account.ID, inventory.AccountProvisioning)
	if err != nil {
		t.Fatal(err)
	}
	version, err := f.vault.Put(t.Context(), f.account.VaultPath, map[string]any{"username": f.account.EngineIdentity, "password": "creation-fixture-account-canary"})
	if err != nil {
		t.Fatal("could not write the task-scoped fixture account credential")
	}
	t.Cleanup(func() {
		_ = f.vault.DeleteMetadata(context.Background(), f.adminPath)
		_ = f.vault.DeleteMetadata(context.Background(), f.account.VaultPath)
	})
	f.payload = jobs.AccountPayload{AccountID: f.account.ID, ExpectedStatus: inventory.AccountProvisioning, ExpectedLifecycleVersion: f.account.LifecycleVersion,
		ExpectedAdminIdentity: "grantor", ExpectedTargetIdentity: "postgres:system:42", ExpectedConfigIncarnation: connections.ConfigIncarnation(f.connection),
		ExpectedCredentialIncarnation: adminVersion, CredentialVaultVersion: version, CredentialMode: "provided"}
	raw, err := json.Marshal(f.payload)
	if err != nil {
		t.Fatal(err)
	}
	f.source, _, err = operations.NewStore().Create(t.Context(), tx, operations.CreateParams{Kind: jobs.KindPostgresAccountProvisionV1,
		ConnectionID: &f.connection.ID, AccountID: &f.account.ID, Payload: raw, ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.executor = jobs.NewMainExecutor(jobs.DiscoveryDeps{Pool: f.pool, Connections: connections.NewStore(), Inventory: inventory.NewStore(), Audit: audit.NewWriter(), Vault: f.vault}).
		WithMutations(jobs.MutationDeps{Credentials: f.service}).WithConnector(jobs.ConnectorDeps{Dispatcher: f.dispatcher})
	return f
}

func (f *accountCreationWorkerFixture) receipt(t *testing.T) accountcreation.Receipt {
	t.Helper()
	r, err := accountcreation.NewStore().Get(t.Context(), f.pool, f.source.ID)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (f *accountCreationWorkerFixture) accountNow(t *testing.T) inventory.Account {
	t.Helper()
	a, err := inventory.NewStore().GetAccount(t.Context(), f.pool, f.account.ID)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (f *accountCreationWorkerFixture) prepareCreated(t *testing.T) {
	t.Helper()
	f.dispatcher.verifyCode = "credential_access_denied"
	if err := f.executor.Execute(t.Context(), f.source); !errors.Is(err, adapter.ErrCredentialProofAccessDenied) {
		t.Fatalf("fixture failed to retain a creation receipt: %v", err)
	}
	if _, err := f.pool.Exec(t.Context(), `update operations set status='failed',error='not retryable: credential access denied',finished_at=now() where id=$1`, f.source.ID); err != nil {
		t.Fatal(err)
	}
	f.dispatcher.verifyCode = ""
}

func (f *accountCreationWorkerFixture) verification(t *testing.T) operations.Operation {
	t.Helper()
	p := f.payload
	p.CreationOperationID = f.source.ID
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	op, _, err := operations.NewStore().Create(t.Context(), f.pool, operations.CreateParams{Kind: jobs.KindPostgresAccountVerifyCreationV1,
		ConnectionID: &f.connection.ID, AccountID: &f.account.ID, Payload: raw, ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	return op
}

func (f *accountCreationWorkerFixture) successAudits(t *testing.T) int {
	t.Helper()
	var count int
	if err := f.pool.QueryRow(t.Context(), `select count(*) from audit_events where account_id=$1 and action='account.created'`, f.account.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestAccountCreationWorkerPreflightDenialNeverStartsCreate(t *testing.T) {
	f := newAccountCreationWorkerFixture(t)
	f.dispatcher.preflightCode = "credential_access_denied"
	if err := f.executor.Execute(t.Context(), f.source); !errors.Is(err, adapter.ErrCredentialProofAccessDenied) {
		t.Fatalf("preflight error = %v", err)
	}
	if f.dispatcher.stages() != "preflight" || f.receipt(t).Phase != "planned" || f.accountNow(t).Status != inventory.AccountProvisioning || f.successAudits(t) != 0 {
		t.Fatal("denied authentication preflight crossed the CREATE or activation boundary")
	}
	f.dispatcher.preflightCode = ""
	if err := f.executor.Execute(t.Context(), f.source); err != nil {
		t.Fatal(err)
	}
	if f.dispatcher.stages() != "preflight,preflight,create,verify" || f.receipt(t).Phase != "verified" {
		t.Fatal("a recovered read-only preflight could not finish the original creation")
	}
}

func TestAccountCreationWorkerVerificationOnlyReusesExactReceipt(t *testing.T) {
	f := newAccountCreationWorkerFixture(t)
	f.dispatcher.beforeStage = func(stage string) error {
		r, err := accountcreation.NewStore().Get(t.Context(), f.pool, f.source.ID)
		if err != nil {
			return err
		}
		if (stage == "create" && r.Phase != "creating") || (stage == "verify" && (r.Phase != "created" || r.RoleOID != 16384)) {
			return errors.New("target stage ran before its durable receipt boundary")
		}
		return nil
	}
	f.prepareCreated(t)
	r := f.receipt(t)
	a := f.accountNow(t)
	if r.Phase != "created" || r.RoleOID != 16384 || r.CredentialVersion != f.payload.CredentialVaultVersion || a.Status != inventory.AccountProvisioning || a.Ownership != inventory.OwnershipManaged {
		t.Fatal("password proof failure lost CREATE ownership, pins or provisioning state")
	}
	op := f.verification(t)
	if err := f.executor.Execute(t.Context(), op); err != nil {
		t.Fatal(err)
	}
	if f.dispatcher.stages() != "preflight,create,verify,verify" || f.receipt(t).Phase != "verified" || f.accountNow(t).Status != inventory.AccountActive || f.successAudits(t) != 1 {
		t.Fatal("verification-only completion repeated CREATE, failed to activate, or duplicated audit")
	}
	f.dispatcher.mu.Lock()
	for _, seen := range f.dispatcher.observations {
		if seen.version != r.CredentialVersion || seen.adminVersion != r.AdminCredentialIncarnation || seen.username != r.EngineIdentity || seen.admin != r.AdminIdentity || seen.target != r.TargetIdentity || seen.config != r.ConfigIncarnation || (seen.stage == "verify" && seen.oid != r.RoleOID) {
			f.dispatcher.mu.Unlock()
			t.Fatal("retry changed a credential version, target pin or role incarnation")
		}
	}
	f.dispatcher.mu.Unlock()
	if err := f.executor.Execute(t.Context(), op); err != nil {
		t.Fatal(err)
	}
	if f.dispatcher.stages() != "preflight,create,verify,verify" || f.successAudits(t) != 1 {
		t.Fatal("durable completion replay reached the target or repeated metadata success")
	}
}

func TestAccountCreationWorkerUnknownCreateNeverReplaysOrManufacturesProof(t *testing.T) {
	for _, malformed := range []string{"lost response", "foreign identity", "foreign target", "zero OID", "missing proof", "foreign account", "foreign version", "unknown field"} {
		t.Run(malformed, func(t *testing.T) {
			f := newAccountCreationWorkerFixture(t)
			f.dispatcher.lostCreate = malformed == "lost response"
			f.dispatcher.createOutcome = malformed
			if err := f.executor.Execute(t.Context(), f.source); !errors.Is(err, jobs.ErrAccountCreationUnknown) {
				t.Fatalf("unknown creation outcome = %v", err)
			}
			if f.receipt(t).Phase != "creating" || f.receipt(t).RoleOID != 0 || f.accountNow(t).Status != inventory.AccountProvisioning || f.dispatcher.stages() != "preflight,create" {
				t.Fatal("malformed or lost CREATE result became acknowledged creation evidence")
			}
			// Observing a same-name live role cannot manufacture ownership/OID.
			if _, err := f.pool.Exec(t.Context(), `update accounts set attributes='{"role_oid":16384,"can_login":true}' where id=$1`, f.account.ID); err != nil {
				t.Fatal(err)
			}
			if err := f.executor.Execute(t.Context(), f.source); !errors.Is(err, jobs.ErrAccountCreationUnknown) {
				t.Fatalf("unknown CREATE retry = %v", err)
			}
			if f.dispatcher.stages() != "preflight,create" || f.successAudits(t) != 0 {
				t.Fatal("unknown CREATE replayed a target operation or manufactured success")
			}
		})
	}
}

func TestAccountCreationWorkerChangedCreationSourceStopsVerification(t *testing.T) {
	for _, mutation := range []string{"old V2 kind", "legacy kind", "retried source", "successful source", "source payload", "source account", "source connection", "missing source"} {
		t.Run(mutation, func(t *testing.T) {
			f := newAccountCreationWorkerFixture(t)
			f.prepareCreated(t)
			op := f.verification(t)
			var err error
			switch mutation {
			case "old V2 kind":
				_, err = f.pool.Exec(t.Context(), `update operations set kind=$2 where id=$1`, f.source.ID, jobs.KindPostgresAccountCreateV2)
			case "legacy kind":
				_, err = f.pool.Exec(t.Context(), `update operations set kind=$2 where id=$1`, f.source.ID, jobs.KindAccountCreate)
			case "retried source":
				_, err = f.pool.Exec(t.Context(), `update operations set status='pending' where id=$1`, f.source.ID)
			case "successful source":
				_, err = f.pool.Exec(t.Context(), `update operations set status='success' where id=$1`, f.source.ID)
			case "source payload":
				_, err = f.pool.Exec(t.Context(), `update operations set payload=jsonb_set(payload,'{expected_config_incarnation}','"changed"') where id=$1`, f.source.ID)
			case "source account":
				_, err = f.pool.Exec(t.Context(), `update operations set account_id=null where id=$1`, f.source.ID)
			case "source connection":
				_, err = f.pool.Exec(t.Context(), `update operations set connection_id=null where id=$1`, f.source.ID)
			case "missing source":
				p := f.payload
				p.CreationOperationID = uuid.New()
				op.Payload, err = json.Marshal(p)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := f.executor.Execute(t.Context(), op); err == nil {
				t.Fatal("verification accepted a missing, changed or legacy source")
			}
			if f.dispatcher.stages() != "preflight,create,verify" || f.accountNow(t).Status != inventory.AccountProvisioning || f.successAudits(t) != 0 {
				t.Fatal("changed creation source reached target verification or activation")
			}
		})
	}
}

func TestAccountCreationWorkerChangedPinsStopBeforeTarget(t *testing.T) {
	for _, mutation := range []string{"lifecycle", "ownership", "identity", "credential path", "credential version", "credential username", "admin version", "admin username", "config", "target", "disabled principal", "pending purge principal", "expired purge principal", "external disabled", "external deleted", "other pending operation"} {
		t.Run(mutation, func(t *testing.T) {
			f := newAccountCreationWorkerFixture(t)
			f.prepareCreated(t)
			op := f.verification(t)
			var err error
			switch mutation {
			case "lifecycle":
				_, err = f.pool.Exec(t.Context(), `update accounts set lifecycle_version=lifecycle_version+1 where id=$1`, f.account.ID)
			case "ownership":
				_, err = f.pool.Exec(t.Context(), `update accounts set ownership='unmanaged' where id=$1`, f.account.ID)
			case "identity":
				_, err = f.pool.Exec(t.Context(), `update accounts set engine_identity='foreign_login' where id=$1`, f.account.ID)
			case "credential path":
				_, err = f.pool.Exec(t.Context(), `update accounts set vault_path='accounts/foreign/credential' where id=$1`, f.account.ID)
			case "credential version", "credential username":
				username := f.account.EngineIdentity
				if mutation == "credential username" {
					username = "foreign_login"
				}
				_, err = f.vault.Put(t.Context(), f.account.VaultPath, map[string]any{"username": username, "password": "changed-creation-fixture-canary"})
			case "admin version", "admin username":
				username := "grantor"
				if mutation == "admin username" {
					username = "foreign_admin"
				}
				_, err = f.vault.Put(t.Context(), f.adminPath, map[string]any{"username": username, "password": "changed-creation-admin-canary"})
			case "config":
				_, err = f.pool.Exec(t.Context(), `update connections set endpoints='["another-postgres:5432"]'::jsonb where id=$1`, f.connection.ID)
			case "target":
				_, err = f.pool.Exec(t.Context(), `update connections set topology=jsonb_set(topology,'{system_identifier}','"43"') where id=$1`, f.connection.ID)
			case "disabled principal":
				_, err = f.pool.Exec(t.Context(), `update principals set status='disabled' where id=$1`, f.principal.ID)
			case "pending purge principal":
				_, err = f.pool.Exec(t.Context(), `update principals set status='pending_purge',purge_after=now()+interval '1 day' where id=$1`, f.principal.ID)
			case "expired purge principal":
				_, err = f.pool.Exec(t.Context(), `update principals set status='pending_purge',purge_after=now()-interval '1 minute' where id=$1`, f.principal.ID)
			case "external disabled", "external deleted":
				status := strings.TrimPrefix(mutation, "external ")
				_, err = f.pool.Exec(t.Context(), `update principals set external_identity_status=$2,external_identity_checked_at=now() where id=$1`, f.principal.ID, status)
			case "other pending operation":
				_, _, err = operations.NewStore().Create(t.Context(), f.pool, operations.CreateParams{Kind: jobs.KindCredentialRotate, ConnectionID: &f.connection.ID,
					AccountID: &f.account.ID, ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString()})
			}
			if err != nil {
				t.Fatal("could not prepare changed intent fixture")
			}
			if err := f.executor.Execute(t.Context(), op); err == nil {
				t.Fatal("verification accepted a changed lifecycle, credential, target or principal")
			}
			if f.dispatcher.stages() != "preflight,create,verify" || f.successAudits(t) != 0 {
				t.Fatal("changed reserved intent reached target verification or activation")
			}
		})
	}
}

func TestAccountCreationWorkerPromotionIsAtomicWithReceiptAndAudit(t *testing.T) {
	f := newAccountCreationWorkerFixture(t)
	bad := f.source
	bad.ActorID = "" // Audit rejects after the metadata mutations are staged.
	if err := f.executor.Execute(t.Context(), bad); err == nil {
		t.Fatal("injected audit failure was ignored")
	}
	if f.accountNow(t).Status != inventory.AccountProvisioning || f.receipt(t).Phase != "created" || f.successAudits(t) != 0 {
		t.Fatal("failed success transaction left partial activation, receipt or audit")
	}
	if err := f.executor.Execute(t.Context(), f.source); err != nil {
		t.Fatal(err)
	}
	if f.dispatcher.stages() != "preflight,create,verify,verify" || f.accountNow(t).Status != inventory.AccountActive || f.receipt(t).Phase != "verified" || f.successAudits(t) != 1 {
		t.Fatal("metadata retry repeated CREATE or failed to commit account, receipt and audit together")
	}
}

func TestAccountCreationWorkerCredentialChangeDuringProofBlocksPromotion(t *testing.T) {
	f := newAccountCreationWorkerFixture(t)
	f.dispatcher.beforeVerifyDone = func() error {
		_, err := f.vault.Put(t.Context(), f.account.VaultPath, map[string]any{"username": f.account.EngineIdentity, "password": "new-during-proof-fixture-canary"})
		return err
	}
	if err := f.executor.Execute(t.Context(), f.source); err == nil {
		t.Fatal("proof promoted a concurrently changed canonical credential")
	}
	if f.receipt(t).Phase != "created" || f.accountNow(t).Status != inventory.AccountProvisioning || f.successAudits(t) != 0 {
		t.Fatal("credential version race left an active account or lost creation ownership")
	}
}

func TestAccountCreationWorkerPrincipalAndOwnershipChangesDuringProofBlockPromotion(t *testing.T) {
	for _, mutation := range []string{"principal disabled", "external disabled", "external deleted", "principal detached", "ownership changed", "lifecycle changed"} {
		t.Run(mutation, func(t *testing.T) {
			f := newAccountCreationWorkerFixture(t)
			f.dispatcher.beforeVerifyDone = func() error {
				var err error
				switch mutation {
				case "principal disabled":
					_, err = f.pool.Exec(t.Context(), `update principals set status='disabled' where id=$1`, f.principal.ID)
				case "external disabled", "external deleted":
					_, err = f.pool.Exec(t.Context(), `update principals set external_identity_status=$2 where id=$1`, f.principal.ID, strings.TrimPrefix(mutation, "external "))
				case "principal detached":
					_, err = f.pool.Exec(t.Context(), `update accounts set principal_id=null where id=$1`, f.account.ID)
				case "ownership changed":
					_, err = f.pool.Exec(t.Context(), `update accounts set ownership='unmanaged' where id=$1`, f.account.ID)
				case "lifecycle changed":
					_, err = f.pool.Exec(t.Context(), `update accounts set lifecycle_version=lifecycle_version+1 where id=$1`, f.account.ID)
				}
				return err
			}
			if err := f.executor.Execute(t.Context(), f.source); err == nil {
				t.Fatal("password proof promoted a changed principal or account reservation")
			}
			if f.receipt(t).Phase != "created" || f.accountNow(t).Status != inventory.AccountProvisioning || f.successAudits(t) != 0 {
				t.Fatal("a concurrent reservation change left partial account activation or verified evidence")
			}
		})
	}
}

type accountCreationOuterCommitFault struct {
	*jobs.MainExecutor
	fail atomic.Bool
}

func (e *accountCreationOuterCommitFault) BeforeOperationCommit(_ context.Context, op operations.Operation) error {
	if op.Kind == jobs.KindPostgresAccountProvisionV1 && e.fail.CompareAndSwap(true, false) {
		return errors.New("forced post-promotion outer operation commit failure")
	}
	return nil
}

func TestAccountCreationWorkerCompletionSurvivesLostOuterCommit(t *testing.T) {
	f := newAccountCreationWorkerFixture(t)
	executor := &accountCreationOuterCommitFault{MainExecutor: f.executor}
	executor.fail.Store(true)
	river, err := jobs.New(f.pool, operations.NewStore(), executor, jobs.Config{Queue: testQueue(), WorkerCount: 1, MaxAttempts: 3, SnoozeOnLock: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context()) //nolint:errcheck
	if err := river.EnqueueOperationTx(t.Context(), tx, f.source.ID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	startRiver(t, river)
	waitForStatus(t, f.pool, operations.NewStore(), f.source.ID, operations.StatusSuccess, 30*time.Second)
	if f.dispatcher.stages() != "preflight,create,verify" || f.accountNow(t).Status != inventory.AccountActive || f.receipt(t).Phase != "verified" || f.successAudits(t) != 1 {
		t.Fatal("outer commit replay repeated a target effect, promotion or audit")
	}
	if states := jobStates(t, f.pool, f.source.ID); len(states) != 1 || !strings.Contains(states[0], ":2") {
		t.Fatalf("outer commit fault was not exercised: %v", states)
	}
}

func TestAccountCreationVerificationDoesNotReviveCanceledOrExpiredGrants(t *testing.T) {
	f := newAccountCreationWorkerFixture(t)
	f.prepareCreated(t)
	inv := inventory.NewStore()
	snap := &adapter.Snapshot{Accounts: []adapter.ObservedAccount{{Kind: "login", EngineIdentity: f.account.EngineIdentity}},
		Permissions: []adapter.ObservedPermission{{ExternalID: "role:r_fixture", Name: "r_fixture", Assignable: true}}}
	if _, err := inv.UpsertSnapshot(t.Context(), f.pool, f.connection.ID, snap, time.Now()); err != nil {
		t.Fatal(err)
	}
	permissions, err := inv.ListPermissions(t.Context(), f.pool, f.connection.ID)
	if err != nil || len(permissions) != 1 {
		t.Fatal("could not prepare a grant fixture")
	}
	expired := time.Now().Add(-time.Minute)
	binding, _, err := inv.EnsureBinding(t.Context(), f.pool, inventory.EnsureBindingParams{AccountID: f.account.ID,
		PermissionID: permissions[0].ID, DesiredState: inventory.BindingAbsent, ExpiresAt: &expired})
	if err != nil {
		t.Fatal(err)
	}
	op := f.verification(t)
	if err := f.executor.Execute(t.Context(), op); err != nil {
		t.Fatal(err)
	}
	got, err := inv.GetBinding(t.Context(), f.pool, binding.ID)
	if err != nil || got.DesiredState == nil || *got.DesiredState != inventory.BindingAbsent || got.ExpiresAt == nil || !got.ExpiresAt.Before(time.Now()) {
		t.Fatal("account verification revived a canceled or expired grant")
	}
	var grantOperations int
	if err := f.pool.QueryRow(t.Context(), `select count(*) from operations where account_id=$1 and kind=$2`, f.account.ID, jobs.KindAccessGrant).Scan(&grantOperations); err != nil {
		t.Fatal(err)
	}
	if grantOperations != 0 || f.dispatcher.stages() != "preflight,create,verify,verify" {
		t.Fatal("verification-only completion enqueued or executed an access grant")
	}
	var metadata string
	if err := f.pool.QueryRow(t.Context(), `select string_agg(metadata::text,' ') from audit_events where account_id=$1`, f.account.ID).Scan(&metadata); err != nil {
		t.Fatal(err)
	}
	for _, canary := range []string{"creation-fixture-account-canary", "creation-fixture-admin-canary", "creation-stage-error-canary"} {
		if strings.Contains(metadata, canary) {
			t.Fatal("account creation audit retained credentials or untrusted connector error contents")
		}
	}
}

func TestAccountCreationWorkerNoReceiptCannotVerifyLegacyCreation(t *testing.T) {
	f := newAccountCreationWorkerFixture(t)
	if _, err := f.pool.Exec(t.Context(), `update operations set kind=$2,status='failed' where id=$1`, f.source.ID, jobs.KindPostgresAccountCreateV2); err != nil {
		t.Fatal(err)
	}
	op := f.verification(t)
	if err := f.executor.Execute(t.Context(), op); err == nil {
		t.Fatal("verification manufactured a receipt for an old CREATE operation")
	}
	if _, err := accountcreation.NewStore().Get(t.Context(), f.pool, f.source.ID); !errors.Is(err, accountcreation.ErrNotFound) || f.dispatcher.stages() != "" {
		t.Fatal("legacy creation was promoted through a role lookup or target probe")
	}
}

func TestAccountCreationWorkerQueuedSourceRetryBlocksVerificationBeforeTarget(t *testing.T) {
	f := newAccountCreationWorkerFixture(t)
	f.prepareCreated(t)
	river, err := jobs.New(f.pool, operations.NewStore(), f.executor, jobs.Config{Queue: testQueue(), WorkerCount: 1})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context()) //nolint:errcheck
	if err := river.EnqueueOperationTx(t.Context(), tx, f.source.ID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	op := f.verification(t)
	if err := f.executor.Execute(t.Context(), op); err == nil {
		t.Fatal("verification stole a source with an active River retry")
	}
	if f.dispatcher.stages() != "preflight,create,verify" || f.accountNow(t).Status != inventory.AccountProvisioning || f.successAudits(t) != 0 {
		t.Fatal("source retry conflict reached target verification or promotion")
	}
}
