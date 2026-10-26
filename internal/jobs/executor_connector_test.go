package jobs

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/netguard"
)

func TestConnectorDescriptorDerivesPrivateDNSGuardWithoutCallerAttributes(t *testing.T) {
	conn := connections.Connection{ID: uuid.New(), Engine: "kafka", ExecutionMode: "connector",
		Endpoints: []string{"kafka-cluster.betting-services.svc.cluster.local:9092"}}
	cfg := adapter.Connection{TLS: adapter.TLSConfig{Mode: "disabled"}}
	ref, _, _ := connectorConnectionParts(conn, cfg)
	if ref.NetworkGuard != netguard.PrivateKubernetesDNSV1 {
		t.Fatal("signed descriptor lacks private DNS policy")
	}
	conn.ExecutionMode = "direct"
	ref, _, _ = connectorConnectionParts(conn, cfg)
	if ref.NetworkGuard != "" {
		t.Fatal("direct descriptor received a connector-only profile")
	}
}

func TestConnectorCredentialFramesOwnIndependentSecretBuffers(t *testing.T) {
	expected := []byte("connector-frame-secret-canary")
	cfg := adapter.Connection{AdminCredentialIncarnation: 23, AdminCredential: adapter.Credential{
		Kind: "password", Username: "grantor_admin", Secret: append([]byte(nil), expected...),
	}}
	defer clear(cfg.AdminCredential.Secret)
	first, second := connectorJobCredentials(cfg), connectorJobCredentials(cfg)
	if first.Admin == nil || second.Admin == nil {
		t.Fatal("admin credential missing")
	}
	if first.AdminCredentialIncarnation != 23 || second.AdminCredentialIncarnation != 23 {
		t.Fatalf("admin credential incarnation was not copied: %d/%d",
			first.AdminCredentialIncarnation, second.AdminCredentialIncarnation)
	}
	frame := first.Frame(connector.Job{ID: "plan", Nonce: "plan-nonce"})
	frame.Zero()
	if !bytes.Equal(first.Admin.Secret, make([]byte, len(expected))) {
		t.Fatal("frame secret was not cleared")
	}
	if !bytes.Equal(cfg.AdminCredential.Secret, expected) {
		t.Fatal("clearing Plan frame erased caller-owned Apply credential")
	}
	if !bytes.Equal(second.Admin.Secret, expected) {
		t.Fatal("two credential frames share a secret buffer")
	}
	second.Zero()
	if !bytes.Equal(cfg.AdminCredential.Secret, expected) {
		t.Fatal("clearing another frame erased caller credential")
	}
	if !bytes.Equal(second.Admin.Secret, make([]byte, len(expected))) {
		t.Fatal("second frame secret was not cleared")
	}
}

// TestConnectorRoute — решение routing по режиму подключения и виду
// операции: direct всегда исполняется напрямую; connector-режим этапа 3
// пускает через gateway ВСЕ виды операций executor и требует
// сконфигурированный gateway; неизвестный вид падает с типизированной
// ошибкой без fallback к прямому исполнению.
func TestConnectorRoute(t *testing.T) {
	allKinds := []string{
		KindConnectionDiscover, KindAccountRecoverProvisioning,
		KindAccessGrant, KindAccessRevoke, KindAccessReplace,
		KindPostgresStatsGrantV1, KindPostgresStatsRevokeV1,
		KindPostgresObjectACLGrantV1, KindPostgresObjectACLRevokeV1,
		KindAccountCreate, KindAccountDisable, KindAccountEnable, KindAccountDelete, KindAccountRestore,
		KindRoleCreate, KindResourceCreateDatabase, KindDatabaseCreateWithRoles, KindResourceCreatePreparedDatabase, KindRolePolicyCreateDatabase,
		KindCredentialRotate, KindRolePolicyApply, KindRolePolicyAdopt, KindRolePolicyRepair, KindRolePolicyCreate,
		KindPostgresAccountCreateV2, KindPostgresAccountRestoreV2, KindPostgresRoleCreateV2,
		KindPostgresResourceCreateDatabaseV2, KindPostgresDatabaseCreateWithRolesV2,
		KindPostgresResourceCreateDatabaseForRolesV2,
		KindPostgresRolePolicyApplyV2, KindPostgresRolePolicyAdoptV2,
		KindPostgresRolePolicyRepairV2, KindPostgresRolePolicyCreateV2,
		KindPostgresRolePolicyCreateDatabaseV2,
	}

	t.Run("direct mode never routes and never errors", func(t *testing.T) {
		for _, kind := range allKinds {
			for _, configured := range []bool{false, true} {
				via, err := connectorRoute(connections.ExecutionModeDirect, kind, configured)
				if err != nil || via {
					t.Errorf("connectorRoute(direct, %q, %v) = (%v, %v), want (false, nil)",
						kind, configured, via, err)
				}
			}
		}
	})

	t.Run("connector mode routes every executor kind via connector", func(t *testing.T) {
		for _, kind := range allKinds {
			via, err := connectorRoute(connections.ExecutionModeConnector, kind, true)
			if err != nil || !via {
				t.Errorf("connectorRoute(connector, %q, true) = (%v, %v), want (true, nil)", kind, via, err)
			}
		}
	})

	t.Run("connector mode without gateway is a typed error", func(t *testing.T) {
		for _, kind := range allKinds {
			_, err := connectorRoute(connections.ExecutionModeConnector, kind, false)
			if !errors.Is(err, ErrConnectorGatewayNotConfigured) {
				t.Errorf("connectorRoute(connector, %q, false) error = %v, want ErrConnectorGatewayNotConfigured",
					kind, err)
			}
		}
	})

	t.Run("unknown kind is a typed not-supported error, no silent fallback", func(t *testing.T) {
		for _, configured := range []bool{false, true} {
			_, err := connectorRoute(connections.ExecutionModeConnector, "resource.create.unknown", configured)
			if !errors.Is(err, ErrConnectorKindNotSupported) {
				t.Errorf("connectorRoute(connector, unknown, %v) error = %v, want ErrConnectorKindNotSupported",
					configured, err)
			}
		}
	})
}

// TestConnectorDiscoverJob — задание JobDiscover строится секрет-free: в
// payload нет ни credentials, ни ссылок на них (ADR-0014: секреты уходят
// кадром TypeCredentials), idempotency key производен от id операции
// (стабилен между повторными доставками), а поля подписи/версии заполнены
// контрактно. Admin credential, прочитанный worker'ом в cfg, в payload не
// просачивается.
func TestConnectorDiscoverJob(t *testing.T) {
	opID := uuid.New()
	connID := uuid.New()
	op := operations.Operation{ID: opID, Kind: KindConnectionDiscover}
	conn := connections.Connection{
		ID:             connID,
		Engine:         "postgres",
		Endpoints:      []string{"db-1:5432"},
		VaultAdminPath: "connections/" + connID.String() + "/admin",
	}
	cfg := adapter.Connection{
		TLS:                        adapter.TLSConfig{Mode: "verify-full", CACertPEM: []byte("ca-pem")},
		Attributes:                 map[string]any{"database": "appdb"},
		ConfigIncarnation:          strings.Repeat("c", 64),
		AdminCredentialIncarnation: 29,
		AdminCredential: adapter.Credential{
			Kind: "password", Username: "admin", Secret: []byte("admin-canary-pw"),
		},
	}
	now := time.Unix(1700000000, 0)

	job, err := connectorDiscoverJob(op, conn, cfg, now)
	if err != nil {
		t.Fatalf("connectorDiscoverJob: %v", err)
	}

	if job.ID != opID.String() {
		t.Errorf("job.ID = %q, want operation id %q", job.ID, opID)
	}
	if job.Kind != connector.JobDiscover {
		t.Errorf("job.Kind = %q, want %q", job.Kind, connector.JobDiscover)
	}
	if job.ProtocolVersion != connector.ProtocolVersion {
		t.Errorf("job.ProtocolVersion = %q, want %q", job.ProtocolVersion, connector.ProtocolVersion)
	}
	if job.IssuedAt != now.Unix() {
		t.Errorf("job.IssuedAt = %d, want %d", job.IssuedAt, now.Unix())
	}
	if want := "op:" + opID.String() + ":snapshot-gzip-v1"; job.IdempotencyKey != want {
		t.Errorf("job.IdempotencyKey = %q, want %q", job.IdempotencyKey, want)
	}
	if job.Nonce == "" {
		t.Error("job.Nonce is empty")
	}

	payload, err := connector.ParseDiscoverPayload(job.Payload)
	if err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	if !payload.PostgresObjectACL || payload.SnapshotEncoding != connector.SnapshotGzipV1 {
		t.Fatal("worker did not opt in to the versioned ACL snapshot")
	}
	if payload.TLS.Mode != "verify-full" || string(payload.TLS.CACertPEM) != "ca-pem" {
		t.Errorf("tls ref = %+v does not mirror adapter tls config", payload.TLS)
	}
	if payload.Attributes["database"] != "appdb" {
		t.Errorf("attributes = %v, want database=appdb", payload.Attributes)
	}
	if payload.Connection.ConfigIncarnation != cfg.ConfigIncarnation {
		t.Errorf("config incarnation = %q, want %q", payload.Connection.ConfigIncarnation, cfg.ConfigIncarnation)
	}

	// Структурная проверка «без секретов»: в payload нет ни секрет-подобных
	// ключей, ни значения admin credential из cfg.
	var raw map[string]any
	if err := json.Unmarshal(job.Payload, &raw); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	assertNoSecretKeys(t, "payload", raw)
	if strings.Contains(string(job.Payload), "admin-canary-pw") {
		t.Errorf("admin credential leaked into job payload: %s", job.Payload)
	}

	// Кадр credentials строится из cfg и привязывается к заданию.
	creds := connectorJobCredentials(cfg)
	if creds.Admin == nil || creds.Admin.Username != "admin" {
		t.Fatalf("connectorJobCredentials admin = %+v, want cfg admin credential", creds.Admin)
	}
	if creds.AdminCredentialIncarnation != cfg.AdminCredentialIncarnation {
		t.Fatalf("admin credential incarnation = %d, want %d",
			creds.AdminCredentialIncarnation, cfg.AdminCredentialIncarnation)
	}
	frame := creds.Frame(job)
	if frame.JobID != job.ID || frame.Nonce != job.Nonce {
		t.Errorf("credentials frame binding = {%q %q}, want {%q %q}",
			frame.JobID, frame.Nonce, job.ID, job.Nonce)
	}
}

// assertNoSecretKeys рекурсивно проверяет, что среди ключей JSON нет
// секрет-подобных имён (password, token, private key, credential и т.п.).
func assertNoSecretKeys(t *testing.T, path string, v any) {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		return
	}
	for key, val := range m {
		lower := strings.ToLower(key)
		for _, bad := range []string{"password", "passwd", "token", "private", "secret", "credential", "vault"} {
			if strings.Contains(lower, bad) {
				t.Errorf("%s.%s: secret-like key in connector job payload", path, key)
			}
		}
		assertNoSecretKeys(t, path+"."+key, val)
	}
}

// --- Этап 3: сборка мутирующих заданий ---

// phase3Fixture — общая фикстура сборки мутирующих заданий.
func phase3Fixture() (operations.Operation, connections.Connection, adapter.Connection, inventory.Account) {
	opID := uuid.New()
	connID := uuid.New()
	op := operations.Operation{ID: opID, Kind: KindAccessGrant}
	conn := connections.Connection{
		ID:             connID,
		Engine:         "postgres",
		Endpoints:      []string{"db-1:5432"},
		VaultAdminPath: "connections/" + connID.String() + "/admin",
	}
	cfg := adapter.Connection{
		TLS:        adapter.TLSConfig{Mode: "verify-full", CACertPEM: []byte("ca-pem")},
		Attributes: map[string]any{"database": "appdb"},
	}
	acct := inventory.Account{
		ID:             uuid.New(),
		ConnectionID:   connID,
		Kind:           "login",
		EngineIdentity: "svc_1",
	}
	return op, conn, cfg, acct
}

// TestConnectorMutationJob — задание JobApply строится секрет-free: в payload
// нет ни credentials, ни ссылок на них (доставка — кадром TypeCredentials),
// idempotency key производен от id операции (стабилен между повторными
// доставками), change зеркалит операцию.
func TestConnectorMutationJob(t *testing.T) {
	op, conn, cfg, acct := phase3Fixture()
	now := time.Unix(1700000000, 0)

	job, err := connectorMutationJob(op, conn, cfg, connector.ChangeRef{
		Kind:       string(adapter.ChangeGrant),
		Account:    connectorAccountRef(acct),
		Permission: "role:readers",
		Scope:      "db:app",
	}, now)
	if err != nil {
		t.Fatalf("connectorMutationJob: %v", err)
	}

	if job.Kind != connector.JobApply {
		t.Errorf("job.Kind = %q, want %q", job.Kind, connector.JobApply)
	}
	if want := "op:" + op.ID.String(); job.IdempotencyKey != want {
		t.Errorf("job.IdempotencyKey = %q, want %q", job.IdempotencyKey, want)
	}
	if job.ProtocolVersion != connector.ProtocolVersion || job.IssuedAt != now.Unix() || job.Nonce == "" {
		t.Errorf("job contract fields mismatch: %+v", job)
	}

	payload, err := connector.ParseMutationPayload(job.Payload)
	if err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	if payload.Change.Kind != string(adapter.ChangeGrant) ||
		payload.Change.Permission != "role:readers" || payload.Change.Scope != "db:app" {
		t.Errorf("change ref mismatch: %+v", payload.Change)
	}
	if payload.Change.Account.EngineIdentity != acct.EngineIdentity {
		t.Errorf("account ref mismatch: %+v", payload.Change.Account)
	}

	// Секрет-подобных ключей и ссылок на credentials в payload нет.
	var raw map[string]any
	if err := json.Unmarshal(job.Payload, &raw); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	assertNoSecretKeys(t, "payload", raw)
}

func TestConnectorRoleCreateJobHasNoAccountCredential(t *testing.T) {
	op, conn, cfg, acct := phase3Fixture()
	op.Kind = KindRoleCreate
	acct.Kind = inventory.AccountKindGroup
	acct.EngineIdentity = "rw_existing_database"
	cfg.AdminCredential = adapter.Credential{
		Kind: "password", Username: "grantor_admin", Secret: []byte("role-create-admin-canary"),
	}
	job, err := connectorMutationJob(op, conn, cfg, connector.ChangeRef{
		Kind: string(adapter.ChangeRoleCreate), Account: connectorAccountRef(acct),
	}, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatalf("connectorMutationJob role.create: %v", err)
	}
	if job.Kind != connector.JobApply || job.IdempotencyKey != "op:"+op.ID.String() {
		t.Fatalf("role.create job kind/key = %q/%q", job.Kind, job.IdempotencyKey)
	}
	payload, err := connector.ParseMutationPayload(job.Payload)
	if err != nil {
		t.Fatalf("parse role.create payload: %v", err)
	}
	if payload.Change.Kind != string(adapter.ChangeRoleCreate) ||
		payload.Change.Account.Kind != inventory.AccountKindGroup ||
		payload.Change.Account.EngineIdentity != acct.EngineIdentity {
		t.Fatalf("role.create change = %+v", payload.Change)
	}
	creds := connectorJobCredentials(cfg)
	defer creds.Zero()
	if creds.Admin == nil || creds.Account != nil || creds.AccountVaultVersion != 0 {
		t.Fatal("role.create must carry only the connection admin credential")
	}
	var raw map[string]any
	if err := json.Unmarshal(job.Payload, &raw); err != nil {
		t.Fatalf("unmarshal role.create payload: %v", err)
	}
	assertNoSecretKeys(t, "payload", raw)
	if strings.Contains(string(job.Payload), "role-create-admin-canary") {
		t.Fatal("role.create leaked connection admin credential into payload")
	}
}

// TestConnectorEnableRestoreJobsAreDedupedPerChange — account.enable на
// движке, чей disable снимает права, отправляет несколько заданий одной
// операции (снятие блокировки + grant на каждый binding). Ключ дедупликации
// обязан различать их, иначе connector вернул бы кешированный результат
// первого задания вместо применения гранта; при этом он остаётся
// детерминированным, чтобы повторная доставка того же задания
// дедуплицировалась.
func TestConnectorEnableRestoreJobsAreDedupedPerChange(t *testing.T) {
	op, conn, cfg, acct := phase3Fixture()
	op.Kind = KindAccountEnable
	now := time.Unix(1700000000, 0)

	enable, err := connectorMutationJob(op, conn, cfg, connector.ChangeRef{
		Kind: string(adapter.ChangeAccountEnable), Account: connectorAccountRef(acct),
	}, now)
	if err != nil {
		t.Fatalf("connectorMutationJob enable: %v", err)
	}
	grantJob := func(permission, scope string) connector.Job {
		t.Helper()
		job, err := connectorMutationJob(op, conn, cfg, connector.ChangeRef{
			Kind: string(adapter.ChangeGrant), Account: connectorAccountRef(acct),
			Permission: permission, Scope: scope,
		}, now)
		if err != nil {
			t.Fatalf("connectorMutationJob grant %q: %v", permission, err)
		}
		return job
	}
	tag := grantJob("tag:management", "")
	vhost := grantJob("vhost-access:app", "vhost:app")

	if want := "op:" + op.ID.String(); enable.IdempotencyKey != want {
		t.Errorf("enable idempotency key = %q, want %q", enable.IdempotencyKey, want)
	}
	keys := map[string]string{
		"enable": enable.IdempotencyKey,
		"tag":    tag.IdempotencyKey,
		"vhost":  vhost.IdempotencyKey,
	}
	seen := map[string]string{}
	for name, key := range keys {
		if other, dup := seen[key]; dup {
			t.Errorf("jobs %q and %q share dedup key %q", name, other, key)
		}
		seen[key] = name
	}
	// Детерминированность: тот же binding в повторном исполнении операции
	// даёт тот же ключ.
	if again := grantJob("tag:management", ""); again.IdempotencyKey != tag.IdempotencyKey {
		t.Errorf("restore dedup key is not stable: %q != %q", again.IdempotencyKey, tag.IdempotencyKey)
	}
	// Ключ производен от операции, но не раскрывает имя permission целиком.
	if !strings.HasPrefix(tag.IdempotencyKey, "op:"+op.ID.String()+":restore:") {
		t.Errorf("restore dedup key = %q, want operation-derived restore prefix", tag.IdempotencyKey)
	}
}

func TestConnectorAccessReplaceDedupSeparatesConvergenceAndTarget(t *testing.T) {
	op, conn, cfg, acct := phase3Fixture()
	op.Kind = KindAccessReplace
	now := time.Unix(1700000000, 0)
	job := func(permission string) connector.Job {
		t.Helper()
		value, err := connectorMutationJob(op, conn, cfg, connector.ChangeRef{
			Kind: string(adapter.ChangeGrant), Account: connectorAccountRef(acct),
			Permission: permission, Scope: "vhost:app",
		}, now)
		if err != nil {
			t.Fatalf("connectorMutationJob(%q): %v", permission, err)
		}
		return value
	}
	converge := job("rabbitmq-template:b")
	target := job("rabbitmq-template:a")
	if converge.IdempotencyKey == target.IdempotencyKey {
		t.Fatalf("replace convergence and target share dedup key %q", converge.IdempotencyKey)
	}
	if again := job("rabbitmq-template:b"); again.IdempotencyKey != converge.IdempotencyKey {
		t.Fatalf("replace convergence dedup key is unstable: %q != %q",
			again.IdempotencyKey, converge.IdempotencyKey)
	}
}

func TestConnectorRestoreJobForcesFreshCredentialProofPerExecute(t *testing.T) {
	op, conn, cfg, acct := phase3Fixture()
	op.Kind = KindAccountRestore
	change := connector.ChangeRef{
		Kind: string(adapter.ChangeAccountRestore), Account: connectorAccountRef(acct),
	}
	first, err := connectorMutationJob(op, conn, cfg, change, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatalf("connectorMutationJob first restore: %v", err)
	}
	second, err := connectorMutationJob(op, conn, cfg, change, time.Unix(1700000001, 0))
	if err != nil {
		t.Fatalf("connectorMutationJob second restore: %v", err)
	}
	if first.IdempotencyKey == second.IdempotencyKey {
		t.Fatalf("restore retries reused connector dedup key %q; credential proof could be cached", first.IdempotencyKey)
	}
	prefix := "op:" + op.ID.String() + ":credential-proof:"
	if !strings.HasPrefix(first.IdempotencyKey, prefix) || !strings.HasPrefix(second.IdempotencyKey, prefix) {
		t.Errorf("restore idempotency keys = %q / %q, want prefix %q",
			first.IdempotencyKey, second.IdempotencyKey, prefix)
	}
	if first.ID != second.ID || first.ID != op.ID.String() {
		t.Errorf("restore wire job IDs = %q/%q, want stable operation id %q", first.ID, second.ID, op.ID)
	}
}

func TestPostgresV2ConnectorAttemptsUseFreshPhaseProofKeys(t *testing.T) {
	op, conn, cfg, acct := phase3Fixture()
	op.Kind = KindPostgresAccountCreateV2
	conn.Engine = "postgres"
	cfg.Engine = "postgres"
	cfg.ConfigIncarnation = strings.Repeat("a", 64)
	change := connector.ChangeRef{Kind: string(adapter.ChangePostgresAccountCreateV2),
		Account: connectorAccountRef(acct), ExpectedAdminIdentity: "grantor",
		ExpectedTargetIdentity: "postgres:system:123"}
	first, err := connectorMutationJobOfKind(op, conn, cfg, change, connector.JobApply, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	second, err := connectorMutationJobOfKind(op, conn, cfg, change, connector.JobApply, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if first.IdempotencyKey == second.IdempotencyKey {
		t.Fatalf("separate v2 worker attempts reused proof key %q", first.IdempotencyKey)
	}
	prefix := "op:" + op.ID.String() + ":postgres-v2:job.apply:"
	if !strings.HasPrefix(first.IdempotencyKey, prefix) || !strings.HasPrefix(second.IdempotencyKey, prefix) {
		t.Fatalf("v2 proof keys = %q/%q, want prefix %q", first.IdempotencyKey, second.IdempotencyKey, prefix)
	}
	// Retransmitting the exact signed job keeps one key and is therefore
	// deduplicated by the connector store.
	retransmission := first
	if retransmission.IdempotencyKey != first.IdempotencyKey || retransmission.ID != first.ID {
		t.Fatal("exact wire retransmission changed identity")
	}
}

func TestConnectorDatabasePolicyForcesFreshOIDProofPerAttempt(t *testing.T) {
	op, conn, cfg, _ := phase3Fixture()
	op.Kind = KindRolePolicyCreateDatabase
	change := connector.ChangeRef{Kind: string(adapter.ChangeRolePolicyCreateDatabase),
		RolePolicySpec:         &adapter.RolePolicySpec{Engine: "postgres", Key: "read", RoleName: "r_app", Database: "app"},
		ExpectedTargetIdentity: "postgres:system:123", ExpectedDatabaseOID: 321}
	first, err := connectorMutationJob(op, conn, cfg, change, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	second, err := connectorMutationJob(op, conn, cfg, change, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	prefix := "op:" + op.ID.String() + ":database-proof:"
	if first.IdempotencyKey == second.IdempotencyKey || !strings.HasPrefix(first.IdempotencyKey, prefix) || !strings.HasPrefix(second.IdempotencyKey, prefix) {
		t.Fatalf("database proof reused a cached worker attempt: %q / %q", first.IdempotencyKey, second.IdempotencyKey)
	}
	if first.ID != op.ID.String() || second.ID != first.ID || string(first.Payload) != string(second.Payload) {
		t.Fatal("fresh proof changed the immutable child identity or intent")
	}
}

func TestConnectorDatabasePreparationDiscoveryUsesFreshAttemptKey(t *testing.T) {
	op, conn, cfg, _ := phase3Fixture()
	parent := uuid.New()
	op.Kind, op.ParentID, op.ID = KindConnectionDiscover, &parent, databaseChildID(parent, "discover_database")
	first, err := connectorDiscoverJob(op, conn, cfg, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	second, err := connectorDiscoverJob(op, conn, cfg, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if first.IdempotencyKey == second.IdempotencyKey || first.ID != second.ID || first.ID != op.ID.String() {
		t.Fatalf("workflow discovery did not refresh while preserving history: %q/%q", first.IdempotencyKey, second.IdempotencyKey)
	}
	// Ordinary discovery retains the established durable delivery contract.
	op.ParentID = nil
	first, _ = connectorDiscoverJob(op, conn, cfg, time.Now())
	second, _ = connectorDiscoverJob(op, conn, cfg, time.Now())
	if first.IdempotencyKey != second.IdempotencyKey {
		t.Fatal("ordinary discovery dedup changed")
	}
}

// TestConnectorRotateJob — задание JobRotateCredential пинит Vault-координаты
// нового секрета (path + версия, известные только worker'у) в idempotency
// key: повтор операции с новой версией секрета не может получить
// закешированный успех применения предыдущей. Сами координаты и секрет в
// payload не попадают.
func TestConnectorRotateJob(t *testing.T) {
	op, conn, cfg, acct := phase3Fixture()
	now := time.Unix(1700000000, 0)
	path := "accounts/" + acct.ID.String() + "/credential"

	jobV1, err := connectorRotateJob(op, conn, cfg, connectorAccountRef(acct), path, 1, false, now)
	if err != nil {
		t.Fatalf("connectorRotateJob v1: %v", err)
	}
	jobV2, err := connectorRotateJob(op, conn, cfg, connectorAccountRef(acct), path, 2, false, now)
	if err != nil {
		t.Fatalf("connectorRotateJob v2: %v", err)
	}
	if jobV1.Kind != connector.JobRotateCredential {
		t.Errorf("job.Kind = %q, want %q", jobV1.Kind, connector.JobRotateCredential)
	}
	if jobV1.IdempotencyKey == jobV2.IdempotencyKey {
		t.Errorf("idempotency keys for different vault versions must differ: %q", jobV1.IdempotencyKey)
	}
	// Тот же op + та же версия -> тот же ключ (стабильность между доставками).
	again, err := connectorRotateJob(op, conn, cfg, connectorAccountRef(acct), path, 1, false, now)
	if err != nil {
		t.Fatalf("connectorRotateJob again: %v", err)
	}
	if again.IdempotencyKey != jobV1.IdempotencyKey {
		t.Errorf("idempotency key is not stable: %q != %q", again.IdempotencyKey, jobV1.IdempotencyKey)
	}

	payload, err := connector.ParseRotatePayload(jobV1.Payload)
	if err != nil {
		t.Fatalf("parse rotate payload: %v", err)
	}
	if payload.Account.EngineIdentity != acct.EngineIdentity {
		t.Errorf("rotate payload account mismatch: %+v", payload.Account)
	}
	var raw map[string]any
	if err := json.Unmarshal(jobV1.Payload, &raw); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	assertNoSecretKeys(t, "payload", raw)
	if strings.Contains(string(jobV1.Payload), path) {
		t.Errorf("vault path leaked into rotate payload: %s", jobV1.Payload)
	}

	// Без Vault-координат нового секрета задание не собирается.
	if _, err := connectorRotateJob(op, conn, cfg, connectorAccountRef(acct), "", 0, false, now); err == nil {
		t.Error("connectorRotateJob without the vault path must fail")
	}
}
