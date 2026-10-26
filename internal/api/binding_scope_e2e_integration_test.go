//go:build integration

// Сквозные регрессии на вывод области действия binding
// (inventory.EffectiveBindingScope) против реальных целевых систем, у которых
// assignable-право неотделимо от своего ресурса: Kafka
// (topic-produce:<topic> — топик) и MongoDB (role:<db>.<name> — база).
//
// Проверяемый инвариант: грант БЕЗ явного scope_resource_id — ровно то, что
// отправляет UI — после discovery остаётся synced. До вывода области такой
// грант создавал binding с scope_resource_id IS NULL, discovery фиксировал
// наблюдаемый доступ отдельной строкой с ресурсом, и каждый выданный доступ
// давал пару «ложный drift + фантомный внешний грант».
//
// API-сервер собирается с полноценным River worker (newCascadeWorkerEnv),
// поэтому операции реально исполняются в целевой системе.
package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/scram"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/kafka"
	"github.com/ArtefactoO/grantor/internal/adapters/mongodb"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
)

// registerKafkaOnceAPI / registerMongoOnceAPI защищают от повторной
// регистрации adapter в процессе тестов api (registry глобален).
var (
	registerKafkaOnceAPI sync.Once
	registerMongoOnceAPI sync.Once
)

// createScopedConnection создаёт connection через API и доводит его до
// active первым refresh; возвращает id подключения и id операции discovery.
func createScopedConnection(t *testing.T, env *testEnv, admin, operator auth.Session, body map[string]any) (uuid.UUID, uuid.UUID) {
	t.Helper()
	resp := env.do(t, http.MethodPost, "/api/v1/connections", body, &admin, true)
	requireStatus(t, resp, http.StatusCreated)
	var connOut struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&connOut); err != nil {
		t.Fatalf("decode connection: %v", err)
	}
	return connOut.ID, refreshConnection(t, env, operator, connOut.ID)
}

// refreshConnection запускает discovery подключения, ждёт успеха операции и
// возвращает её id.
func refreshConnection(t *testing.T, env *testEnv, operator auth.Session, connID uuid.UUID) uuid.UUID {
	t.Helper()
	resp := env.do(t, http.MethodPost, "/api/v1/connections/"+connID.String()+"/refresh", nil, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var out struct {
		OperationID uuid.UUID `json:"operation_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode refresh: %v", err)
	}
	waitOperation(t, env, out.OperationID, operations.StatusSuccess, 120*time.Second)
	return out.OperationID
}

// refreshConnectionAgain добивается НОВОГО прогона discovery после prevOpID.
// Idempotency key refresh огрублён до минуты (refreshOperationKey), поэтому
// повторный вызов в том же окне вернул бы ту же уже успешную операцию, и
// сведение observed-состояния не выполнилось бы: тест проверял бы только
// запись, сделанную самим grant-джобом. Здесь окно честно пережидается.
func refreshConnectionAgain(t *testing.T, env *testEnv, operator auth.Session, connID, prevOpID uuid.UUID) {
	t.Helper()
	for attempt := 0; attempt < 3; attempt++ {
		resp := env.do(t, http.MethodPost, "/api/v1/connections/"+connID.String()+"/refresh", nil, &operator, true)
		requireStatus(t, resp, http.StatusAccepted)
		var out struct {
			OperationID uuid.UUID `json:"operation_id"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode refresh: %v", err)
		}
		if out.OperationID != prevOpID {
			waitOperation(t, env, out.OperationID, operations.StatusSuccess, 120*time.Second)
			return
		}
		wait := time.Until(time.Now().Truncate(time.Minute).Add(time.Minute + time.Second))
		t.Logf("refresh idempotency window is still open, waiting %s for a new discovery", wait.Round(time.Second))
		time.Sleep(wait)
	}
	t.Fatal("could not start a new discovery: refresh kept returning the previous operation")
}

// grantWithoutScope выдаёт принципалу право БЕЗ scope_resource_id (путь UI) и
// дожидается исполнения account.create и access.grant.
func grantWithoutScope(t *testing.T, env *testEnv, operator auth.Session,
	connID uuid.UUID, perm inventory.Permission, identity string) uuid.UUID {
	t.Helper()
	resp := env.do(t, http.MethodPost, "/api/v1/principals", map[string]any{
		"type": "service", "display_name": "Scope E2E " + identity,
	}, &operator, true)
	requireStatus(t, resp, http.StatusCreated)
	var principal struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&principal); err != nil {
		t.Fatalf("decode principal: %v", err)
	}

	access := grantPrincipalAccessItems(t, env, &operator, principal.ID, identity, []map[string]any{
		// scope_resource_id намеренно отсутствует: ровно то, что отправляет UI.
		{"connection_id": connID, "permission_id": perm.ID},
	})
	if len(access.Children) != 1 {
		t.Fatalf("access children = %d, want 1", len(access.Children))
	}
	child := access.Children[0]
	if child.AccountCreateOperationID == nil {
		t.Fatalf("account.create operation is missing; managed account was expected to be created")
	}
	waitOperation(t, env, *child.AccountCreateOperationID, operations.StatusSuccess, 120*time.Second)
	waitOperation(t, env, child.GrantOperationID, operations.StatusSuccess, 120*time.Second)
	return child.AccountID
}

// requireSyncedScopedBinding — основная проверка регрессии: у аккаунта ровно
// один binding на это право, он лежит в собственной области права, управляем
// сервисом и synced. Фантомной external-строки нет.
func requireSyncedScopedBinding(t *testing.T, env *testEnv, accountID uuid.UUID, perm inventory.Permission) {
	t.Helper()
	if perm.ScopeResourceID == nil {
		t.Fatalf("permission %q has no own scope resource; the regression cannot be reproduced on it",
			perm.ExternalID)
	}
	bindings, err := inventory.NewStore().ListBindingsByAccount(context.Background(), env.pool, accountID)
	if err != nil {
		t.Fatalf("list bindings: %v", err)
	}
	var matched []inventory.Binding
	for i := range bindings {
		if bindings[i].PermissionDefinitionID == perm.ID {
			matched = append(matched, bindings[i])
		}
	}
	if len(matched) != 1 {
		t.Fatalf("bindings on permission %q = %d, want exactly 1 (a second row is the phantom external grant): %+v",
			perm.ExternalID, len(matched), matched)
	}
	b := matched[0]
	if !inventory.SameScope(b.ScopeResourceID, perm.ScopeResourceID) {
		t.Errorf("binding scope = %v, want permission scope %v", b.ScopeResourceID, perm.ScopeResourceID)
	}
	if b.Source != string(inventory.BindingSourceService) {
		t.Errorf("binding source = %q, want service", b.Source)
	}
	if b.DesiredState == nil || *b.DesiredState != inventory.BindingPresent {
		t.Errorf("binding desired_state = %v, want present", b.DesiredState)
	}
	if b.ObservedState != inventory.BindingPresent {
		t.Errorf("binding observed_state = %q, want present", b.ObservedState)
	}
	if b.Status != inventory.BindingStatusSynced {
		t.Errorf("binding status = %q, want synced", b.Status)
	}
}

// requireNoDriftForAccount проверяет, что отчёт GET /drift подключения не
// содержит находок по нашему аккаунту (ни ложного drift, ни фантомного
// unmanaged binding). Остальные аккаунты общей целевой системы не проверяются:
// фикстуры соседних тестов живут на том же кластере.
func requireNoDriftForAccount(t *testing.T, env *testEnv, operator auth.Session, connID, accountID uuid.UUID) {
	t.Helper()
	resp := env.do(t, http.MethodGet, "/api/v1/drift?connection_id="+connID.String(), nil, &operator, false)
	requireStatus(t, resp, http.StatusOK)
	var out struct {
		Findings []struct {
			Kind      string     `json:"kind"`
			AccountID *uuid.UUID `json:"account_id"`
			Detail    string     `json:"detail"`
		} `json:"findings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode drift: %v", err)
	}
	for _, f := range out.Findings {
		if f.AccountID != nil && *f.AccountID == accountID {
			t.Errorf("drift finding for managed account: kind=%q detail=%q", f.Kind, f.Detail)
		}
	}
}

// --- Kafka ---------------------------------------------------------------

// kafkaAdmin строит kadm-клиент админской SCRAM-учёткой стенда.
func kafkaAdmin(t *testing.T, broker, user, pass string) (*kadm.Client, func()) {
	t.Helper()
	kcl, err := kgo.NewClient(
		kgo.SeedBrokers(broker),
		kgo.DialTimeout(10*time.Second),
		kgo.SASL(scram.Auth{User: user, Pass: pass}.AsSha256Mechanism()),
	)
	if err != nil {
		t.Fatalf("create kafka client: %v", err)
	}
	return kadm.NewClient(kcl), kcl.Close
}

func TestIntegrationGrantWithoutScopeStaysSyncedKafka(t *testing.T) {
	// Тесты обоих движков ждут окно идемпотентности refresh (до минуты) —
	// параллельный прогон совмещает ожидания.
	t.Parallel()
	broker := os.Getenv("GRANTOR_TEST_KAFKA_BROKER")
	kafkaUser := os.Getenv("GRANTOR_TEST_KAFKA_USER")
	kafkaPass := os.Getenv("GRANTOR_TEST_KAFKA_PASS")
	if broker == "" || kafkaUser == "" || kafkaPass == "" {
		t.Skip("set GRANTOR_TEST_KAFKA_BROKER/USER/PASS to run the Kafka scope e2e test")
	}
	vaultClient := newTestVault(t)
	registerKafkaOnceAPI.Do(func() {
		adapter.Register(kafka.Engine, func() adapter.Adapter { return kafka.New() })
	})

	ctx := context.Background()
	sfx := uniqueSuffix()[:8]
	topic := "scope-e2e-" + sfx
	identity := "scope_e2e_" + sfx

	adm, closeAdm := kafkaAdmin(t, broker, kafkaUser, kafkaPass)
	// Регистрируется первым, а выполняется последним (Cleanup — LIFO):
	// клиент обязан пережить очистку фикстуры ниже.
	t.Cleanup(closeAdm)
	if _, err := adm.CreateTopic(ctx, 1, 1, nil, topic); err != nil && !errors.Is(err, kerr.TopicAlreadyExists) {
		t.Fatalf("create topic %q: %v", topic, err)
	}
	t.Cleanup(func() {
		cleanupCtx := context.Background()
		// Порядок: ACL нашего пользователя, сам пользователь, топик — иначе
		// оставленные записи попадут в discovery соседних прогонов.
		builder := kadm.NewACLs().
			ResourcePatternType(kadm.ACLPatternLiteral).
			Topics(topic).
			Operations().
			Allow("User:" + identity).
			AllowHosts()
		if _, err := adm.DeleteACLs(cleanupCtx, builder); err != nil {
			t.Logf("cleanup kafka acls: %v", err)
		}
		if _, err := adm.AlterUserSCRAMs(cleanupCtx,
			[]kadm.DeleteSCRAM{{User: identity, Mechanism: kadm.ScramSha256}}, nil); err != nil {
			t.Logf("cleanup kafka user: %v", err)
		}
		if _, err := adm.DeleteTopics(cleanupCtx, topic); err != nil {
			t.Logf("cleanup kafka topic: %v", err)
		}
	})

	env := newCascadeWorkerEnv(t, vaultClient)
	operator := session(auth.RoleOperator)
	admin := session(auth.RoleAdmin)

	connID, discoveryOpID := createScopedConnection(t, env, admin, operator, map[string]any{
		"display_name":     "itest-scope-kafka-" + sfx,
		"engine":           kafka.Engine,
		"environment":      "scope",
		"endpoints":        []string{broker},
		"tls_config":       map[string]string{"mode": "disabled"},
		"admin_credential": map[string]string{"username": kafkaUser, "password": kafkaPass},
	})

	// topic-produce:<topic> — bundle-право, неотделимое от топика: discovery
	// объявляет его вместе с scope_resource_id.
	perm := findPermission(t, env.pool, connID, "topic-produce:"+topic)
	accountID := grantWithoutScope(t, env, operator, connID, perm, identity)

	refreshConnectionAgain(t, env, operator, connID, discoveryOpID)
	requireSyncedScopedBinding(t, env, accountID, perm)
	requireNoDriftForAccount(t, env, operator, connID, accountID)
}

// --- MongoDB -------------------------------------------------------------

func TestIntegrationGrantWithoutScopeStaysSyncedMongoDB(t *testing.T) {
	t.Parallel()
	uri := os.Getenv("GRANTOR_TEST_MONGO_URI")
	if uri == "" {
		t.Skip("set GRANTOR_TEST_MONGO_URI to run the MongoDB scope e2e test")
	}
	vaultClient := newTestVault(t)
	registerMongoOnceAPI.Do(func() {
		adapter.Register(mongodb.Engine, func() adapter.Adapter { return mongodb.New() })
	})

	ctx := context.Background()
	sfx := uniqueSuffix()[:8]
	database := "scope_e2e_" + sfx
	seedUser := "scope_seed_" + sfx
	identity := "scope_e2e_" + sfx + "@" + database

	opts := options.Client().ApplyURI(uri)
	if err := opts.Validate(); err != nil {
		t.Fatalf("parse GRANTOR_TEST_MONGO_URI: %v", err)
	}
	client := mongoAdminClient(ctx, t, uri)
	t.Cleanup(func() {
		cleanupCtx := context.Background()
		if err := client.Database(database).Drop(cleanupCtx); err != nil {
			t.Logf("cleanup mongo database: %v", err)
		}
		if err := client.Disconnect(cleanupCtx); err != nil {
			t.Logf("disconnect mongo: %v", err)
		}
	})

	// Фикстура: база с коллекцией (пустая база в listDatabases не видна) и
	// пользователь с ролью read на ней — так discovery объявляет assignable
	// право role:<db>.read с собственной областью.
	if err := client.Database(database).CreateCollection(ctx, "events"); err != nil {
		t.Fatalf("create collection: %v", err)
	}
	if err := client.Database(database).RunCommand(ctx, bson.D{
		{Key: "createUser", Value: seedUser},
		{Key: "pwd", Value: "scope_seed_fixture_pwd"},
		{Key: "roles", Value: bson.A{bson.D{{Key: "role", Value: "read"}, {Key: "db", Value: database}}}},
	}).Err(); err != nil {
		t.Fatalf("create seed user: %v", err)
	}

	env := newCascadeWorkerEnv(t, vaultClient)
	operator := session(auth.RoleOperator)
	admin := session(auth.RoleAdmin)

	connBody := map[string]any{
		"display_name":     "itest-scope-mongo-" + sfx,
		"engine":           mongodb.Engine,
		"environment":      "scope",
		"endpoints":        opts.Hosts,
		"tls_config":       map[string]string{"mode": "disabled"},
		"admin_credential": map[string]string{"username": opts.Auth.Username, "password": opts.Auth.Password},
	}
	if opts.Auth.AuthSource != "" {
		cfg, err := json.Marshal(map[string]string{"auth_source": opts.Auth.AuthSource})
		if err != nil {
			t.Fatalf("marshal discovery config: %v", err)
		}
		connBody["discovery_config"] = json.RawMessage(cfg)
	}
	connID, discoveryOpID := createScopedConnection(t, env, admin, operator, connBody)

	// role:<db>.read несёт базу в самом идентификаторе — право неотделимо от
	// своей области.
	perm := findPermission(t, env.pool, connID, "role:"+database+".read")
	accountID := grantWithoutScope(t, env, operator, connID, perm, identity)

	refreshConnectionAgain(t, env, operator, connID, discoveryOpID)
	requireSyncedScopedBinding(t, env, accountID, perm)
	requireNoDriftForAccount(t, env, operator, connID, accountID)
}

// mongoAdminClient открывает клиент под admin credential из URI.
func mongoAdminClient(ctx context.Context, t *testing.T, uri string) *mongo.Client {
	t.Helper()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri).
		SetServerSelectionTimeout(10*time.Second).
		SetConnectTimeout(10*time.Second))
	if err != nil {
		t.Fatalf("connect mongo: %v", err)
	}
	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		t.Fatalf("ping mongo: %v", err)
	}
	return client
}
