//go:build integration

// Интеграционные тесты Kafka adapter (discovery и мутации). Требуют «целевой»
// Kafka-совместимый брокер с включённым SASL/SCRAM; CI поднимает одноузловую
// Redpanda (scripts/test-integration.sh). Подключение задаётся через
// GRANTOR_TEST_KAFKA_BROKER (host:port) + GRANTOR_TEST_KAFKA_USER /
// GRANTOR_TEST_KAFKA_PASS (admin SCRAM credential), иначе тесты
// пропускаются. Фикстура создаётся идемпотентно, поэтому тесты можно
// запускать многократно над одним и тем же брокером.
//
// Пароли в логи не выводятся: секретный материал передаётся только внутри
// SASL handshake.
package kafka_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/scram"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adaptertest"
	"github.com/ArtefactoO/grantor/internal/adapters/kafka"
)

const (
	// Переменные окружения целевого брокера (admin SCRAM credential).
	brokerEnv = "GRANTOR_TEST_KAFKA_BROKER"
	userEnv   = "GRANTOR_TEST_KAFKA_USER"
	passEnv   = "GRANTOR_TEST_KAFKA_PASS"
	// Topics фикстуры: два, чтобы contract suite получил не менее двух
	// assignable не-dangerous permissions на разных scope.
	fixtureTopicA = "app-topic-a"
	fixtureTopicB = "app-topic-b"
	// fixtureUser — служебный пользователь фикстуры. Сортируется раньше
	// админского логина grantor, поэтому contract suite выбирает именно его
	// как активный login-аккаунт и не трогает администратора.
	fixtureUser = "app_svc"
	// fixturePass — заведомо небоевой пароль фикстурного пользователя.
	fixturePass = "app_svc_fixture_pwd"
	// wildcardHost — host ACL-записей, которые создаёт adapter.
	wildcardHost = "*"
)

// target возвращает адрес брокера и admin credential или пропускает тест.
func target(t *testing.T) (broker, user, pass string) {
	t.Helper()
	broker = os.Getenv(brokerEnv)
	if broker == "" {
		t.Skipf("%s is not set; skipping Kafka integration test", brokerEnv)
	}
	user = os.Getenv(userEnv)
	pass = os.Getenv(passEnv)
	if user == "" || pass == "" {
		t.Skipf("%s / %s are not set; skipping Kafka integration test", userEnv, passEnv)
	}
	return broker, user, pass
}

// connection строит adapter.Connection целевого брокера.
func connection(broker, user, pass string) adapter.Connection {
	return adapter.Connection{
		ID:        "conn-kafka-target",
		Engine:    kafka.Engine,
		Endpoints: []string{broker},
		TLS:       adapter.TLSConfig{Mode: "disabled"},
		AdminCredential: adapter.Credential{
			Kind:     "password",
			Username: user,
			Secret:   []byte(pass),
		},
	}
}

// plainEnv отмечает, что целевой брокер принимает SASL/PLAIN (harness
// включает механизм на дуальном SCRAM+PLAIN листенере).
const plainEnv = "GRANTOR_TEST_KAFKA_PLAIN"

// connectionMech строит adapter.Connection с явным SASL-механизмом через
// per-connection auth attribute (тот же путь, что discovery_config -> Attributes).
func connectionMech(broker, user, pass, mech string) adapter.Connection {
	conn := connection(broker, user, pass)
	conn.Attributes = map[string]any{"sasl_mechanism": mech}
	return conn
}

// adminKadmClient строит kadm-клиент с указанными SCRAM-credentials для
// подготовки фикстуры и независимой проверки состояния.
func adminKadmClient(t *testing.T, broker, user, pass string) (*kadm.Client, func()) {
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

// ensureFixture идемпотентно создаёт фикстуру: topics app-topic-a/b и
// SCRAM-пользователя app_svc.
func ensureFixture(ctx context.Context, t *testing.T, broker, user, pass string) {
	t.Helper()
	adm, closeFn := adminKadmClient(t, broker, user, pass)
	defer closeFn()

	for _, topic := range []string{fixtureTopicA, fixtureTopicB} {
		// CreateTopic возвращает и per-topic ошибку как err: уже существующий
		// topic фикстуры — не ошибка (идемпотентность).
		if _, err := adm.CreateTopic(ctx, 1, 1, nil, topic); err != nil &&
			!errors.Is(err, kerr.TopicAlreadyExists) {
			t.Fatalf("create topic %q: %v", topic, err)
		}
	}

	altered, err := adm.AlterUserSCRAMs(ctx, nil, []kadm.UpsertSCRAM{{
		User:       fixtureUser,
		Mechanism:  kadm.ScramSha256,
		Iterations: 4096,
		Password:   fixturePass,
	}})
	if err != nil {
		t.Fatalf("create fixture user: %v", err)
	}
	if err := altered.Error(); err != nil {
		t.Fatalf("create fixture user: %v", err)
	}
}

// TestContract прогоняет общий contract suite поверх целевого брокера.
// Manifest объявляет access.grant/revoke, поэтому suite выполняет grant/revoke
// тесты: фикстура даёт активный login-аккаунт (app_svc) и не менее двух
// assignable не-dangerous permissions (produce/consume bundles на двух
// topics).
func TestContract(t *testing.T) {
	broker, user, pass := target(t)
	ctx := context.Background()
	ensureFixture(ctx, t, broker, user, pass)
	conn := connection(broker, user, pass)

	adaptertest.Run(t, adaptertest.Harness{
		New: func(*testing.T) (adapter.Adapter, adapter.Connection) {
			return kafka.New(), conn
		},
	})
}

// TestValidateConnection проверяет, что admin credential проходит валидацию.
func TestValidateConnection(t *testing.T) {
	broker, user, pass := target(t)
	ctx := context.Background()
	if err := kafka.New().ValidateConnection(ctx, connection(broker, user, pass)); err != nil {
		t.Fatalf("ValidateConnection: %v", err)
	}
}

// TestPlainMechanism прогоняет SASL/PLAIN-путь на дуальном (SCRAM+PLAIN)
// брокере: ValidateConnection проходит по ACL-праву (SCRAM API не
// запрашивается), discovery читает topics/accounts/ACL без SCRAM API, ACL-
// управление (grant/revoke) доступно на principal без SCRAM credential, а
// SCRAM-lifecycle (account.create/credential.rotate) корректно сообщается
// недоступным. Так живьём подтверждается per-connection выбор механизма и
// capability downgrade на не-SCRAM подключении.
func TestPlainMechanism(t *testing.T) {
	broker, user, pass := target(t)
	if os.Getenv(plainEnv) == "" {
		t.Skipf("%s is not set; skipping Kafka SASL/PLAIN test", plainEnv)
	}
	ctx := context.Background()
	ensureFixture(ctx, t, broker, user, pass)
	ad := kafka.New()
	conn := connectionMech(broker, user, pass, "plain")

	// ValidateConnection проходит: Metadata + DescribeAcls, без SCRAM API.
	if err := ad.ValidateConnection(ctx, conn); err != nil {
		t.Fatalf("ValidateConnection over PLAIN: %v", err)
	}

	// Discovery читает topics фикстуры и не падает без запроса SCRAM users.
	snap, err := ad.Discover(ctx, conn)
	if err != nil {
		t.Fatalf("Discover over PLAIN: %v", err)
	}
	res := map[string]bool{}
	for _, r := range snap.Resources {
		res[r.ExternalID] = true
	}
	for _, id := range []string{"topic:" + fixtureTopicA, "topic:" + fixtureTopicB} {
		if !res[id] {
			t.Errorf("resource %q not found in PLAIN discovery", id)
		}
	}

	// Эффективный набор capabilities подключения сужен по живой topology:
	// SCRAM-lifecycle на PLAIN не заявляется вовсе, а ACL-операции и
	// инвентарь остаются (у стенда ACL-авторизатор включён).
	caps := ad.CapabilitiesFor(conn, snap.Topology)
	for _, gone := range []adapter.Capability{
		adapter.CapAccountCreate, adapter.CapAccountDelete, adapter.CapCredentialRotate,
	} {
		if slices.Contains(caps, gone) {
			t.Errorf("capability %q must not be declared on a PLAIN connection: %v", gone, caps)
		}
	}
	for _, kept := range []adapter.Capability{
		adapter.CapInventoryResources, adapter.CapAccessGrant, adapter.CapAccessRevoke,
	} {
		if !slices.Contains(caps, kept) {
			t.Errorf("capability %q must survive on a PLAIN connection: %v", kept, caps)
		}
	}

	// SCRAM-lifecycle недоступен: account.create отклоняется до Apply.
	_, err = ad.Plan(ctx, adapter.DesiredChange{
		Kind:       adapter.ChangeAccountCreate,
		Connection: conn,
		Account:    adapter.Account{Kind: "login", EngineIdentity: "gr_plain_" + adaptertest.RandomHex(t, 4)},
		Credential: &adapter.Credential{Kind: "password", Secret: []byte("pw")},
	})
	if err == nil {
		t.Fatal("account.create over PLAIN must be reported unavailable")
	}
	if !errors.Is(err, adapter.ErrUnsupportedChange) {
		t.Errorf("account.create error = %v, want adapter.ErrUnsupportedChange", err)
	}
	// credential.rotate тоже недоступен.
	rotErr := ad.RotateCredential(ctx, conn,
		adapter.Account{Kind: "login", EngineIdentity: fixtureUser},
		adapter.Credential{Kind: "password", Secret: []byte("pw")})
	if !errors.Is(rotErr, adapter.ErrUnsupportedChange) {
		t.Errorf("RotateCredential over PLAIN error = %v, want adapter.ErrUnsupportedChange", rotErr)
	}

	// ACL-управление доступно: grant/revoke produce на principal без SCRAM
	// credential (ACL привязан к имени principal, а не к учётке).
	aclPrincipal := adapter.Account{Kind: "login", EngineIdentity: "gr_plain_acl_" + adaptertest.RandomHex(t, 4)}
	grant := adapter.DesiredChange{
		Kind: adapter.ChangeGrant, Connection: conn, Account: aclPrincipal,
		Permission: "topic-produce:" + fixtureTopicA,
	}
	revoke := grant
	revoke.Kind = adapter.ChangeRevoke
	t.Cleanup(func() {
		if plan, perr := ad.Plan(context.Background(), revoke); perr == nil {
			_, _ = ad.Apply(context.Background(), *plan)
		}
	})
	adaptertest.PlanApplyVerify(ctx, t, ad, grant)
	adaptertest.PlanApplyVerify(ctx, t, ad, revoke)
}

// TestDiscoverFixture проверяет, что discovery видит объекты фикстуры и верно
// классифицирует топологию, аккаунты и permissions.
func TestDiscoverFixture(t *testing.T) {
	broker, user, pass := target(t)
	ctx := context.Background()
	ensureFixture(ctx, t, broker, user, pass)

	snap, err := kafka.New().Discover(ctx, connection(broker, user, pass))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	// Одноузловая Redpanda — standalone; под GRANTOR_TEST_CLUSTERS harness
	// присоединяет к цели второй брокер, и та же цель становится cluster.
	if want := wantKafkaTopology(); snap.Topology["topology"] != want {
		t.Errorf("topology = %v, want %s", snap.Topology["topology"], want)
	}
	if !kafkaClustered() && snap.Topology["broker_count"] != 1 {
		t.Errorf("broker_count = %v, want 1", snap.Topology["broker_count"])
	}

	resources := map[string]adapter.ObservedResource{}
	for _, r := range snap.Resources {
		resources[r.ExternalID] = r
		if strings.HasPrefix(r.Name, "_") {
			t.Errorf("internal topic %q must not be discovered", r.Name)
		}
	}
	for _, id := range []string{"topic:" + fixtureTopicA, "topic:" + fixtureTopicB} {
		r, ok := resources[id]
		if !ok {
			t.Errorf("resource %q not found", id)
			continue
		}
		if r.Kind != "topic" || r.Fingerprint == "" {
			t.Errorf("resource %q = %+v, want kind topic with fingerprint", id, r)
		}
	}

	accounts := map[string]adapter.ObservedAccount{}
	for _, a := range snap.Accounts {
		accounts[a.EngineIdentity] = a
	}
	svc, ok := accounts[fixtureUser]
	if !ok {
		t.Fatalf("account %q not found", fixtureUser)
	}
	if svc.Kind != "login" || svc.Disabled {
		t.Errorf("account %q = %+v, want active login", fixtureUser, svc)
	}
	if svc.Attributes["has_scram_credential"] != true {
		t.Errorf("account %q must have has_scram_credential=true", fixtureUser)
	}
	if _, ok := accounts[user]; !ok {
		t.Errorf("admin account %q not found", user)
	}

	perms := map[string]adapter.ObservedPermission{}
	for _, p := range snap.Permissions {
		perms[p.ExternalID] = p
	}
	if admin, ok := perms["cluster-admin"]; !ok || !admin.Dangerous || !admin.Assignable {
		t.Error("permission cluster-admin must exist, be assignable and dangerous")
	}
	if produce, ok := perms["topic-produce:"+fixtureTopicA]; !ok || produce.Dangerous || !produce.Assignable {
		t.Error("permission topic-produce:app-topic-a must exist, be assignable and non-dangerous")
	}
	if consume, ok := perms["topic-consume:"+fixtureTopicB]; !ok || consume.Dangerous || !consume.Assignable {
		t.Error("permission topic-consume:app-topic-b must exist, be assignable and non-dangerous")
	}
}

// TestTopologyStandalone проверяет определение standalone на одноузловом
// брокере (multi-broker cluster проверяется юнит-тестом по canned metadata,
// а живьём — TestTopologyCluster под GRANTOR_TEST_CLUSTERS).
func TestTopologyStandalone(t *testing.T) {
	broker, user, pass := target(t)
	if kafkaClustered() {
		t.Skipf("%s is set: the target broker is clustered; see TestTopologyCluster", kafkaClusterEnv)
	}
	ctx := context.Background()
	snap, err := kafka.New().Discover(ctx, connection(broker, user, pass))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if snap.Topology["topology"] != "standalone" {
		t.Errorf("topology = %v, want standalone", snap.Topology["topology"])
	}
	if snap.Topology["broker_count"] != 1 {
		t.Errorf("broker_count = %v, want 1", snap.Topology["broker_count"])
	}
}

// login выполняет SASL/SCRAM-подключение указанным пользователем и запрашивает
// metadata; возвращает nil при успешной аутентификации. Пароль не печатается.
func login(ctx context.Context, t *testing.T, broker, user, pass string) error {
	t.Helper()
	adm, closeFn := adminKadmClient(t, broker, user, pass)
	defer closeFn()
	loginCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	_, err := adm.BrokerMetadata(loginCtx)
	return err
}

// produce пытается отправить одну запись в topic указанным пользователем и
// возвращает ошибку доставки (nil = запись принята брокером).
func produce(ctx context.Context, t *testing.T, broker, user, pass, topic string) error {
	t.Helper()
	kcl, err := kgo.NewClient(
		kgo.SeedBrokers(broker),
		kgo.DialTimeout(10*time.Second),
		kgo.SASL(scram.Auth{User: user, Pass: pass}.AsSha256Mechanism()),
		kgo.RecordDeliveryTimeout(20*time.Second),
	)
	if err != nil {
		t.Fatalf("create producer client: %v", err)
	}
	defer kcl.Close()
	produceCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return kcl.ProduceSync(produceCtx, &kgo.Record{Topic: topic, Value: []byte("grantor-test")}).FirstErr()
}

// TestAccountLifecycle прогоняет полный жизненный цикл пользователя:
// create -> login работает -> rotate (новый пароль работает, старый — нет) ->
// grant topic-produce -> ACL виден и produce реально работает -> disable
// (DENY-маркер: produce отклоняется, ALLOW ACL сохранены) -> enable (produce
// снова работает без re-grant) -> revoke (produce отклоняется) -> delete
// (login невозможен, ACL удалены).
func TestAccountLifecycle(t *testing.T) {
	broker, adminUser, adminPass := target(t)
	ctx := context.Background()
	ensureFixture(ctx, t, broker, adminUser, adminPass)
	conn := connection(broker, adminUser, adminPass)
	ad := kafka.New()

	user := "gr_tmp_" + adaptertest.RandomHex(t, 4)
	account := adapter.Account{Kind: "login", EngineIdentity: user}
	t.Cleanup(func() {
		// Идемпотентная зачистка на случай падения теста посередине.
		plan, err := ad.Plan(context.Background(), adapter.DesiredChange{
			Kind: adapter.ChangeAccountDelete, Connection: conn, Account: account,
		})
		if err == nil {
			_, _ = ad.Apply(context.Background(), *plan)
		}
	})

	cred, err := ad.GenerateCredential(ctx, adapter.CredentialPolicy{})
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	adaptertest.PlanApplyVerify(ctx, t, ad, adapter.DesiredChange{
		Kind:       adapter.ChangeAccountCreate,
		Connection: conn,
		Account:    account,
		Credential: cred,
	})
	// Повтор создания отклоняется: существующая identity не присваивается
	// даже собственной операцией — идемпотентность повтора обеспечивает ядро
	// (см. adaptertest.Run/AccountCreateRefusesExistingIdentity).
	if _, err := ad.Plan(ctx, adapter.DesiredChange{
		Kind:       adapter.ChangeAccountCreate,
		Connection: conn,
		Account:    account,
		Credential: cred,
	}); !errors.Is(err, adapter.ErrExternalIdentityConflict) {
		t.Fatalf("repeated account.create error = %v, want ErrExternalIdentityConflict", err)
	}

	if err := login(ctx, t, broker, user, string(cred.Secret)); err != nil {
		t.Fatalf("login with generated password: %v", err)
	}
	if err := ad.ProveCredential(ctx, conn, account, *cred); err != nil {
		t.Fatalf("ProveCredential with generated password: %v", err)
	}

	// Ротация пароля: новый работает, старый — нет.
	rotated, err := ad.GenerateCredential(ctx, adapter.CredentialPolicy{})
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	if err := ad.RotateCredential(ctx, conn, account, *rotated); err != nil {
		t.Fatalf("RotateCredential: %v", err)
	}
	if err := login(ctx, t, broker, user, string(rotated.Secret)); err != nil {
		t.Fatalf("login with rotated password: %v", err)
	}
	if err := ad.ProveCredential(ctx, conn, account, *rotated); err != nil {
		t.Fatalf("ProveCredential with rotated password: %v", err)
	}
	if err := ad.ProveCredential(ctx, conn, account, *cred); !errors.Is(err, adapter.ErrExternalIdentityConflict) {
		t.Fatalf("ProveCredential with old password: error = %v, want ErrExternalIdentityConflict", err)
	}
	if err := login(ctx, t, broker, user, string(cred.Secret)); err == nil {
		t.Fatal("login with old password must fail after rotation")
	}

	// Grant produce: ACL наблюдаем в discovery, produce реально работает.
	grant := func(permission string) adapter.DesiredChange {
		return adapter.DesiredChange{
			Kind: adapter.ChangeGrant, Connection: conn, Account: account, Permission: permission,
		}
	}
	adaptertest.PlanApplyVerify(ctx, t, ad, grant("topic-produce:"+fixtureTopicA))
	adaptertest.PlanApplyVerify(ctx, t, ad, grant("topic-produce:"+fixtureTopicA)) // повтор — StepSkipped

	snap, err := ad.Discover(ctx, conn)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if !hasBinding(snap, user, "topic-produce:"+fixtureTopicA) {
		t.Fatalf("binding %s -> topic-produce:%s not found after grant", user, fixtureTopicA)
	}
	if err := produce(ctx, t, broker, user, string(rotated.Secret), fixtureTopicA); err != nil {
		t.Fatalf("produce after grant: %v", err)
	}

	// Disable: DENY-маркер блокирует операции, ALLOW ACL сохраняются.
	disable := adapter.DesiredChange{Kind: adapter.ChangeAccountDisable, Connection: conn, Account: account}
	adaptertest.PlanApplyVerify(ctx, t, ad, disable)
	adaptertest.PlanApplyVerify(ctx, t, ad, disable) // idempotent
	if err := produce(ctx, t, broker, user, string(rotated.Secret), fixtureTopicA); err == nil {
		t.Fatal("disabled user must not be able to produce")
	}
	snap, err = ad.Discover(ctx, conn)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if acc, ok := findAccount(snap, user); !ok || !acc.Disabled {
		t.Errorf("account %q must be observed disabled, got %+v", user, acc)
	}
	if !hasBinding(snap, user, "topic-produce:"+fixtureTopicA) {
		t.Error("ALLOW ACLs must survive disable (non-lossy model)")
	}

	// Enable: produce снова работает без повторного grant.
	enable := adapter.DesiredChange{Kind: adapter.ChangeAccountEnable, Connection: conn, Account: account}
	adaptertest.PlanApplyVerify(ctx, t, ad, enable)
	adaptertest.PlanApplyVerify(ctx, t, ad, enable) // idempotent
	if err := produce(ctx, t, broker, user, string(rotated.Secret), fixtureTopicA); err != nil {
		t.Fatalf("produce after enable (ACLs must be preserved): %v", err)
	}

	// Revoke: produce отклоняется авторизацией.
	revoke := grant("topic-produce:" + fixtureTopicA)
	revoke.Kind = adapter.ChangeRevoke
	adaptertest.PlanApplyVerify(ctx, t, ad, revoke)
	adaptertest.PlanApplyVerify(ctx, t, ad, revoke) // повтор — StepSkipped
	if err := produce(ctx, t, broker, user, string(rotated.Secret), fixtureTopicA); err == nil {
		t.Fatal("produce after revoke must fail")
	}

	// Consume bundle: grant/revoke на второй topic.
	adaptertest.PlanApplyVerify(ctx, t, ad, grant("topic-consume:"+fixtureTopicB))
	revokeConsume := grant("topic-consume:" + fixtureTopicB)
	revokeConsume.Kind = adapter.ChangeRevoke
	adaptertest.PlanApplyVerify(ctx, t, ad, revokeConsume)

	// Delete и его идемпотентность: SCRAM credential и ACL исчезают.
	adaptertest.PlanApplyVerify(ctx, t, ad, adapter.DesiredChange{
		Kind: adapter.ChangeAccountDelete, Connection: conn, Account: account,
	})
	adaptertest.PlanApplyVerify(ctx, t, ad, adapter.DesiredChange{
		Kind: adapter.ChangeAccountDelete, Connection: conn, Account: account,
	})
	if err := login(ctx, t, broker, user, string(rotated.Secret)); err == nil {
		t.Fatal("login must fail after delete")
	}
	if err := ad.RotateCredential(ctx, conn, account, *rotated); err == nil {
		t.Error("RotateCredential must fail for a deleted user")
	} else if !errors.Is(err, adapter.ErrNotFound) {
		t.Errorf("RotateCredential error = %v, want adapter.ErrNotFound", err)
	}
}

// TestValidateConnectionPrivilegeGate проверяет матрицу минимальных привилегий
// (R4): администратор проходит валидацию, а обычный SCRAM-пользователь без
// cluster-ACL (аутентификация работает, DescribeAcls — нет) отклоняется с
// adapter.InsufficientPrivilegeError, называющим отсутствующую привилегию и
// не содержащим пароль.
func TestValidateConnectionPrivilegeGate(t *testing.T) {
	broker, adminUser, adminPass := target(t)
	ctx := context.Background()
	ad := kafka.New()

	// Positive: настоящий администратор проходит проверку привилегий.
	if err := ad.ValidateConnection(ctx, connection(broker, adminUser, adminPass)); err != nil {
		t.Fatalf("ValidateConnection with privileged admin: %v", err)
	}

	// Negative: SCRAM-пользователь без каких-либо cluster-ACL.
	probe := "gr_probe_" + adaptertest.RandomHex(t, 4)
	probePass := "probe" + adaptertest.RandomHex(t, 8)
	adm, closeFn := adminKadmClient(t, broker, adminUser, adminPass)
	defer closeFn()
	altered, err := adm.AlterUserSCRAMs(ctx, nil, []kadm.UpsertSCRAM{{
		User: probe, Mechanism: kadm.ScramSha256, Iterations: 4096, Password: probePass,
	}})
	if err != nil {
		t.Fatalf("create probe user: %v", err)
	}
	if err := altered.Error(); err != nil {
		t.Fatalf("create probe user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = adm.AlterUserSCRAMs(context.Background(),
			[]kadm.DeleteSCRAM{{User: probe, Mechanism: kadm.ScramSha256}}, nil)
	})

	err = ad.ValidateConnection(ctx, connection(broker, probe, probePass))
	if err == nil {
		t.Fatal("ValidateConnection must reject an admin without cluster ACL privileges")
	}
	var pe *adapter.InsufficientPrivilegeError
	if !errors.As(err, &pe) {
		t.Fatalf("error = %v, want *adapter.InsufficientPrivilegeError", err)
	}
	if !errors.Is(err, adapter.ErrInsufficientAdminPrivilege) {
		t.Error("error must wrap adapter.ErrInsufficientAdminPrivilege")
	}
	if !strings.Contains(pe.Missing, "cluster") {
		t.Errorf("missing = %q, want it to mention cluster privileges", pe.Missing)
	}
	if strings.Contains(err.Error(), probePass) {
		t.Error("error message leaks the probe password")
	}
}

// hasBinding сообщает, есть ли в snapshot binding account -> permission.
func hasBinding(snap *adapter.Snapshot, identity, permission string) bool {
	for _, b := range snap.Bindings {
		if b.AccountEngineIdentity == identity && b.PermissionExternalID == permission {
			return true
		}
	}
	return false
}

// findAccount возвращает наблюдаемый аккаунт по engine identity.
func findAccount(snap *adapter.Snapshot, identity string) (adapter.ObservedAccount, bool) {
	for _, a := range snap.Accounts {
		if a.EngineIdentity == identity {
			return a, true
		}
	}
	return adapter.ObservedAccount{}, false
}

// principalACLSet читает ACL principal НЕЗАВИСИМО от adapter: собственным
// kadm-клиентом, тем же запросом DescribeAcls, который делает rpk acl list
// (rpk живёт в контейнере брокера и из тест-контейнера недоступен, поэтому
// «нативная» проверка выполняется прямым Kafka Admin API). Записи
// нормализуются в строки "<resource>:<name>:<operation>:<permission>".
func principalACLSet(ctx context.Context, t *testing.T, adm *kadm.Client, user string) map[string]bool {
	t.Helper()
	principal := "User:" + user
	b := kadm.NewACLs().
		AnyResource().
		ResourcePatternType(kadm.ACLPatternAny).
		Operations(kadm.OpAny).
		Allow(principal).AllowHosts().
		Deny(principal).DenyHosts()
	results, err := adm.DescribeACLs(ctx, b)
	if err != nil {
		t.Fatalf("describe acls of %q: %v", user, err)
	}
	out := map[string]bool{}
	for _, r := range results {
		if r.Err != nil {
			t.Fatalf("describe acls of %q: %v", user, r.Err)
		}
		for _, d := range r.Described {
			out[strings.ToLower(fmt.Sprintf("%s:%s:%s:%s",
				d.Type.String(), d.Name, d.Operation.String(), d.Permission.String()))] = true
		}
	}
	return out
}

// consume пытается прочитать хотя бы одну запись topic указанным
// пользователем в отдельной consumer group и возвращает ошибку авторизации
// или таймаута (nil = чтение реально работает).
func consume(ctx context.Context, t *testing.T, broker, user, pass, topic, group string) error {
	t.Helper()
	kcl, err := kgo.NewClient(
		kgo.SeedBrokers(broker),
		kgo.DialTimeout(10*time.Second),
		kgo.SASL(scram.Auth{User: user, Pass: pass}.AsSha256Mechanism()),
		kgo.ConsumeTopics(topic),
		kgo.ConsumerGroup(group),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
	)
	if err != nil {
		t.Fatalf("create consumer client: %v", err)
	}
	defer kcl.Close()
	pollCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		fetches := kcl.PollRecords(pollCtx, 1)
		if errs := fetches.Errors(); len(errs) > 0 {
			return errs[0].Err
		}
		if fetches.NumRecords() > 0 {
			return nil
		}
		if pollCtx.Err() != nil {
			return pollCtx.Err()
		}
	}
}

// TestRevokeKeepsOtherPermissions — регрессия на «тихую потерю чужого права»
// при отзыве. ACL bundles Kafka разделяют записи (DESCRIBE на topic — между
// produce и consume того же topic, READ на group "*" — между consume всех
// topics), а решение «что удалить» раньше принималось по состоянию движка:
// неполный ответ DescribeAcls снимал чужое право, и Verify это подтверждал
// зелёным.
//
// Сценарий: у аккаунта два права на одном topic (produce + consume) и consume
// на втором topic. Отзывается одно; остальные обязаны уцелеть — и в ACL
// брокера (нативная проверка независимым клиентом), и функционально (реальные
// produce/consume под учётной записью).
func TestRevokeKeepsOtherPermissions(t *testing.T) {
	broker, adminUser, adminPass := target(t)
	ctx := context.Background()
	ensureFixture(ctx, t, broker, adminUser, adminPass)
	conn := connection(broker, adminUser, adminPass)
	ad := kafka.New()

	adm, closeAdm := adminKadmClient(t, broker, adminUser, adminPass)
	t.Cleanup(closeAdm)

	user := "gr_rev_" + adaptertest.RandomHex(t, 4)
	account := adapter.Account{Kind: "login", EngineIdentity: user}
	t.Cleanup(func() {
		plan, err := ad.Plan(context.Background(), adapter.DesiredChange{
			Kind: adapter.ChangeAccountDelete, Connection: conn, Account: account,
		})
		if err == nil {
			_, _ = ad.Apply(context.Background(), *plan)
		}
	})

	cred, err := ad.GenerateCredential(ctx, adapter.CredentialPolicy{})
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	adaptertest.PlanApplyVerify(ctx, t, ad, adapter.DesiredChange{
		Kind: adapter.ChangeAccountCreate, Connection: conn, Account: account, Credential: cred,
	})
	pass := string(cred.Secret)

	produceA := "topic-produce:" + fixtureTopicA
	consumeA := "topic-consume:" + fixtureTopicA
	consumeB := "topic-consume:" + fixtureTopicB

	// AccountPermissions — desired-набор ТОГО ЖЕ scope после изменения, ровно
	// как его считает ядро (internal/jobs, accountPermissionsAfter).
	access := func(kind adapter.ChangeKind, permission string, accountPerms []string) adapter.DesiredChange {
		return adapter.DesiredChange{
			Kind: kind, Connection: conn, Account: account,
			Permission: permission, AccountPermissions: accountPerms,
		}
	}
	adaptertest.PlanApplyVerify(ctx, t, ad, access(adapter.ChangeGrant, produceA, []string{produceA}))
	adaptertest.PlanApplyVerify(ctx, t, ad, access(adapter.ChangeGrant, consumeA, []string{produceA, consumeA}))
	adaptertest.PlanApplyVerify(ctx, t, ad, access(adapter.ChangeGrant, consumeB, []string{consumeB}))

	// Наполняем оба topic под админом: consume ниже должен что-то прочитать.
	for _, topic := range []string{fixtureTopicA, fixtureTopicB} {
		if err := produce(ctx, t, broker, adminUser, adminPass, topic); err != nil {
			t.Fatalf("seed %q as admin: %v", topic, err)
		}
	}
	if err := consume(ctx, t, broker, user, pass, fixtureTopicA,
		"gr_rev_grp_"+adaptertest.RandomHex(t, 4)); err != nil {
		t.Fatalf("consume %q after grant: %v", fixtureTopicA, err)
	}

	// Отзыв produce на topic A. DESCRIBE на A нужен оставшемуся consume:A
	// (тот же scope — решает desired-состояние), READ на group "*" — consume:B
	// (другой scope).
	adaptertest.PlanApplyVerify(ctx, t, ad, access(adapter.ChangeRevoke, produceA, []string{consumeA}))

	acls := principalACLSet(ctx, t, adm, user)
	for _, want := range []string{
		"topic:" + fixtureTopicA + ":read:allow",
		"topic:" + fixtureTopicA + ":describe:allow",
		"topic:" + fixtureTopicB + ":read:allow",
		"topic:" + fixtureTopicB + ":describe:allow",
		"group:*:read:allow",
	} {
		if !acls[want] {
			t.Errorf("acl %q lost by revoking %s; acls = %v", want, produceA, acls)
		}
	}
	if got := "topic:" + fixtureTopicA + ":write:allow"; acls[got] {
		t.Errorf("acl %q must be gone after revoking %s", got, produceA)
	}

	// Функциональная проверка: produce отклонён, consume обоих topics работает.
	if err := produce(ctx, t, broker, user, pass, fixtureTopicA); err == nil {
		t.Errorf("produce to %q must fail after revoke", fixtureTopicA)
	}
	for _, topic := range []string{fixtureTopicA, fixtureTopicB} {
		if err := consume(ctx, t, broker, user, pass, topic,
			"gr_rev_grp_"+adaptertest.RandomHex(t, 4)); err != nil {
			t.Errorf("consume %q must still work after revoking %s: %v", topic, produceA, err)
		}
	}

	// Отзыв consume на topic A: READ на group "*" обязан пережить отзыв, пока
	// у аккаунта остаётся consume другого topic (cross-scope запись, которой
	// нет в desired-наборе того же scope).
	adaptertest.PlanApplyVerify(ctx, t, ad, access(adapter.ChangeRevoke, consumeA, nil))

	acls = principalACLSet(ctx, t, adm, user)
	if !acls["group:*:read:allow"] {
		t.Errorf("group read lost by revoking %s while %s remains; acls = %v", consumeA, consumeB, acls)
	}
	for _, gone := range []string{
		"topic:" + fixtureTopicA + ":read:allow",
		"topic:" + fixtureTopicA + ":describe:allow",
	} {
		if acls[gone] {
			t.Errorf("acl %q must be gone after revoking %s", gone, consumeA)
		}
	}
	if err := consume(ctx, t, broker, user, pass, fixtureTopicB,
		"gr_rev_grp_"+adaptertest.RandomHex(t, 4)); err != nil {
		t.Errorf("consume %q must still work after revoking %s: %v", fixtureTopicB, consumeA, err)
	}
}

// TestRevokeUsesDesiredStateNotEngineState — живой сценарий, который
// различает старое и новое поведение. Часть ACL желаемого права аккаунта
// пропала с брокера (ручное вмешательство, потерянная запись, неполный ответ
// DescribeAcls). Реконструкция «оставить то, что видно в движке» в этот момент
// доламывала чужое право: DESCRIBE удалялся вместе с отзываемым produce,
// потому что READ уже не наблюдался. Решение по desired-состоянию ядра
// оставляет DESCRIBE, а усиленный Verify не подтверждает результат зелёным —
// недостача остальных прав аккаунта видна.
func TestRevokeUsesDesiredStateNotEngineState(t *testing.T) {
	broker, adminUser, adminPass := target(t)
	ctx := context.Background()
	ensureFixture(ctx, t, broker, adminUser, adminPass)
	conn := connection(broker, adminUser, adminPass)
	ad := kafka.New()

	adm, closeAdm := adminKadmClient(t, broker, adminUser, adminPass)
	t.Cleanup(closeAdm)

	user := "gr_drift_" + adaptertest.RandomHex(t, 4)
	account := adapter.Account{Kind: "login", EngineIdentity: user}
	t.Cleanup(func() {
		plan, err := ad.Plan(context.Background(), adapter.DesiredChange{
			Kind: adapter.ChangeAccountDelete, Connection: conn, Account: account,
		})
		if err == nil {
			_, _ = ad.Apply(context.Background(), *plan)
		}
	})

	produceB := "topic-produce:" + fixtureTopicB
	consumeB := "topic-consume:" + fixtureTopicB
	access := func(kind adapter.ChangeKind, permission string, accountPerms []string) adapter.DesiredChange {
		return adapter.DesiredChange{
			Kind: kind, Connection: conn, Account: account,
			Permission: permission, AccountPermissions: accountPerms,
		}
	}
	adaptertest.PlanApplyVerify(ctx, t, ad, access(adapter.ChangeGrant, consumeB, []string{consumeB}))
	adaptertest.PlanApplyVerify(ctx, t, ad, access(adapter.ChangeGrant, produceB, []string{consumeB, produceB}))

	// Расхождение: READ на topic снят на брокере мимо grantor, а binding
	// consume остаётся желаемым в control plane.
	if _, err := adm.DeleteACLs(ctx, kadm.NewACLs().
		ResourcePatternType(kadm.ACLPatternLiteral).
		Topics(fixtureTopicB).
		Operations(kadm.OpRead).
		Allow("User:"+user).AllowHosts(wildcardHost)); err != nil {
		t.Fatalf("simulate acl drift: %v", err)
	}

	revoke := access(adapter.ChangeRevoke, produceB, []string{consumeB})
	plan, err := ad.Plan(ctx, revoke)
	if err != nil {
		t.Fatalf("Plan(revoke): %v", err)
	}
	res, err := ad.Apply(ctx, *plan)
	if err != nil {
		t.Fatalf("Apply(revoke): %v", err)
	}
	for _, s := range res.Steps {
		if s.Status != adapter.StepApplied && s.Status != adapter.StepSkipped {
			t.Fatalf("Apply(revoke): step %q finished with %q: %s", s.Step.Kind, s.Status, s.Error)
		}
	}

	acls := principalACLSet(ctx, t, adm, user)
	if want := "topic:" + fixtureTopicB + ":describe:allow"; !acls[want] {
		t.Errorf("acl %q must survive: the desired %s still needs it; acls = %v", want, consumeB, acls)
	}
	if gone := "topic:" + fixtureTopicB + ":write:allow"; acls[gone] {
		t.Errorf("acl %q must be gone after revoking %s", gone, produceB)
	}

	ver, err := ad.Verify(ctx, *plan)
	if err != nil {
		t.Fatalf("Verify(revoke): %v", err)
	}
	if ver.Verified {
		t.Errorf("Verify must not be green while acls of the remaining %s are missing: %s",
			consumeB, ver.Details)
	}
}
