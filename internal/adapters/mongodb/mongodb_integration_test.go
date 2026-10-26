//go:build integration

// Интеграционные тесты MongoDB adapter (discovery и мутации). Требуют
// «целевой» MongoDB: URI админского подключения задаётся через
// GRANTOR_TEST_MONGO_URI (standalone), иначе тесты пропускаются. Опциональный
// GRANTOR_TEST_MONGO_RS_URI указывает на replica set для проверки topology.
// Фикстура создаётся идемпотентно, поэтому тесты можно запускать многократно
// над одним и тем же кластером.
//
// URI и пароли в логи не выводятся: секретный материал берётся из URI и
// передаётся драйверу полями options, но не печатается.
package mongodb_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adaptertest"
	"github.com/ArtefactoO/grantor/internal/adapters/mongodb"
	coreconnections "github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/mongodbconfig"
)

const (
	// mongoEnv — переменная окружения с URI standalone MongoDB (admin).
	mongoEnv = "GRANTOR_TEST_MONGO_URI"
	// mongoRSEnv — опциональный URI replica set для проверки topology.
	mongoRSEnv = "GRANTOR_TEST_MONGO_RS_URI"
	// appDatabase — база фикстуры.
	appDatabase   = "appdb"
	adminDatabase = "admin"
)

// TestContract прогоняет общий contract suite поверх целевого MongoDB. Manifest
// объявляет access.grant/revoke, поэтому suite выполняет grant/revoke тесты:
// фикстура даёт активные login-аккаунты и две assignable не-dangerous роли
// (read и readWrite на appdb).
func TestContract(t *testing.T) {
	uri := targetURI(t)
	ctx := context.Background()
	ensureFixture(ctx, t, uri)
	conn := connectionFromURI(t, uri)

	adaptertest.Run(t, adaptertest.Harness{
		New: func(*testing.T) (adapter.Adapter, adapter.Connection) {
			return mongodb.New(), conn
		},
	})
}

// TestDiscoverFixture проверяет, что discovery видит объекты фикстуры и верно
// классифицирует topology, аккаунты, роли и bindings.
func TestDiscoverFixture(t *testing.T) {
	uri := targetURI(t)
	ctx := context.Background()
	ensureFixture(ctx, t, uri)

	snap, err := mongodb.New().Discover(ctx, connectionFromURI(t, uri))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if snap.Topology["topology"] != "standalone" {
		t.Errorf("topology = %v, want standalone", snap.Topology["topology"])
	}

	resources := map[string]adapter.ObservedResource{}
	for _, r := range snap.Resources {
		resources[r.ExternalID] = r
	}
	wantResources := []struct {
		id   string
		kind string
	}{
		{id: "db:appdb", kind: "database"},
		{id: "collection:appdb.events", kind: "collection"},
		{id: "view:appdb.recent_events", kind: "view"},
	}
	for _, want := range wantResources {
		r, ok := resources[want.id]
		if !ok {
			t.Errorf("resource %q not found", want.id)
			continue
		}
		if r.Kind != want.kind {
			t.Errorf("resource %q kind = %q, want %q", want.id, r.Kind, want.kind)
		}
		if r.Fingerprint == "" {
			t.Errorf("resource %q has empty fingerprint", want.id)
		}
	}
	// Индекс на events с родителем-коллекцией.
	foundIndex := false
	for _, r := range snap.Resources {
		if r.Kind == "index" && r.ParentExternalID == "collection:appdb.events" {
			foundIndex = true
			break
		}
	}
	if !foundIndex {
		t.Error("no index resource with parent collection:appdb.events")
	}

	accounts := map[string]adapter.ObservedAccount{}
	for _, a := range snap.Accounts {
		accounts[a.EngineIdentity] = a
	}
	if svc, ok := accounts["svc_app@appdb"]; !ok {
		t.Error("account svc_app@appdb not found")
	} else if svc.Kind != "login" {
		t.Errorf("account svc_app@appdb kind = %q, want login", svc.Kind)
	}
	if _, ok := accounts["reader@admin"]; !ok {
		t.Error("account reader@admin not found (multi-db assignment)")
	}

	perms := map[string]adapter.ObservedPermission{}
	for _, p := range snap.Permissions {
		perms[p.ExternalID] = p
	}
	rw, ok := perms["role:appdb.readWrite"]
	if !ok {
		t.Fatal("permission role:appdb.readWrite not found")
	}
	if !rw.Assignable || rw.Dangerous {
		t.Errorf("role:appdb.readWrite = %+v, want assignable non-dangerous", rw)
	}
	if _, ok := perms["role:appdb.read"]; !ok {
		t.Error("permission role:appdb.read not found")
	}

	if !hasBinding(snap, "svc_app@appdb", "role:appdb.readWrite") {
		t.Error("binding svc_app@appdb -> role:appdb.readWrite not found")
	}
	if !hasBinding(snap, "reader@admin", "role:appdb.read") {
		t.Error("binding reader@admin -> role:appdb.read not found (multi-db)")
	}
}

// TestDiscoverReplicaSetTopology проверяет detection replica set, если задан
// GRANTOR_TEST_MONGO_RS_URI.
func TestDiscoverReplicaSetTopology(t *testing.T) {
	uri := os.Getenv(mongoRSEnv)
	if uri == "" {
		t.Skipf("%s is not set; skipping replica set topology test", mongoRSEnv)
	}
	ctx := context.Background()

	snap, err := mongodb.New().Discover(ctx, connectionFromURI(t, uri))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if snap.Topology["topology"] != "replica_set" {
		t.Errorf("topology = %v, want replica_set", snap.Topology["topology"])
	}
	if name, _ := snap.Topology["set_name"].(string); name == "" {
		t.Error("replica set topology must expose non-empty set_name")
	}
	if id, _ := snap.Topology["replica_set_id"].(string); id == "" {
		t.Error("replica set topology must expose immutable replica_set_id")
	}
	if identity := mongoSnapshotTargetIdentity(t, snap); !strings.HasPrefix(identity, "mongodb:replica-set:") {
		t.Errorf("replica set target identity = %q", identity)
	}
	if snap.Topology["writable_primary"] != true {
		t.Errorf("replica set writable_primary = %v, want true", snap.Topology["writable_primary"])
	}
}

// TestAccountLifecycle прогоняет полный жизненный цикл SCRAM-аккаунта на appdb:
// create со сгенерированным паролем -> реальный вход этим пользователем ->
// ротация (новый пароль работает, старый — нет) -> grant read@appdb -> delete.
func TestAccountLifecycle(t *testing.T) {
	uri := targetURI(t)
	ctx := context.Background()
	ensureFixture(ctx, t, uri)
	conn := connectionFromURI(t, uri)
	ad := mongodb.New()

	user := "gr_tmp_" + adaptertest.RandomHex(t, 4)
	identity := user + "@" + appDatabase
	account := adapter.Account{Kind: "login", EngineIdentity: identity}
	t.Cleanup(func() { dropUserQuietly(uri, appDatabase, user) })

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
	if err := tryLogin(ctx, t, uri, appDatabase, user, string(cred.Secret)); err != nil {
		t.Fatalf("login with generated password: %v", err)
	}

	rotated, err := ad.GenerateCredential(ctx, adapter.CredentialPolicy{})
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	if err := ad.RotateCredential(ctx, conn, account, *rotated); err != nil {
		t.Fatalf("RotateCredential: %v", err)
	}
	if err := tryLogin(ctx, t, uri, appDatabase, user, string(rotated.Secret)); err != nil {
		t.Fatalf("login with rotated password: %v", err)
	}
	if err := ad.ProveCredential(ctx, conn, account, *rotated); err != nil {
		t.Fatalf("ProveCredential with exact identity/password: %v", err)
	}
	wrong := *rotated
	wrong.Secret = []byte("definitely-wrong-password")
	if err := ad.ProveCredential(ctx, conn, account, wrong); !errors.Is(err, adapter.ErrExternalIdentityConflict) {
		t.Fatalf("ProveCredential wrong password error = %v, want ErrExternalIdentityConflict", err)
	}
	if err := tryLogin(ctx, t, uri, appDatabase, user, string(cred.Secret)); err == nil {
		t.Fatal("login with old password must fail after rotation")
	}

	// grant роли новому пользователю и проверка идемпотентности.
	grant := adapter.DesiredChange{
		Kind:       adapter.ChangeGrant,
		Connection: conn,
		Account:    account,
		Permission: "role:appdb.read",
	}
	adaptertest.PlanApplyVerify(ctx, t, ad, grant)
	adaptertest.PlanApplyVerify(ctx, t, ad, grant) // повтор — StepSkipped

	adaptertest.PlanApplyVerify(ctx, t, ad, adapter.DesiredChange{
		Kind:       adapter.ChangeAccountDelete,
		Connection: conn,
		Account:    account,
	})

	// После delete пользователь недоступен; rotate возвращает ErrNotFound.
	if err := ad.RotateCredential(ctx, conn, account, *rotated); err == nil {
		t.Error("RotateCredential must fail for a deleted user")
	}
}

func TestRolePolicyLifecycle(t *testing.T) {
	uri := targetURI(t)
	ctx := context.Background()
	ensureFixture(ctx, t, uri)
	client := adminClient(ctx, t, uri)
	defer func() { _ = client.Disconnect(context.Background()) }()

	role := "gr_policy_" + adaptertest.RandomHex(t, 4)
	t.Cleanup(func() { dropRoleQuietly(uri, appDatabase, role) })
	template := mongodbconfig.Normalize(mongodbconfig.RolePolicyTemplate{
		Key: "policy-" + role, Name: "Integration scoped writer", Description: "Integration fixture",
		RoleName: role, RoleDatabase: appDatabase,
		Privileges: []adapter.MongoRolePrivilege{{
			Resource: adapter.MongoRoleResource{DB: appDatabase, Collection: "events"},
			Actions:  []string{"find", "insert", "update"},
		}},
	})
	conn := connectionFromURI(t, uri)
	conn.Attributes[mongodbconfig.AttributeRolePolicyTemplates] = []mongodbconfig.RolePolicyTemplate{template}
	ad := mongodb.New()

	missingSnapshot, err := ad.Discover(ctx, conn)
	if err != nil {
		t.Fatalf("Discover missing policy: %v", err)
	}
	identity := mongoSnapshotTargetIdentity(t, missingSnapshot)
	missing := findMongoRolePolicy(t, missingSnapshot, "role:"+appDatabase+"."+role)
	if missing.Exact || !missing.ApplySupported || mongoPolicyRoleExists(missing) || missing.Dangerous {
		t.Fatalf("missing policy = %+v", missing)
	}
	if permission := findMongoPermission(t, missingSnapshot, missing.ExternalID); permission.Assignable {
		t.Fatalf("configured missing permission is assignable: %+v", permission)
	}
	if !slices.Contains(ad.CapabilitiesFor(conn, missingSnapshot.Topology), adapter.CapRolePolicyApply) {
		t.Fatal("role.policy.apply capability is not enabled after exact identity/authorization discovery")
	}

	spec := mongodbconfig.Spec(template)
	change := adapter.DesiredChange{
		Kind: adapter.ChangeRolePolicyApply, Connection: conn,
		Permission: missing.ExternalID, RolePolicySpec: &spec,
		ExpectedTargetIdentity: identity,
	}
	plan, err := ad.Plan(ctx, change)
	if err != nil {
		t.Fatalf("Plan create role policy: %v", err)
	}
	result, err := ad.Apply(ctx, *plan)
	if err != nil {
		t.Fatalf("Apply create role policy: %v", err)
	}
	if len(result.Steps) != 1 || result.Steps[0].Status != adapter.StepApplied {
		t.Fatalf("create result = %+v", result)
	}
	verification, err := ad.Verify(ctx, *plan)
	if err != nil || !verification.Verified {
		t.Fatalf("Verify create = %+v, %v", verification, err)
	}

	// Lost-response retry: the same immutable plan converges by exact read and
	// skips instead of issuing a second create/update command.
	retry, err := ad.Apply(ctx, *plan)
	if err != nil {
		t.Fatalf("Apply retry after target success: %v", err)
	}
	if len(retry.Steps) != 1 || retry.Steps[0].Status != adapter.StepSkipped {
		t.Fatalf("retry result = %+v, want StepSkipped", retry)
	}

	exactSnapshot, err := ad.Discover(ctx, conn)
	if err != nil {
		t.Fatalf("Discover exact policy: %v", err)
	}
	exact := findMongoRolePolicy(t, exactSnapshot, missing.ExternalID)
	if !exact.Exact || !mongoPolicyRoleExists(exact) || exact.ObservedFingerprint != exact.ExpectedFingerprint {
		t.Fatalf("exact policy = %+v", exact)
	}
	repeatedSnapshot, err := ad.Discover(ctx, conn)
	if err != nil {
		t.Fatalf("repeated Discover: %v", err)
	}
	repeated := findMongoRolePolicy(t, repeatedSnapshot, missing.ExternalID)
	if !repeated.Exact || repeated.ObservedFingerprint != exact.ObservedFingerprint {
		t.Fatalf("repeated policy = %+v, previous = %+v", repeated, exact)
	}

	// External drift changes the exact direct action set. Discovery must retain
	// one configured policy row and repair must replace the whole definition.
	driftPrivileges := bson.A{bson.D{
		{Key: "resource", Value: bson.D{{Key: "db", Value: appDatabase}, {Key: "collection", Value: "events"}}},
		{Key: "actions", Value: bson.A{"find", "insert", "update", "remove"}},
	}}
	if err := client.Database(appDatabase).RunCommand(ctx, bson.D{
		{Key: "updateRole", Value: role},
		{Key: "privileges", Value: driftPrivileges},
		{Key: "roles", Value: bson.A{}},
		{Key: "writeConcern", Value: bson.D{{Key: "w", Value: "majority"}}},
	}).Err(); err != nil {
		t.Fatalf("inject role policy drift: %v", err)
	}
	driftSnapshot, err := ad.Discover(ctx, conn)
	if err != nil {
		t.Fatalf("Discover drift: %v", err)
	}
	drift := findMongoRolePolicy(t, driftSnapshot, missing.ExternalID)
	if drift.Exact || drift.ObservedFingerprint == drift.ExpectedFingerprint {
		t.Fatalf("drift was not detected: %+v", drift)
	}
	repairPlan, err := ad.Plan(ctx, change)
	if err != nil {
		t.Fatalf("Plan repair: %v", err)
	}
	if _, err := ad.Apply(ctx, *repairPlan); err != nil {
		t.Fatalf("Apply repair: %v", err)
	}
	if verified, err := ad.Verify(ctx, *repairPlan); err != nil || !verified.Verified {
		t.Fatalf("Verify repair = %+v, %v", verified, err)
	}
	repairedSnapshot, err := ad.Discover(ctx, conn)
	if err != nil {
		t.Fatalf("Discover after repair: %v", err)
	}
	repaired := findMongoRolePolicy(t, repairedSnapshot, missing.ExternalID)
	if !repaired.Exact || repaired.ObservedFingerprint != repaired.ExpectedFingerprint {
		t.Fatalf("repaired policy = %+v", repaired)
	}
	stableSnapshot, err := ad.Discover(ctx, conn)
	if err != nil {
		t.Fatalf("second Discover after repair: %v", err)
	}
	stable := findMongoRolePolicy(t, stableSnapshot, missing.ExternalID)
	if !stable.Exact || stable.ObservedFingerprint != repaired.ObservedFingerprint {
		t.Fatalf("post-repair discovery drifted: repaired=%+v stable=%+v", repaired, stable)
	}
}

func TestRolePolicyDependencyDriftCascades(t *testing.T) {
	uri := targetURI(t)
	ctx := context.Background()
	ensureFixture(ctx, t, uri)
	client := adminClient(ctx, t, uri)
	defer func() { _ = client.Disconnect(context.Background()) }()
	ad := mongodb.New()

	baseRole := "gr_base_" + adaptertest.RandomHex(t, 4)
	parentRole := "gr_parent_" + adaptertest.RandomHex(t, 4)
	for _, role := range []string{baseRole, parentRole} {
		role := role
		t.Cleanup(func() { dropRoleQuietly(uri, appDatabase, role) })
	}
	baseTemplate := mongodbconfig.Normalize(mongodbconfig.RolePolicyTemplate{
		Key: "base-" + baseRole, Name: "Base dependency", Description: "Integration fixture",
		RoleName: baseRole, RoleDatabase: appDatabase,
		Privileges: []adapter.MongoRolePrivilege{{
			Resource: adapter.MongoRoleResource{DB: appDatabase, Collection: "events"}, Actions: []string{"find"},
		}},
	})
	parentTemplate := mongodbconfig.Normalize(mongodbconfig.RolePolicyTemplate{
		Key: "parent-" + parentRole, Name: "Parent policy", Description: "Integration fixture",
		RoleName: parentRole, RoleDatabase: appDatabase,
		InheritedRoles: []adapter.MongoRoleRef{{Role: baseRole, DB: appDatabase}},
	})
	catalog := []mongodbconfig.RolePolicyTemplate{baseTemplate, parentTemplate}
	if err := mongodbconfig.Validate(catalog); err != nil {
		t.Fatalf("validate dependency catalog: %v", err)
	}
	conn := connectionFromURI(t, uri)
	conn.Attributes[mongodbconfig.AttributeRolePolicyTemplates] = catalog
	initial, err := ad.Discover(ctx, conn)
	if err != nil {
		t.Fatalf("Discover dependency catalog: %v", err)
	}
	identity := mongoSnapshotTargetIdentity(t, initial)
	baseSpec := mongodbconfig.Spec(baseTemplate)
	baseChange := adapter.DesiredChange{
		Kind: adapter.ChangeRolePolicyApply, Connection: conn,
		Permission:     "role:" + appDatabase + "." + baseRole,
		RolePolicySpec: &baseSpec, ExpectedTargetIdentity: identity,
	}
	basePlan, err := ad.Plan(ctx, baseChange)
	if err != nil {
		t.Fatalf("Plan base dependency: %v", err)
	}
	if _, err := ad.Apply(ctx, *basePlan); err != nil {
		t.Fatalf("Apply base dependency: %v", err)
	}
	parentSpec := mongodbconfig.Spec(parentTemplate)
	parentChange := adapter.DesiredChange{
		Kind: adapter.ChangeRolePolicyApply, Connection: conn,
		Permission:     "role:" + appDatabase + "." + parentRole,
		RolePolicySpec: &parentSpec, ExpectedTargetIdentity: identity,
	}
	parentPlan, err := ad.Plan(ctx, parentChange)
	if err != nil {
		t.Fatalf("Plan parent policy: %v", err)
	}
	if _, err := ad.Apply(ctx, *parentPlan); err != nil {
		t.Fatalf("Apply parent policy: %v", err)
	}
	exactSnapshot, err := ad.Discover(ctx, conn)
	if err != nil {
		t.Fatalf("Discover exact dependency policies: %v", err)
	}
	if base := findMongoRolePolicy(t, exactSnapshot, baseChange.Permission); !base.Exact {
		t.Fatalf("base policy is not exact: %+v", base)
	}
	if parent := findMongoRolePolicy(t, exactSnapshot, parentChange.Permission); !parent.Exact {
		t.Fatalf("parent policy is not exact: %+v", parent)
	}

	if err := client.Database(appDatabase).RunCommand(ctx, bson.D{
		{Key: "updateRole", Value: baseRole},
		{Key: "privileges", Value: bson.A{bson.D{
			{Key: "resource", Value: bson.D{{Key: "db", Value: appDatabase}, {Key: "collection", Value: "events"}}},
			{Key: "actions", Value: bson.A{"find", "insert"}},
		}}},
		{Key: "roles", Value: bson.A{}},
		{Key: "writeConcern", Value: bson.D{{Key: "w", Value: "majority"}}},
	}).Err(); err != nil {
		t.Fatalf("inject dependency drift: %v", err)
	}
	driftSnapshot, err := ad.Discover(ctx, conn)
	if err != nil {
		t.Fatalf("Discover dependency drift: %v", err)
	}
	baseDrift := findMongoRolePolicy(t, driftSnapshot, baseChange.Permission)
	parentDrift := findMongoRolePolicy(t, driftSnapshot, parentChange.Permission)
	if baseDrift.Exact || parentDrift.Exact || parentDrift.ApplySupported ||
		parentDrift.BlockedReason != "inherited_policy_drift" {
		t.Fatalf("dependency drift did not cascade: base=%+v parent=%+v", baseDrift, parentDrift)
	}
	if _, err := ad.Plan(ctx, parentChange); !errors.Is(err, adapter.ErrUnsupportedChange) {
		t.Fatalf("Plan parent with drifted dependency error = %v, want ErrUnsupportedChange", err)
	}

	baseRepair, err := ad.Plan(ctx, baseChange)
	if err != nil {
		t.Fatalf("Plan base repair: %v", err)
	}
	if _, err := ad.Apply(ctx, *baseRepair); err != nil {
		t.Fatalf("Apply base repair: %v", err)
	}
	repairedSnapshot, err := ad.Discover(ctx, conn)
	if err != nil {
		t.Fatalf("Discover after dependency repair: %v", err)
	}
	repairedParent := findMongoRolePolicy(t, repairedSnapshot, parentChange.Permission)
	if !repairedParent.Exact || !repairedParent.ApplySupported || repairedParent.BlockedReason != "" {
		t.Fatalf("parent did not recover after base repair: %+v", repairedParent)
	}
}

func TestRolePolicyExactAdoptDangerRestrictionAndIdentityFence(t *testing.T) {
	uri := targetURI(t)
	ctx := context.Background()
	ensureFixture(ctx, t, uri)
	client := adminClient(ctx, t, uri)
	defer func() { _ = client.Disconnect(context.Background()) }()
	ad := mongodb.New()

	adoptRole := "gr_adopt_" + adaptertest.RandomHex(t, 4)
	dangerRole := "gr_danger_" + adaptertest.RandomHex(t, 4)
	restrictedRole := "gr_restrict_" + adaptertest.RandomHex(t, 4)
	identityRole := "gr_identity_" + adaptertest.RandomHex(t, 4)
	for _, role := range []string{adoptRole, dangerRole, restrictedRole, identityRole} {
		role := role
		t.Cleanup(func() { dropRoleQuietly(uri, roleDatabaseForName(role, dangerRole), role) })
	}

	adoptTemplate := mongodbconfig.Normalize(mongodbconfig.RolePolicyTemplate{
		Key: "adopt-" + adoptRole, Name: "Adopt exact", Description: "Integration fixture",
		RoleName: adoptRole, RoleDatabase: appDatabase,
		Privileges: []adapter.MongoRolePrivilege{{
			Resource: adapter.MongoRoleResource{DB: appDatabase, Collection: "events"},
			Actions:  []string{"find"},
		}},
	})
	dangerTemplate := mongodbconfig.Normalize(mongodbconfig.RolePolicyTemplate{
		Key: "danger-" + dangerRole, Name: "Dangerous cluster policy", Description: "Integration fixture",
		RoleName: dangerRole, RoleDatabase: adminDatabase,
		Privileges: []adapter.MongoRolePrivilege{{
			Resource: adapter.MongoRoleResource{Cluster: true}, Actions: []string{"serverStatus"},
		}},
	})
	restrictedTemplate := mongodbconfig.Normalize(mongodbconfig.RolePolicyTemplate{
		Key: "restricted-" + restrictedRole, Name: "Restricted policy", Description: "Integration fixture",
		RoleName: restrictedRole, RoleDatabase: appDatabase,
		Privileges: []adapter.MongoRolePrivilege{{
			Resource: adapter.MongoRoleResource{DB: appDatabase, Collection: "events"}, Actions: []string{"find"},
		}},
	})
	identityTemplate := restrictedTemplate
	identityTemplate.Key = "identity-" + identityRole
	identityTemplate.Name = "Identity fence"
	identityTemplate.RoleName = identityRole
	if err := mongodbconfig.Validate([]mongodbconfig.RolePolicyTemplate{
		adoptTemplate, dangerTemplate, restrictedTemplate, identityTemplate,
	}); err != nil {
		t.Fatalf("validate integration templates: %v", err)
	}

	createRoleFromTemplate(ctx, t, client, adoptTemplate, nil)
	dangerActual := dangerTemplate
	dangerActual.Privileges = []adapter.MongoRolePrivilege{{
		Resource: adapter.MongoRoleResource{DB: adminDatabase, Collection: "events"},
		Actions:  []string{"find"},
	}}
	createRoleFromTemplate(ctx, t, client, dangerActual, nil)
	createRoleFromTemplate(ctx, t, client, restrictedTemplate, bson.A{
		bson.D{{Key: "clientSource", Value: bson.A{"127.0.0.1"}}},
	})
	conn := connectionFromURI(t, uri)
	conn.Attributes[mongodbconfig.AttributeRolePolicyTemplates] = []mongodbconfig.RolePolicyTemplate{
		adoptTemplate, dangerTemplate, restrictedTemplate, identityTemplate,
	}
	snapshot, err := ad.Discover(ctx, conn)
	if err != nil {
		t.Fatalf("Discover role policy matrix: %v", err)
	}
	identity := mongoSnapshotTargetIdentity(t, snapshot)

	adopt := findMongoRolePolicy(t, snapshot, "role:"+appDatabase+"."+adoptRole)
	if !adopt.Exact || !adopt.ApplySupported || adopt.Dangerous {
		t.Fatalf("adopt candidate = %+v", adopt)
	}
	adoptSpec := mongodbconfig.Spec(adoptTemplate)
	adoptPlan, err := ad.Plan(ctx, adapter.DesiredChange{
		Kind: adapter.ChangeRolePolicyVerify, Connection: conn,
		Permission: adopt.ExternalID, RolePolicySpec: &adoptSpec,
		ExpectedTargetIdentity: identity,
	})
	if err != nil {
		t.Fatalf("Plan exact adopt: %v", err)
	}
	if verified, err := ad.Verify(ctx, *adoptPlan); err != nil || !verified.Verified {
		t.Fatalf("Verify exact adopt = %+v, %v", verified, err)
	}
	wrongVerifyPlan := *adoptPlan
	wrongVerifyPlan.Change.ExpectedTargetIdentity = "mongodb:standalone-process:000000000000000000000000"
	if _, err := ad.Verify(ctx, wrongVerifyPlan); !errors.Is(err, adapter.ErrTargetIdentityConflict) {
		t.Fatalf("Verify wrong target identity error = %v, want ErrTargetIdentityConflict", err)
	}

	danger := findMongoRolePolicy(t, snapshot, "role:"+adminDatabase+"."+dangerRole)
	if !danger.Dangerous || !danger.ApplySupported || danger.Exact {
		t.Fatalf("dangerous desired/safe actual policy = %+v", danger)
	}
	dangerSpec := mongodbconfig.Spec(dangerTemplate)
	dangerChange := adapter.DesiredChange{
		Kind: adapter.ChangeRolePolicyApply, Connection: conn,
		Permission: danger.ExternalID, RolePolicySpec: &dangerSpec,
		ExpectedTargetIdentity: identity,
	}
	dangerPlan, err := ad.Plan(ctx, dangerChange)
	if err != nil {
		t.Fatalf("Plan dangerous policy: %v", err)
	}
	if _, err := ad.Apply(ctx, *dangerPlan); err != nil {
		t.Fatalf("Apply dangerous policy: %v", err)
	}
	if verified, err := ad.Verify(ctx, *dangerPlan); err != nil || !verified.Verified {
		t.Fatalf("Verify dangerous policy = %+v, %v", verified, err)
	}

	restricted := findMongoRolePolicy(t, snapshot, "role:"+appDatabase+"."+restrictedRole)
	if restricted.ApplySupported || restricted.BlockedReason != "role_has_authentication_restrictions" {
		t.Fatalf("restricted policy = %+v", restricted)
	}
	restrictedSpec := mongodbconfig.Spec(restrictedTemplate)
	if _, err := ad.Plan(ctx, adapter.DesiredChange{
		Kind: adapter.ChangeRolePolicyApply, Connection: conn,
		Permission: restricted.ExternalID, RolePolicySpec: &restrictedSpec,
		ExpectedTargetIdentity: identity,
	}); !errors.Is(err, adapter.ErrUnsupportedChange) {
		t.Fatalf("Plan restricted role error = %v, want ErrUnsupportedChange", err)
	}

	identitySpec := mongodbconfig.Spec(identityTemplate)
	wrongIdentity := "mongodb:standalone-process:000000000000000000000000"
	identityChange := adapter.DesiredChange{
		Kind: adapter.ChangeRolePolicyApply, Connection: conn,
		Permission:     "role:" + appDatabase + "." + identityRole,
		RolePolicySpec: &identitySpec, ExpectedTargetIdentity: identity,
	}
	identityPlan, err := ad.Plan(ctx, identityChange)
	if err != nil {
		t.Fatalf("Plan correct target identity: %v", err)
	}
	wrongApplyPlan := *identityPlan
	wrongApplyPlan.Change.ExpectedTargetIdentity = wrongIdentity
	if _, err := ad.Apply(ctx, wrongApplyPlan); !errors.Is(err, adapter.ErrTargetIdentityConflict) {
		t.Fatalf("Apply wrong target identity error = %v, want ErrTargetIdentityConflict", err)
	}
	identityChange.ExpectedTargetIdentity = wrongIdentity
	if _, err := ad.Plan(ctx, identityChange); !errors.Is(err, adapter.ErrTargetIdentityConflict) {
		t.Fatalf("Plan wrong target identity error = %v, want ErrTargetIdentityConflict", err)
	}
	if roleExists(ctx, t, client, appDatabase, identityRole) {
		t.Fatal("identity mismatch mutated the target role")
	}
}

func TestRolePolicyManagementPrivilegeScope(t *testing.T) {
	uri := targetURI(t)
	ctx := context.Background()
	ensureFixture(ctx, t, uri)
	client := adminClient(ctx, t, uri)
	defer func() { _ = client.Disconnect(context.Background()) }()
	ad := mongodb.New()

	managerRole := "gr_manager_role_" + adaptertest.RandomHex(t, 4)
	managerUser := "gr_manager_user_" + adaptertest.RandomHex(t, 4)
	managerPassword := "scope-" + adaptertest.RandomHex(t, 12)
	t.Cleanup(func() {
		dropUserQuietly(uri, adminDatabase, managerUser)
		dropRoleQuietly(uri, adminDatabase, managerRole)
	})
	if err := client.Database(adminDatabase).RunCommand(ctx, bson.D{
		{Key: "createRole", Value: managerRole},
		{Key: "privileges", Value: bson.A{
			bson.D{
				{Key: "resource", Value: bson.D{{Key: "db", Value: appDatabase}, {Key: "collection", Value: ""}}},
				{Key: "actions", Value: bson.A{"viewRole", "createRole", "grantRole"}},
			},
			bson.D{
				{Key: "resource", Value: bson.D{{Key: "db", Value: ""}, {Key: "collection", Value: ""}}},
				{Key: "actions", Value: bson.A{"revokeRole"}},
			},
			bson.D{
				{Key: "resource", Value: bson.D{{Key: "db", Value: adminDatabase}, {Key: "collection", Value: ""}}},
				{Key: "actions", Value: bson.A{"viewUser"}},
			},
		}},
		{Key: "roles", Value: bson.A{}},
		{Key: "writeConcern", Value: bson.D{{Key: "w", Value: "majority"}}},
	}).Err(); err != nil {
		t.Fatalf("create scoped role-policy manager role: %v", err)
	}
	if err := client.Database(adminDatabase).RunCommand(ctx, bson.D{
		{Key: "createUser", Value: managerUser},
		{Key: "pwd", Value: managerPassword},
		{Key: "roles", Value: bson.A{bson.D{{Key: "role", Value: managerRole}, {Key: "db", Value: adminDatabase}}}},
		{Key: "writeConcern", Value: bson.D{{Key: "w", Value: "majority"}}},
	}).Err(); err != nil {
		t.Fatalf("create scoped role-policy manager user: %v", err)
	}

	rootConn := connectionFromURI(t, uri)
	rootSnapshot, err := ad.Discover(ctx, rootConn)
	if err != nil {
		t.Fatalf("Discover root target identity: %v", err)
	}
	identity := mongoSnapshotTargetIdentity(t, rootSnapshot)
	appRole := "gr_scoped_app_" + adaptertest.RandomHex(t, 4)
	otherRole := "gr_scoped_other_" + adaptertest.RandomHex(t, 4)
	for _, pair := range []struct{ database, role string }{{appDatabase, appRole}, {"otherdb", otherRole}} {
		pair := pair
		t.Cleanup(func() { dropRoleQuietly(uri, pair.database, pair.role) })
	}
	appTemplate := mongodbconfig.Normalize(mongodbconfig.RolePolicyTemplate{
		Key: "scope-" + appRole, Name: "Scoped app policy", Description: "Integration fixture",
		RoleName: appRole, RoleDatabase: appDatabase,
		Privileges: []adapter.MongoRolePrivilege{{
			Resource: adapter.MongoRoleResource{DB: appDatabase, Collection: "events"}, Actions: []string{"find"},
		}},
	})
	otherTemplate := mongodbconfig.Normalize(mongodbconfig.RolePolicyTemplate{
		Key: "scope-" + otherRole, Name: "Other DB policy", Description: "Integration fixture",
		RoleName: otherRole, RoleDatabase: "otherdb",
		Privileges: []adapter.MongoRolePrivilege{{
			Resource: adapter.MongoRoleResource{DB: "otherdb", Collection: "events"}, Actions: []string{"find"},
		}},
	})
	scopedConn := rootConn
	scopedConn.AdminCredential = adapter.Credential{
		Kind: "password", Username: managerUser, Secret: []byte(managerPassword),
	}
	scopedConn.Attributes = map[string]any{
		"auth_source": adminDatabase,
		mongodbconfig.AttributeRolePolicyTemplates: []mongodbconfig.RolePolicyTemplate{appTemplate},
	}
	appSpec := mongodbconfig.Spec(appTemplate)
	if _, err := ad.Plan(ctx, adapter.DesiredChange{
		Kind: adapter.ChangeRolePolicyApply, Connection: scopedConn,
		Permission:     "role:" + appDatabase + "." + appRole,
		RolePolicySpec: &appSpec, ExpectedTargetIdentity: identity,
	}); err != nil {
		t.Fatalf("Plan policy inside authorized database: %v", err)
	}

	scopedConn.Attributes[mongodbconfig.AttributeRolePolicyTemplates] = []mongodbconfig.RolePolicyTemplate{otherTemplate}
	otherSpec := mongodbconfig.Spec(otherTemplate)
	if _, err := ad.Plan(ctx, adapter.DesiredChange{
		Kind: adapter.ChangeRolePolicyApply, Connection: scopedConn,
		Permission:     "role:otherdb." + otherRole,
		RolePolicySpec: &otherSpec, ExpectedTargetIdentity: identity,
	}); !errors.Is(err, adapter.ErrUnsupportedChange) {
		t.Fatalf("Plan policy outside authorized database error = %v, want ErrUnsupportedChange", err)
	}
}

func TestRolePolicyBlocksConnectionAdminDependency(t *testing.T) {
	uri := targetURI(t)
	ctx := context.Background()
	ensureFixture(ctx, t, uri)
	client := adminClient(ctx, t, uri)
	defer func() { _ = client.Disconnect(context.Background()) }()
	ad := mongodb.New()
	conn := connectionFromURI(t, uri)

	role := "gr_self_authority_" + adaptertest.RandomHex(t, 4)
	desiredTemplate := mongodbconfig.Normalize(mongodbconfig.RolePolicyTemplate{
		Key: "self-authority-" + role, Name: "Self authority fence", Description: "Integration fixture",
		RoleName: role, RoleDatabase: appDatabase,
		Privileges: []adapter.MongoRolePrivilege{{
			Resource: adapter.MongoRoleResource{DB: appDatabase, Collection: "events"}, Actions: []string{"find"},
		}},
	})
	actualTemplate := desiredTemplate
	actualTemplate.Privileges = []adapter.MongoRolePrivilege{{
		Resource: adapter.MongoRoleResource{DB: appDatabase, Collection: "events"},
		Actions:  []string{"find", "insert"},
	}}
	createRoleFromTemplate(ctx, t, client, actualTemplate, nil)
	adminDB := authSourceFromConnection(conn)
	if err := client.Database(adminDB).RunCommand(ctx, bson.D{
		{Key: "grantRolesToUser", Value: conn.AdminCredential.Username},
		{Key: "roles", Value: bson.A{bson.D{{Key: "role", Value: role}, {Key: "db", Value: appDatabase}}}},
		{Key: "writeConcern", Value: bson.D{{Key: "w", Value: "majority"}}},
	}).Err(); err != nil {
		t.Fatalf("grant policy role to connection admin: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cleanupClient, err := mongo.Connect(cleanupCtx, options.Client().ApplyURI(uri))
		if err != nil {
			return
		}
		defer func() { _ = cleanupClient.Disconnect(context.Background()) }()
		_ = cleanupClient.Database(adminDB).RunCommand(cleanupCtx, bson.D{
			{Key: "revokeRolesFromUser", Value: conn.AdminCredential.Username},
			{Key: "roles", Value: bson.A{bson.D{{Key: "role", Value: role}, {Key: "db", Value: appDatabase}}}},
		}).Err()
		_ = cleanupClient.Database(appDatabase).RunCommand(cleanupCtx, bson.D{{Key: "dropRole", Value: role}}).Err()
	})

	conn.Attributes[mongodbconfig.AttributeRolePolicyTemplates] = []mongodbconfig.RolePolicyTemplate{desiredTemplate}
	snapshot, err := ad.Discover(ctx, conn)
	if err != nil {
		t.Fatalf("Discover self-authority policy: %v", err)
	}
	policy := findMongoRolePolicy(t, snapshot, "role:"+appDatabase+"."+role)
	if policy.ApplySupported || policy.BlockedReason != "role_is_connection_admin_dependency" || policy.Exact {
		t.Fatalf("self-authority policy = %+v", policy)
	}
	if slices.Contains(ad.CapabilitiesFor(conn, snapshot.Topology), adapter.CapRolePolicyApply) {
		t.Fatal("self-authority-only catalog must not expose role.policy.apply capability")
	}
	identity := mongoSnapshotTargetIdentity(t, snapshot)
	spec := mongodbconfig.Spec(desiredTemplate)
	change := adapter.DesiredChange{
		Kind: adapter.ChangeRolePolicyApply, Connection: conn,
		Permission: policy.ExternalID, RolePolicySpec: &spec,
		ExpectedTargetIdentity: identity,
	}
	if _, err := ad.Plan(ctx, change); !errors.Is(err, adapter.ErrUnsupportedChange) {
		t.Fatalf("Plan self-authority policy error = %v, want ErrUnsupportedChange", err)
	}
	fakePlan := adapter.Plan{
		Change: change,
		Steps:  []adapter.PlanStep{{Kind: "role-policy-apply", Description: "self-authority regression"}},
	}
	if _, err := ad.Apply(ctx, fakePlan); !errors.Is(err, adapter.ErrUnsupportedChange) {
		t.Fatalf("Apply self-authority policy error = %v, want ErrUnsupportedChange", err)
	}
	fakePlan.Change.Kind = adapter.ChangeRolePolicyVerify
	fakePlan.Steps[0].Kind = "role-policy-verify"
	if _, err := ad.Verify(ctx, fakePlan); !errors.Is(err, adapter.ErrUnsupportedChange) {
		t.Fatalf("Verify self-authority policy error = %v, want ErrUnsupportedChange", err)
	}
	if !roleHasAction(ctx, t, client, appDatabase, role, "insert") {
		t.Fatal("self-authority fence failed: updateRole side effect removed actual action")
	}
}

func mongoSnapshotTargetIdentity(t *testing.T, snapshot *adapter.Snapshot) string {
	t.Helper()
	raw, err := json.Marshal(snapshot.Topology)
	if err != nil {
		t.Fatalf("marshal MongoDB topology: %v", err)
	}
	identity := coreconnections.TargetIdentity(coreconnections.Connection{
		Engine: mongodb.Engine, Topology: raw,
	})
	if identity == "" {
		t.Fatalf("MongoDB target identity is absent in topology %+v", snapshot.Topology)
	}
	return identity
}

func findMongoRolePolicy(t *testing.T, snapshot *adapter.Snapshot, externalID string) adapter.ObservedRolePolicy {
	t.Helper()
	for _, policy := range snapshot.RolePolicies {
		if policy.ExternalID == externalID {
			return policy
		}
	}
	t.Fatalf("role policy %q not found in %+v", externalID, snapshot.RolePolicies)
	return adapter.ObservedRolePolicy{}
}

func mongoPolicyRoleExists(policy adapter.ObservedRolePolicy) bool {
	role, ok := policy.Summary["role"].(map[string]any)
	return ok && role["exists"] == true
}

func findMongoPermission(t *testing.T, snapshot *adapter.Snapshot, externalID string) adapter.ObservedPermission {
	t.Helper()
	for _, permission := range snapshot.Permissions {
		if permission.ExternalID == externalID {
			return permission
		}
	}
	t.Fatalf("permission %q not found", externalID)
	return adapter.ObservedPermission{}
}

func createRoleFromTemplate(
	ctx context.Context,
	t *testing.T,
	client *mongo.Client,
	template mongodbconfig.RolePolicyTemplate,
	restrictions bson.A,
) {
	t.Helper()
	roles := make(bson.A, 0, len(template.InheritedRoles))
	for _, ref := range template.InheritedRoles {
		roles = append(roles, bson.D{{Key: "role", Value: ref.Role}, {Key: "db", Value: ref.DB}})
	}
	privileges := make(bson.A, 0, len(template.Privileges))
	for _, privilege := range template.Privileges {
		resource := bson.D{}
		if privilege.Resource.Cluster {
			resource = bson.D{{Key: "cluster", Value: true}}
		} else {
			resource = bson.D{
				{Key: "db", Value: privilege.Resource.DB},
				{Key: "collection", Value: privilege.Resource.Collection},
			}
		}
		privileges = append(privileges, bson.D{
			{Key: "resource", Value: resource}, {Key: "actions", Value: privilege.Actions},
		})
	}
	cmd := bson.D{
		{Key: "createRole", Value: template.RoleName},
		{Key: "privileges", Value: privileges},
		{Key: "roles", Value: roles},
	}
	if restrictions != nil {
		cmd = append(cmd, bson.E{Key: "authenticationRestrictions", Value: restrictions})
	}
	cmd = append(cmd, bson.E{Key: "writeConcern", Value: bson.D{{Key: "w", Value: "majority"}}})
	if err := client.Database(template.RoleDatabase).RunCommand(ctx, cmd).Err(); err != nil {
		t.Fatalf("create role %q on %q: %v", template.RoleName, template.RoleDatabase, err)
	}
}

func roleExists(ctx context.Context, t *testing.T, client *mongo.Client, database, role string) bool {
	t.Helper()
	var result struct {
		Roles []bson.M `bson:"roles"`
	}
	cmd := bson.D{{Key: "rolesInfo", Value: bson.D{
		{Key: "role", Value: role}, {Key: "db", Value: database},
	}}}
	if err := client.Database(adminDatabase).RunCommand(ctx, cmd).Decode(&result); err != nil {
		t.Fatalf("rolesInfo %q on %q: %v", role, database, err)
	}
	return len(result.Roles) > 0
}

func roleHasAction(
	ctx context.Context,
	t *testing.T,
	client *mongo.Client,
	database, role, action string,
) bool {
	t.Helper()
	var result struct {
		Roles []struct {
			Privileges []struct {
				Actions []string `bson:"actions"`
			} `bson:"privileges"`
		} `bson:"roles"`
	}
	cmd := bson.D{
		{Key: "rolesInfo", Value: bson.D{{Key: "role", Value: role}, {Key: "db", Value: database}}},
		{Key: "showPrivileges", Value: true},
	}
	if err := client.Database(adminDatabase).RunCommand(ctx, cmd).Decode(&result); err != nil {
		t.Fatalf("rolesInfo actions %q on %q: %v", role, database, err)
	}
	for _, observedRole := range result.Roles {
		for _, privilege := range observedRole.Privileges {
			if slices.Contains(privilege.Actions, action) {
				return true
			}
		}
	}
	return false
}

func authSourceFromConnection(connection adapter.Connection) string {
	if value, ok := connection.Attributes["auth_source"].(string); ok && value != "" {
		return value
	}
	return adminDatabase
}

func roleDatabaseForName(role, dangerRole string) string {
	if role == dangerRole {
		return adminDatabase
	}
	return appDatabase
}

func dropRoleQuietly(uri, database, role string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return
	}
	defer func() { _ = client.Disconnect(context.Background()) }()
	_ = client.Database(database).RunCommand(ctx, bson.D{{Key: "dropRole", Value: role}}).Err()
}

// targetURI возвращает URI целевого MongoDB или пропускает тест.
func targetURI(t *testing.T) string {
	t.Helper()
	uri := os.Getenv(mongoEnv)
	if uri == "" {
		t.Skipf("%s is not set; skipping MongoDB integration test", mongoEnv)
	}
	return uri
}

// connectionFromURI строит adapter.Connection из URI: hosts, admin credential,
// authSource и replicaSet берутся из разобранного URI.
func connectionFromURI(t *testing.T, uri string) adapter.Connection {
	t.Helper()
	opts := options.Client().ApplyURI(uri)
	if err := opts.Validate(); err != nil {
		t.Fatalf("parse %s: %v", mongoEnv, err)
	}
	conn := adapter.Connection{
		ID:         "conn-mongodb-target",
		Engine:     mongodb.Engine,
		Endpoints:  opts.Hosts,
		TLS:        adapter.TLSConfig{Mode: "disabled"},
		Attributes: map[string]any{},
	}
	if opts.Auth != nil {
		conn.AdminCredential = adapter.Credential{
			Kind:     "password",
			Username: opts.Auth.Username,
			Secret:   []byte(opts.Auth.Password),
		}
		if opts.Auth.AuthSource != "" {
			conn.Attributes["auth_source"] = opts.Auth.AuthSource
		}
	}
	if opts.ReplicaSet != nil {
		conn.Attributes["replica_set"] = *opts.ReplicaSet
	}
	return conn
}

// adminClient открывает клиент по URI напрямую (admin credential из URI).
func adminClient(ctx context.Context, t *testing.T, uri string) *mongo.Client {
	t.Helper()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri).
		SetServerSelectionTimeout(10*time.Second).
		SetConnectTimeout(10*time.Second))
	if err != nil {
		t.Fatalf("connect target: %v", err)
	}
	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		t.Fatalf("ping target: %v", err)
	}
	return client
}

// ensureFixture идемпотентно создаёт фикстуру: база appdb с коллекцией events
// (индекс на created_at) и view recent_events; пользователь svc_app на appdb с
// readWrite@appdb; пользователь reader на admin с read@appdb (multi-db).
func ensureFixture(ctx context.Context, t *testing.T, uri string) {
	t.Helper()
	client := adminClient(ctx, t, uri)
	defer func() { _ = client.Disconnect(context.Background()) }()

	appdb := client.Database(appDatabase)
	ensureCollection(ctx, t, appdb, "events")
	if _, err := appdb.Collection("events").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "created_at", Value: 1}},
	}); err != nil {
		t.Fatalf("create index: %v", err)
	}
	ensureView(ctx, t, appdb, "recent_events", "events")

	ensureUser(ctx, t, client, appDatabase, "svc_app", "svc_app_fixture_pwd",
		bson.A{bson.D{{Key: "role", Value: "readWrite"}, {Key: "db", Value: appDatabase}}})
	ensureUser(ctx, t, client, "admin", "reader", "reader_fixture_pwd",
		bson.A{bson.D{{Key: "role", Value: "read"}, {Key: "db", Value: appDatabase}}})
}

// ensureCollection создаёт коллекцию, если её нет.
func ensureCollection(ctx context.Context, t *testing.T, db *mongo.Database, name string) {
	t.Helper()
	names, err := db.ListCollectionNames(ctx, bson.D{{Key: "name", Value: name}})
	if err != nil {
		t.Fatalf("list collections: %v", err)
	}
	if len(names) > 0 {
		return
	}
	if err := db.CreateCollection(ctx, name); err != nil {
		t.Fatalf("create collection %q: %v", name, err)
	}
}

// ensureView создаёт view поверх коллекции, если его ещё нет.
func ensureView(ctx context.Context, t *testing.T, db *mongo.Database, view, on string) {
	t.Helper()
	names, err := db.ListCollectionNames(ctx, bson.D{{Key: "name", Value: view}})
	if err != nil {
		t.Fatalf("list collections: %v", err)
	}
	if len(names) > 0 {
		return
	}
	if err := db.CreateView(ctx, view, on, mongo.Pipeline{}); err != nil {
		t.Fatalf("create view %q: %v", view, err)
	}
}

// ensureUser идемпотентно приводит пользователя к нужному набору ролей: если
// пользователя нет — createUser с паролем; если есть — updateUser с ролями
// (пароль не трогается).
func ensureUser(ctx context.Context, t *testing.T, client *mongo.Client, authDB, user, pwd string, roles bson.A) {
	t.Helper()
	db := client.Database(authDB)
	var info struct {
		Users []bson.M `bson:"users"`
	}
	if err := db.RunCommand(ctx, bson.D{{Key: "usersInfo", Value: user}}).Decode(&info); err != nil {
		t.Fatalf("usersInfo %q on %q: %v", user, authDB, err)
	}
	if len(info.Users) == 0 {
		cmd := bson.D{
			{Key: "createUser", Value: user},
			{Key: "pwd", Value: pwd},
			{Key: "roles", Value: roles},
		}
		if err := db.RunCommand(ctx, cmd).Err(); err != nil {
			t.Fatalf("create user %q on %q: %v", user, authDB, err)
		}
		return
	}
	cmd := bson.D{
		{Key: "updateUser", Value: user},
		{Key: "roles", Value: roles},
	}
	if err := db.RunCommand(ctx, cmd).Err(); err != nil {
		t.Fatalf("update user %q on %q: %v", user, authDB, err)
	}
}

// tryLogin аутентифицируется указанным пользователем и подтверждает, что вход
// действительно состоялся (connectionStatus). Пароль не печатается.
func tryLogin(ctx context.Context, t *testing.T, uri, authSource, user, pwd string) error {
	t.Helper()
	opts := options.Client().ApplyURI(uri).
		SetAuth(options.Credential{AuthSource: authSource, Username: user, Password: pwd}).
		SetServerSelectionTimeout(10 * time.Second).
		SetConnectTimeout(10 * time.Second)
	client, err := mongo.Connect(ctx, opts)
	if err != nil {
		return err
	}
	defer func() { _ = client.Disconnect(context.Background()) }()

	var st struct {
		AuthInfo struct {
			AuthenticatedUsers []struct {
				User string `bson:"user"`
				DB   string `bson:"db"`
			} `bson:"authenticatedUsers"`
		} `bson:"authInfo"`
	}
	if err := client.Database("admin").RunCommand(ctx, bson.D{{Key: "connectionStatus", Value: 1}}).Decode(&st); err != nil {
		return err
	}
	for _, au := range st.AuthInfo.AuthenticatedUsers {
		if au.User == user && au.DB == authSource {
			return nil
		}
	}
	return fmt.Errorf("user %q was not authenticated", user)
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

// TestValidateConnectionPrivilegeGate проверяет матрицу минимальных привилегий
// (R4): привилегированный admin (root) проходит валидацию, а пользователь лишь
// с ролью read@appdb отклоняется с adapter.InsufficientPrivilegeError,
// называющим отсутствующие user-management действия и не содержащим пароль.
func TestValidateConnectionPrivilegeGate(t *testing.T) {
	uri := targetURI(t)
	ctx := context.Background()
	ensureFixture(ctx, t, uri)
	ad := mongodb.New()

	// Positive: настоящий admin (root) проходит проверку привилегий.
	if err := ad.ValidateConnection(ctx, connectionFromURI(t, uri)); err != nil {
		t.Fatalf("ValidateConnection with privileged admin: %v", err)
	}

	// Negative: пользователь только с ролью read@appdb — управлять учётками не
	// может. Создаётся на appdb, поэтому auth_source указываем на appdb.
	probe := "gr_probe_" + adaptertest.RandomHex(t, 4)
	probePass := "probe" + adaptertest.RandomHex(t, 8)
	client := adminClient(ctx, t, uri)
	defer func() { _ = client.Disconnect(context.Background()) }()
	createCmd := bson.D{
		{Key: "createUser", Value: probe},
		{Key: "pwd", Value: probePass},
		{Key: "roles", Value: bson.A{bson.D{{Key: "role", Value: "read"}, {Key: "db", Value: appDatabase}}}},
	}
	if err := client.Database(appDatabase).RunCommand(ctx, createCmd).Err(); err != nil {
		t.Fatalf("create underprivileged probe user: %v", err)
	}
	t.Cleanup(func() { dropUserQuietly(uri, appDatabase, probe) })

	conn := connectionFromURI(t, uri)
	conn.AdminCredential = adapter.Credential{Kind: "password", Username: probe, Secret: []byte(probePass)}
	conn.Attributes = map[string]any{"auth_source": appDatabase}

	err := ad.ValidateConnection(ctx, conn)
	if err == nil {
		t.Fatal("ValidateConnection must reject an admin that cannot manage users")
	}
	var pe *adapter.InsufficientPrivilegeError
	if !errors.As(err, &pe) {
		t.Fatalf("error = %v, want *adapter.InsufficientPrivilegeError", err)
	}
	if !strings.Contains(pe.Missing, "createUser") {
		t.Errorf("missing = %q, want it to mention createUser", pe.Missing)
	}
	if strings.Contains(err.Error(), probePass) {
		t.Error("error message leaks the probe password")
	}
}

// dropUserQuietly удаляет временного пользователя напрямую админским
// подключением. Ошибки игнорируются: cleanup не должен маскировать результат.
func dropUserQuietly(uri, authDB, user string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return
	}
	defer func() { _ = client.Disconnect(context.Background()) }()
	_ = client.Database(authDB).RunCommand(ctx, bson.D{{Key: "dropUser", Value: user}}).Err()
}
