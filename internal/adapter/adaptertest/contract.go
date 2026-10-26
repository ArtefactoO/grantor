// Package adaptertest содержит общий contract test suite, который обязан
// проходить каждый adapter (docs/architecture.md, раздел 29).
package adaptertest

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

// Harness подготавливает adapter и connection к тестовой целевой системе:
// для fake — in-memory состояние, для реальных движков — ephemeral container.
//
// Требования к фикстуре целевой системы: минимум один активный login account
// и, если adapter объявляет access.grant, минимум две assignable
// не-dangerous permissions. AdminCredential.Secret должен быть непустым —
// по нему проверяется redaction.
type Harness struct {
	New                func(t *testing.T) (adapter.Adapter, adapter.Connection)
	SkipLegacyCreation bool
}

// Run прогоняет contract suite. Каждый subtest получает свежую пару
// adapter/connection, чтобы тесты не зависели друг от друга.
func Run(t *testing.T, h Harness) {
	t.Run("ManifestIsValid", func(t *testing.T) { testManifest(t, h) })
	t.Run("ValidateConnection", func(t *testing.T) { testValidate(t, h) })
	t.Run("DiscoveryIsRepeatable", func(t *testing.T) { testDiscoveryRepeatable(t, h) })
	t.Run("SnapshotIsConsistent", func(t *testing.T) { testSnapshotConsistent(t, h) })
	t.Run("PlanRedactsSecrets", func(t *testing.T) { testPlanRedactsSecrets(t, h) })
	t.Run("GrantApplyIsIdempotent", func(t *testing.T) { testGrantIdempotent(t, h) })
	t.Run("RevokeRemovesOnlyTargetBinding", func(t *testing.T) { testRevokeOnlyTarget(t, h) })
	t.Run("RestoreProvesCredentialAndIsIdempotent", func(t *testing.T) {
		if h.SkipLegacyCreation {
			t.Skip("adapter uses an engine-specific versioned creation contract")
		}
		testRestoreCredentialProof(t, h)
	})
	t.Run("AccountCreateRefusesExistingIdentity", func(t *testing.T) {
		if h.SkipLegacyCreation {
			t.Skip("adapter uses an engine-specific versioned creation contract")
		}
		testAccountCreateConflict(t, h)
	})
	t.Run("RoleCreateRefusesExistingIdentity", func(t *testing.T) {
		if h.SkipLegacyCreation {
			t.Skip("adapter uses an engine-specific versioned creation contract")
		}
		testRoleCreateConflict(t, h)
	})
	t.Run("RoleCreateIsVisibleInDiscovery", func(t *testing.T) {
		if h.SkipLegacyCreation {
			t.Skip("adapter uses an engine-specific versioned creation contract")
		}
		testRoleCreateDiscoverable(t, h)
	})
	t.Run("DatabaseCreateRefusesExistingDatabase", func(t *testing.T) {
		if h.SkipLegacyCreation {
			t.Skip("adapter uses an engine-specific versioned creation contract")
		}
		testDatabaseCreateConflict(t, h)
	})
	t.Run("DatabaseCreateIsVisibleInDiscovery", func(t *testing.T) {
		if h.SkipLegacyCreation {
			t.Skip("adapter uses an engine-specific versioned creation contract")
		}
		testDatabaseCreateDiscoverable(t, h)
	})
}

// testAccountCreateConflict фиксирует контракт account.create: шаг создаёт
// НОВУЮ identity и никогда не присваивает уже существующую.
//
// Пропуск шага для существующей identity выглядит как безобидная
// идемпотентность, но означает тихий захват: grantor записывает учётку себе и
// кладёт в Vault свежий пароль, тогда как на target остаётся прежний. Оператор
// получает через share мёртвый credential, а весь контур adopt (доказательство
// пароля, гейт на опасные bindings) оказывается обойдён.
//
// Поэтому account.create — единственная мутация, где повторный Apply того же
// плана обязан отказать, а не быть no-op (ср. testGrantIdempotent).
// Идемпотентность повторной операции обеспечивает ядро: аккаунт в статусе
// active второй раз до adapter не доходит.
func testAccountCreateConflict(t *testing.T, h Harness) {
	ad, conn := h.New(t)
	if !ad.Manifest().HasCapability(adapter.CapAccountCreate) {
		t.Skip("adapter does not declare account.create")
	}
	cred, err := ad.GenerateCredential(t.Context(), adapter.CredentialPolicy{})
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	account := adapter.Account{
		Kind:           "login",
		EngineIdentity: engineIdentity(t, ad, conn, "grantor_create_"+RandomHex(t, 6)),
	}
	change := adapter.DesiredChange{
		Kind: adapter.ChangeAccountCreate, Connection: conn, Account: account, Credential: cred,
	}
	plan := mustPlan(t, ad, change)
	mustApply(t, ad, *plan)
	t.Cleanup(func() {
		del := change
		del.Kind = adapter.ChangeAccountDelete
		del.Credential = nil
		delPlan, err := ad.Plan(t.Context(), del)
		if err != nil {
			t.Logf("cleanup plan account.delete: %v", err)
			return
		}
		if _, err := ad.Apply(t.Context(), *delPlan); err != nil {
			t.Logf("cleanup apply account.delete: %v", err)
		}
	})

	if _, err := ad.Plan(t.Context(), change); !errors.Is(err, adapter.ErrExternalIdentityConflict) {
		t.Errorf("Plan(account.create) over an existing identity error = %v, want ErrExternalIdentityConflict", err)
	}

	// Повтор уже построенного плана моделирует identity, появившуюся между
	// Plan и Apply: шаг обязан упасть, а не быть пропущен.
	res, err := ad.Apply(t.Context(), *plan)
	if err != nil {
		return // Adapter отказал целиком — тоже корректный отказ.
	}
	for _, s := range res.Steps {
		if s.Status != adapter.StepFailed {
			t.Errorf("Apply(account.create) over an existing identity: step %q status = %q, want %q",
				s.Step.Kind, s.Status, adapter.StepFailed)
		}
	}
}

func testRestoreCredentialProof(t *testing.T, h Harness) {
	ad, conn := h.New(t)
	if !ad.Manifest().HasCapability(adapter.CapAccountRestore) {
		t.Skip("adapter does not declare account.restore")
	}
	if _, ok := ad.(adapter.CredentialProver); !ok {
		t.Fatal("adapter declares account.restore without CredentialProver")
	}
	cred, err := ad.GenerateCredential(t.Context(), adapter.CredentialPolicy{})
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	account := adapter.Account{Kind: "login", EngineIdentity: engineIdentity(t, ad, conn, "grantor_restore_"+RandomHex(t, 6))}
	change := adapter.DesiredChange{
		Kind: adapter.ChangeAccountRestore, Connection: conn, Account: account, Credential: cred,
	}
	plan := mustPlan(t, ad, change)
	mustApply(t, ad, *plan)
	ver, err := ad.Verify(t.Context(), *plan)
	if err != nil || !ver.Verified {
		t.Fatalf("restore Verify = %+v, %v", ver, err)
	}
	// Повтор строит recovery plan только после credential proof.
	mustApply(t, ad, *mustPlan(t, ad, change))
	bad := *cred
	bad.Secret = []byte("definitely-not-the-reserved-credential")
	change.Credential = &bad
	if _, err := ad.Plan(t.Context(), change); !errors.Is(err, adapter.ErrExternalIdentityConflict) {
		t.Errorf("restore with mismatched credential error = %v, want ErrExternalIdentityConflict", err)
	}
	// Cleanup target fixture.
	deleteChange := change
	deleteChange.Kind = adapter.ChangeAccountDelete
	deleteChange.Credential = nil
	mustApply(t, ad, *mustPlan(t, ad, deleteChange))
}

// engineIdentity приводит базовое имя эфемерной учётки к engine-специфичной
// форме подключения. Ядро делает то же самое перед account.create
// (adapter.FormatEngineIdentity), но contract suite обращается к adapter
// напрямую, не полагаясь на глобальный registry движков. Adapter без
// EngineIdentityFormatter (postgres, clickhouse, rabbitmq, ...) оставляет
// имя как есть; mysql достраивает его до user@host.
func engineIdentity(t *testing.T, ad adapter.Adapter, conn adapter.Connection, base string) string {
	t.Helper()
	f, ok := ad.(adapter.EngineIdentityFormatter)
	if !ok {
		return base
	}
	identity, err := f.FormatEngineIdentity(conn, base)
	if err != nil {
		t.Fatalf("FormatEngineIdentity(%q): %v", base, err)
	}
	return identity
}

func testManifest(t *testing.T, h Harness) {
	ad, _ := h.New(t)
	m := ad.Manifest()
	if m.Engine == "" {
		t.Error("manifest: empty Engine")
	}
	if m.Version == "" {
		t.Error("manifest: empty Version")
	}
	if m.ConnectionSchema == "" {
		t.Error("manifest: empty ConnectionSchema")
	}
	if len(m.Capabilities) == 0 {
		t.Error("manifest: no capabilities declared")
	}
	seen := map[adapter.Capability]bool{}
	for _, c := range m.Capabilities {
		if c == "" {
			t.Error("manifest: empty capability")
		}
		if seen[c] {
			t.Errorf("manifest: duplicate capability %q", c)
		}
		seen[c] = true
	}
	_, hasProver := ad.(adapter.CredentialProver)
	if m.HasCapability(adapter.CapCredentialProve) {
		if !hasProver {
			t.Error("manifest declares credential.prove without CredentialProver")
		}
		if !m.HasCapability(adapter.CapCredentialRotate) {
			t.Error("manifest declares credential.prove without credential.rotate")
		}
	} else if hasProver {
		t.Error("adapter implements CredentialProver without credential.prove capability")
	}
	if m.HasCapability(adapter.CapAccountRestore) && !m.HasCapability(adapter.CapCredentialProve) {
		t.Error("manifest declares account.restore without credential.prove")
	}
}

func testValidate(t *testing.T, h Harness) {
	ad, conn := h.New(t)
	if err := ad.ValidateConnection(t.Context(), conn); err != nil {
		t.Fatalf("ValidateConnection: %v", err)
	}
}

func testDiscoveryRepeatable(t *testing.T, h Harness) {
	ad, conn := h.New(t)
	first := discover(t, ad, conn)
	second := discover(t, ad, conn)

	if got, want := resourceIDs(second), resourceIDs(first); !slices.Equal(got, want) {
		t.Errorf("resource external IDs not stable between discoveries:\nfirst:  %v\nsecond: %v", want, got)
	}
	if got, want := accountIDs(second), accountIDs(first); !slices.Equal(got, want) {
		t.Errorf("account identities not stable between discoveries:\nfirst:  %v\nsecond: %v", want, got)
	}
	if got, want := permissionIDs(second), permissionIDs(first); !slices.Equal(got, want) {
		t.Errorf("permission external IDs not stable between discoveries:\nfirst:  %v\nsecond: %v", want, got)
	}
}

func testSnapshotConsistent(t *testing.T, h Harness) {
	ad, conn := h.New(t)
	snap := discover(t, ad, conn)

	resources := map[string]bool{}
	for _, r := range snap.Resources {
		key := r.Kind + "/" + r.ExternalID
		if resources[key] {
			t.Errorf("duplicate resource %q", key)
		}
		resources[key] = true
	}
	byID := map[string]bool{}
	for _, r := range snap.Resources {
		byID[r.ExternalID] = true
	}
	for _, r := range snap.Resources {
		if r.ParentExternalID != "" && !byID[r.ParentExternalID] {
			t.Errorf("resource %q references unknown parent %q", r.ExternalID, r.ParentExternalID)
		}
	}

	accounts := map[string]bool{}
	for _, a := range snap.Accounts {
		if accounts[a.EngineIdentity] {
			t.Errorf("duplicate account identity %q", a.EngineIdentity)
		}
		accounts[a.EngineIdentity] = true
	}
	permissions := map[string]bool{}
	for _, p := range snap.Permissions {
		if permissions[p.ExternalID] {
			t.Errorf("duplicate permission %q", p.ExternalID)
		}
		permissions[p.ExternalID] = true
		if p.ScopeExternalID != "" && !byID[p.ScopeExternalID] {
			t.Errorf("permission %q references unknown scope %q", p.ExternalID, p.ScopeExternalID)
		}
	}
	for _, b := range snap.Bindings {
		if !accounts[b.AccountEngineIdentity] {
			t.Errorf("binding references unknown account %q", b.AccountEngineIdentity)
		}
		if !permissions[b.PermissionExternalID] {
			t.Errorf("binding references unknown permission %q", b.PermissionExternalID)
		}
		if b.ScopeExternalID != "" && !byID[b.ScopeExternalID] {
			t.Errorf("binding references unknown scope %q", b.ScopeExternalID)
		}
	}
}

func testPlanRedactsSecrets(t *testing.T, h Harness) {
	ad, conn := h.New(t)
	if !ad.Manifest().HasCapability(adapter.CapAccessGrant) {
		t.Skip("adapter does not declare access.grant")
	}
	secret := string(conn.AdminCredential.Secret)
	if secret == "" {
		t.Fatal("harness must provide a non-empty admin credential secret")
	}

	snap := discover(t, ad, conn)
	acct, perms := grantFixture(t, snap)
	plan := mustPlan(t, ad, grantChange(conn, acct, perms[0]))
	for _, s := range plan.Steps {
		if strings.Contains(s.Description, secret) {
			t.Errorf("plan step description leaks admin secret: %q", s.Description)
		}
		// Attributes сериализуются в jsonb и показываются в UI; секрет не
		// должен просачиваться ни в значения, ни в ключи.
		attrs, err := json.Marshal(s.Attributes)
		if err != nil {
			t.Fatalf("marshal plan step %q attributes: %v", s.Kind, err)
		}
		if strings.Contains(string(attrs), secret) {
			t.Errorf("plan step %q attributes leak admin secret: %s", s.Kind, attrs)
		}
	}

	// Verify выполняется на неприменённом плане: он вернёт «не в целевом
	// состоянии», но и такие Details не должны содержать секрет.
	ver, err := ad.Verify(t.Context(), *plan)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if strings.Contains(ver.Details, secret) {
		t.Errorf("verification details leak admin secret: %q", ver.Details)
	}
}

func testGrantIdempotent(t *testing.T, h Harness) {
	ad, conn := h.New(t)
	if !ad.Manifest().HasCapability(adapter.CapAccessGrant) {
		t.Skip("adapter does not declare access.grant")
	}
	snap := discover(t, ad, conn)
	acct, perms := grantFixture(t, snap)
	change := grantChange(conn, acct, perms[0])

	plan := mustPlan(t, ad, change)
	mustApply(t, ad, *plan)

	ver, err := ad.Verify(t.Context(), *plan)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ver.Verified {
		t.Fatalf("Verify after Apply: not verified: %s", ver.Details)
	}

	// Повторный Apply того же плана обязан быть безопасен.
	mustApply(t, ad, *plan)

	after := discover(t, ad, conn)
	if !hasBinding(after, acct, perms[0].ExternalID) {
		t.Error("granted binding not visible in discovery")
	}
}

func testRevokeOnlyTarget(t *testing.T, h Harness) {
	ad, conn := h.New(t)
	m := ad.Manifest()
	if !m.HasCapability(adapter.CapAccessGrant) || !m.HasCapability(adapter.CapAccessRevoke) {
		t.Skip("adapter does not declare access.grant + access.revoke")
	}
	snap := discover(t, ad, conn)
	acct, perms := grantFixture(t, snap)
	if len(perms) < 2 {
		t.Fatal("fixture must provide at least two assignable permissions for revoke test")
	}

	for _, p := range perms[:2] {
		mustApply(t, ad, *mustPlan(t, ad, grantChange(conn, acct, p)))
	}

	revoke := grantChange(conn, acct, perms[0])
	revoke.Kind = adapter.ChangeRevoke
	plan := mustPlan(t, ad, revoke)
	mustApply(t, ad, *plan)

	ver, err := ad.Verify(t.Context(), *plan)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ver.Verified {
		t.Fatalf("Verify after revoke: not verified: %s", ver.Details)
	}

	after := discover(t, ad, conn)
	if hasBinding(after, acct, perms[0].ExternalID) {
		t.Error("revoked binding still present")
	}
	if !hasBinding(after, acct, perms[1].ExternalID) {
		t.Error("revoke removed a binding it must not touch")
	}
}

func discover(t *testing.T, ad adapter.Adapter, conn adapter.Connection) *adapter.Snapshot {
	t.Helper()
	snap, err := ad.Discover(t.Context(), conn)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if snap == nil {
		t.Fatal("Discover: nil snapshot")
	}
	return snap
}

// grantFixture возвращает активный login account и assignable не-dangerous
// permissions из snapshot; падает, если фикстура не отвечает требованиям.
func grantFixture(t *testing.T, snap *adapter.Snapshot) (adapter.Account, []adapter.ObservedPermission) {
	t.Helper()
	var acct adapter.Account
	found := false
	for _, a := range snap.Accounts {
		if a.Kind == "login" && !a.Disabled {
			acct = adapter.Account{
				Kind:                a.Kind,
				EngineIdentity:      a.EngineIdentity,
				AuthenticationScope: a.AuthenticationScope,
			}
			found = true
			break
		}
	}
	if !found {
		t.Fatal("fixture must provide at least one active login account")
	}
	var perms []adapter.ObservedPermission
	for _, p := range snap.Permissions {
		if p.Assignable && !p.Dangerous {
			perms = append(perms, p)
		}
	}
	if len(perms) == 0 {
		t.Fatal("fixture must provide at least one assignable non-dangerous permission")
	}
	return acct, perms
}

func grantChange(conn adapter.Connection, acct adapter.Account, perm adapter.ObservedPermission) adapter.DesiredChange {
	return adapter.DesiredChange{
		Kind:       adapter.ChangeGrant,
		Connection: conn,
		Account:    acct,
		Permission: perm.ExternalID,
		Scope:      perm.ScopeExternalID,
	}
}

func mustPlan(t *testing.T, ad adapter.Adapter, change adapter.DesiredChange) *adapter.Plan {
	t.Helper()
	plan, err := ad.Plan(t.Context(), change)
	if err != nil {
		t.Fatalf("Plan(%s): %v", change.Kind, err)
	}
	if plan == nil || len(plan.Steps) == 0 {
		t.Fatalf("Plan(%s): empty plan", change.Kind)
	}
	return plan
}

func mustApply(t *testing.T, ad adapter.Adapter, plan adapter.Plan) *adapter.Result {
	t.Helper()
	res, err := ad.Apply(t.Context(), plan)
	if err != nil {
		t.Fatalf("Apply(%s): %v", plan.Change.Kind, err)
	}
	for _, s := range res.Steps {
		if s.Status != adapter.StepApplied && s.Status != adapter.StepSkipped {
			t.Fatalf("Apply(%s): step %q finished with %q: %s",
				plan.Change.Kind, s.Step.Kind, s.Status, s.Error)
		}
	}
	return res
}

func hasBinding(snap *adapter.Snapshot, acct adapter.Account, permissionID string) bool {
	for _, b := range snap.Bindings {
		if b.AccountEngineIdentity == acct.EngineIdentity && b.PermissionExternalID == permissionID {
			return true
		}
	}
	return false
}

func resourceIDs(s *adapter.Snapshot) []string {
	ids := make([]string, 0, len(s.Resources))
	for _, r := range s.Resources {
		ids = append(ids, r.Kind+"/"+r.ExternalID)
	}
	slices.Sort(ids)
	return ids
}

func accountIDs(s *adapter.Snapshot) []string {
	ids := make([]string, 0, len(s.Accounts))
	for _, a := range s.Accounts {
		ids = append(ids, a.EngineIdentity)
	}
	slices.Sort(ids)
	return ids
}

func permissionIDs(s *adapter.Snapshot) []string {
	ids := make([]string, 0, len(s.Permissions))
	for _, p := range s.Permissions {
		ids = append(ids, p.ExternalID)
	}
	slices.Sort(ids)
	return ids
}

// testRoleCreateConflict фиксирует тот же контракт, что и account.create, но
// для роли-контейнера: создаётся НОВАЯ роль, существующая не присваивается.
//
// Захват роли не безобиднее захвата учётки: роль — это право, и «принять» её
// молча значит выдать grantor управление чужими выданными доступами в обход
// adopt, который делает это через явный review bindings.
func testRoleCreateConflict(t *testing.T, h Harness) {
	ad, conn := h.New(t)
	if !ad.Manifest().HasCapability(adapter.CapRoleCreate) {
		t.Skip("adapter does not declare role.create")
	}
	account := adapter.Account{
		Kind:           "group",
		EngineIdentity: "grantor_role_" + RandomHex(t, 6),
	}
	change := adapter.DesiredChange{
		Kind: adapter.ChangeRoleCreate, Connection: conn, Account: account,
	}
	plan := mustPlan(t, ad, change)
	mustApply(t, ad, *plan)
	t.Cleanup(func() {
		del := change
		del.Kind = adapter.ChangeAccountDelete
		delPlan, err := ad.Plan(t.Context(), del)
		if err != nil {
			t.Logf("cleanup plan account.delete: %v", err)
			return
		}
		if _, err := ad.Apply(t.Context(), *delPlan); err != nil {
			t.Logf("cleanup apply account.delete: %v", err)
		}
	})

	if _, err := ad.Plan(t.Context(), change); !errors.Is(err, adapter.ErrExternalIdentityConflict) {
		t.Errorf("Plan(role.create) over an existing role error = %v, want ErrExternalIdentityConflict", err)
	}

	// Повтор уже построенного плана моделирует роль, появившуюся между Plan
	// и Apply: шаг обязан упасть, а не быть пропущен.
	res, err := ad.Apply(t.Context(), *plan)
	if err != nil {
		return // Adapter отказал целиком — тоже корректный отказ.
	}
	for _, s := range res.Steps {
		if s.Status != adapter.StepFailed {
			t.Errorf("Apply(role.create) over an existing role: step %q status = %q, want %q",
				s.Step.Kind, s.Status, adapter.StepFailed)
		}
	}
}

// testRoleCreateDiscoverable фиксирует смысл capability: созданная роль
// обязана появиться в снимке И как учётная запись без логина, И как
// назначаемое право. Без второй проекции роль нельзя выдать, то есть
// создавать её незачем.
func testRoleCreateDiscoverable(t *testing.T, h Harness) {
	ad, conn := h.New(t)
	if !ad.Manifest().HasCapability(adapter.CapRoleCreate) {
		t.Skip("adapter does not declare role.create")
	}
	if !ad.Manifest().HasCapability(adapter.CapInventoryPermissions) {
		t.Skip("adapter does not publish permissions")
	}
	name := "grantor_role_" + RandomHex(t, 6)
	change := adapter.DesiredChange{
		Kind:       adapter.ChangeRoleCreate,
		Connection: conn,
		Account:    adapter.Account{Kind: "group", EngineIdentity: name},
	}
	PlanApplyVerify(t.Context(), t, ad, change)
	t.Cleanup(func() {
		del := change
		del.Kind = adapter.ChangeAccountDelete
		delPlan, err := ad.Plan(t.Context(), del)
		if err != nil {
			t.Logf("cleanup plan account.delete: %v", err)
			return
		}
		if _, err := ad.Apply(t.Context(), *delPlan); err != nil {
			t.Logf("cleanup apply account.delete: %v", err)
		}
	})

	snap, err := ad.Discover(t.Context(), conn)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	account := false
	for _, a := range snap.Accounts {
		if a.EngineIdentity == name {
			account = true
			if a.Kind != "group" {
				t.Errorf("created role appears as account kind %q, want group", a.Kind)
			}
		}
	}
	if !account {
		t.Errorf("created role %q is missing from snapshot accounts", name)
	}
	permission := false
	for _, p := range snap.Permissions {
		if p.AccountEngineIdentity == name {
			permission = true
			if !p.Assignable {
				t.Errorf("created role %q is published as a non-assignable permission", name)
			}
		}
	}
	if !permission {
		t.Errorf("created role %q is missing from snapshot permissions: it cannot be granted", name)
	}
}

// databaseCreateChange собирает изменение создания базы с заданным именем.
func databaseCreateChange(conn adapter.Connection, name string) adapter.DesiredChange {
	return adapter.DesiredChange{
		Kind:       adapter.ChangeResourceCreate,
		Connection: conn,
		Resource:   &adapter.ResourceSpec{Kind: "database", Name: name},
	}
}

// testDatabaseCreateConflict фиксирует контракт создания базы: существующая
// база не присваивается.
//
// Пропуск шага выглядел бы идемпотентностью, но означает тихий захват: grantor
// записал бы чужую базу себе в инвентарь как созданную им и managed, хотя её
// содержимое и владелец принадлежат кому-то другому. Автоматического отката
// у создания базы нет (architecture §11.2), поэтому единственная защита —
// отказ.
func testDatabaseCreateConflict(t *testing.T, h Harness) {
	ad, conn := h.New(t)
	if !ad.Manifest().HasCapability(adapter.ResourceCapability("create", "database")) {
		t.Skip("adapter does not declare resource.create.database")
	}
	change := databaseCreateChange(conn, "grantor_db_"+RandomHex(t, 6))
	plan := mustPlan(t, ad, change)
	mustApply(t, ad, *plan)

	if _, err := ad.Plan(t.Context(), change); !errors.Is(err, adapter.ErrExternalIdentityConflict) {
		t.Errorf("Plan(resource.create) over an existing database error = %v, want ErrExternalIdentityConflict", err)
	}

	// Повтор уже построенного плана моделирует базу, появившуюся между Plan
	// и Apply: шаг обязан упасть, а не быть пропущен.
	res, err := ad.Apply(t.Context(), *plan)
	if err != nil {
		return // Adapter отказал целиком — тоже корректный отказ.
	}
	for _, s := range res.Steps {
		if s.Status != adapter.StepFailed {
			t.Errorf("Apply(resource.create) over an existing database: step %q status = %q, want %q",
				s.Step.Kind, s.Status, adapter.StepFailed)
		}
	}
}

// testDatabaseCreateDiscoverable фиксирует, что созданная база попадает в
// инвентарь: без этого её нельзя выбрать областью выдачи, то есть создавать
// её из grantor незачем.
func testDatabaseCreateDiscoverable(t *testing.T, h Harness) {
	ad, conn := h.New(t)
	if !ad.Manifest().HasCapability(adapter.ResourceCapability("create", "database")) {
		t.Skip("adapter does not declare resource.create.database")
	}
	name := "grantor_db_" + RandomHex(t, 6)
	PlanApplyVerify(t.Context(), t, ad, databaseCreateChange(conn, name))

	snap, err := ad.Discover(t.Context(), conn)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	for _, r := range snap.Resources {
		if r.Kind == "database" && r.Name == name {
			return
		}
	}
	t.Errorf("created database %q is missing from snapshot resources", name)
}
