package accessmanifest

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/principals"
)

// fakeSource — in-memory реализация Source для юнит-тестов diff-логики без
// БД. Резолв имён и точечные загрузки идут по картам; отсутствие ссылки даёт
// *ResolveError, как у реального storeSource.
type fakeSource struct {
	principalByRef map[string]principals.Principal
	principalByID  map[uuid.UUID]principals.Principal
	connByRef      map[string]connections.Connection
	connByID       map[uuid.UUID]connections.Connection
	permByRef      map[uuid.UUID]map[string]inventory.Permission
	permByID       map[uuid.UUID]inventory.Permission
	managed        map[managedKey]AccountLookup
	bindings       map[uuid.UUID][]inventory.Binding
	principalAccts map[uuid.UUID][]inventory.Account
	allConns       []connections.Connection
	connAccts      map[uuid.UUID][]inventory.Account
}

type managedKey struct {
	conn     uuid.UUID
	identity string
}

func newFakeSource() *fakeSource {
	return &fakeSource{
		principalByRef: map[string]principals.Principal{},
		principalByID:  map[uuid.UUID]principals.Principal{},
		connByRef:      map[string]connections.Connection{},
		connByID:       map[uuid.UUID]connections.Connection{},
		permByRef:      map[uuid.UUID]map[string]inventory.Permission{},
		permByID:       map[uuid.UUID]inventory.Permission{},
		managed:        map[managedKey]AccountLookup{},
		bindings:       map[uuid.UUID][]inventory.Binding{},
		principalAccts: map[uuid.UUID][]inventory.Account{},
		connAccts:      map[uuid.UUID][]inventory.Account{},
	}
}

func (f *fakeSource) addPrincipal(ref, subject, name string) principals.Principal {
	p := principals.Principal{ID: uuid.New(), ExternalSubject: subject, DisplayName: name}
	f.principalByRef[ref] = p
	f.principalByID[p.ID] = p
	return p
}

func (f *fakeSource) addConnection(ref, name, env string) connections.Connection {
	c := connections.Connection{ID: uuid.New(), DisplayName: name, Environment: env}
	f.connByRef[ref] = c
	f.connByRef[c.ID.String()] = c
	f.connByRef[c.DisplayName] = c
	f.connByID[c.ID] = c
	f.allConns = append(f.allConns, c)
	return c
}

func TestComputePlanForConnectionAcceptsIDAndDisplayNameAndRejectsForeignEntries(t *testing.T) {
	f := newFakeSource()
	f.addPrincipal("svc", "svc-sub", "Service")
	connA := f.addConnection("a", "database-a", "test")
	connB := f.addConnection("b", "database-b", "test")
	f.addPermission(connA, "role:ro", "readonly", true, false)
	f.addPermission(connB, "role:ro", "readonly", true, false)

	for _, ref := range []string{connA.ID.String(), connA.DisplayName} {
		plan, err := computePlanForConnection(context.Background(), f, manifestOf("", false,
			Entry{Principal: "svc", Connection: ref, Role: "role:ro"}), connA.ID)
		if err != nil {
			t.Fatalf("computePlanForConnection(%q): %v", ref, err)
		}
		if got := kinds(plan); len(got) != 2 || got[0] != ActionCreateAccount || got[1] != ActionGrant {
			t.Fatalf("actions for %q = %v, want [create_account grant]", ref, got)
		}
	}

	_, err := computePlanForConnection(context.Background(), f, manifestOf("", false,
		Entry{Principal: "svc", Connection: connA.DisplayName, Role: "role:ro"},
		Entry{Principal: "svc", Connection: connB.DisplayName, Role: "role:ro"}), connA.ID)
	if !errors.Is(err, ErrConnectionScopeMismatch) {
		t.Fatalf("mixed manifest error = %v, want ErrConnectionScopeMismatch", err)
	}
}

func TestComputePlanForConnectionScopesPrune(t *testing.T) {
	f := newFakeSource()
	p := f.addPrincipal("svc", "svc-sub", "Service")
	connA := f.addConnection("a", "database-a", "test")
	connB := f.addConnection("b", "database-b", "test")
	keepA := f.addPermission(connA, "role:keep", "keep", true, false)
	extraA := f.addPermission(connA, "role:extra", "extra", true, false)
	extraB := f.addPermission(connB, "role:extra", "extra", true, false)
	f.addManagedAccount(connA, p, "svc-sub", keepA, extraA)
	f.addManagedAccount(connB, p, "svc-sub", extraB)

	plan, err := computePlanForConnection(context.Background(), f, manifestOf("", true,
		Entry{Principal: "svc", Connection: connA.DisplayName, Role: "role:keep"}), connA.ID)
	if err != nil {
		t.Fatalf("computePlanForConnection: %v", err)
	}
	if got := kinds(plan); len(got) != 1 || got[0] != ActionRevoke {
		t.Fatalf("scoped prune actions = %v, want one revoke", got)
	}
	if plan.Actions[0].Resolved.Connection.ID != connA.ID || plan.Actions[0].Role != "role:extra" {
		t.Fatalf("scoped prune action = %+v, want only extra role from connection A", plan.Actions[0])
	}
}

func (f *fakeSource) addPermission(conn connections.Connection, externalID, name string, assignable, dangerous bool) inventory.Permission {
	p := inventory.Permission{
		ID: uuid.New(), ConnectionID: conn.ID, ExternalID: externalID,
		Name: name, Assignable: assignable, Dangerous: dangerous,
	}
	if f.permByRef[conn.ID] == nil {
		f.permByRef[conn.ID] = map[string]inventory.Permission{}
	}
	f.permByRef[conn.ID][externalID] = p
	if name != "" {
		f.permByRef[conn.ID][name] = p
	}
	f.permByID[p.ID] = p
	return p
}

func (f *fakeSource) setPermissionAssignment(conn connections.Connection,
	p inventory.Permission, assignmentKey string) inventory.Permission {
	p.AssignmentKey = assignmentKey
	f.permByID[p.ID] = p
	f.permByRef[conn.ID][p.ExternalID] = p
	if p.Name != "" {
		f.permByRef[conn.ID][p.Name] = p
	}
	return p
}

// addManagedAccount регистрирует managed-аккаунт принципала в подключении и
// его bindings (present, без scope) на переданные permissions.
func (f *fakeSource) addManagedAccount(conn connections.Connection, p principals.Principal, identity string, presentPerms ...inventory.Permission) inventory.Account {
	pid := p.ID
	acct := inventory.Account{
		ID: uuid.New(), ConnectionID: conn.ID, PrincipalID: &pid,
		EngineIdentity: identity, Ownership: inventory.OwnershipManaged, Status: inventory.AccountActive,
	}
	f.managed[managedKey{conn.ID, identity}] = AccountLookup{Account: acct, Found: true}
	for _, perm := range presentPerms {
		f.bindings[acct.ID] = append(f.bindings[acct.ID], presentBinding(acct.ID, perm.ID))
	}
	f.principalAccts[pid] = append(f.principalAccts[pid], acct)
	f.connAccts[conn.ID] = append(f.connAccts[conn.ID], acct)
	return acct
}

// presentBinding — право, которое и затребовано, и ФАКТИЧЕСКИ применено в
// целевой системе. Наблюдаемое состояние задаётся явно: план отличает
// применённое право от расходящегося, и binding без observed выглядел бы
// дрифтом, для которого повторная выдача — легитимная починка.
func presentBinding(acctID, permID uuid.UUID) inventory.Binding {
	st := inventory.BindingPresent
	return inventory.Binding{
		ID:                     uuid.New(),
		AccountID:              acctID,
		PermissionDefinitionID: permID,
		DesiredState:           &st,
		ObservedState:          inventory.BindingPresent,
		ObservedEffective:      true,
	}
}

// driftedBinding — право затребовано, но в целевой системе его нет: снято
// снаружи. План обязан предложить повторную выдачу.
func driftedBinding(acctID, permID uuid.UUID) inventory.Binding {
	st := inventory.BindingPresent
	return inventory.Binding{
		ID:                     uuid.New(),
		AccountID:              acctID,
		PermissionDefinitionID: permID,
		DesiredState:           &st,
		ObservedState:          inventory.BindingAbsent,
		ObservedEffective:      true,
	}
}

func (f *fakeSource) ResolvePrincipal(_ context.Context, ref string) (principals.Principal, error) {
	if p, ok := f.principalByRef[ref]; ok {
		return p, nil
	}
	return principals.Principal{}, resolveErr("principal %q not found", ref)
}

func (f *fakeSource) ResolveConnection(_ context.Context, ref string) (connections.Connection, error) {
	if c, ok := f.connByRef[ref]; ok {
		return c, nil
	}
	return connections.Connection{}, resolveErr("connection %q not found", ref)
}

func (f *fakeSource) ResolvePermission(_ context.Context, connID uuid.UUID, ref string) (inventory.Permission, error) {
	if m, ok := f.permByRef[connID]; ok {
		if p, ok := m[ref]; ok {
			return p, nil
		}
	}
	return inventory.Permission{}, resolveErr("role %q not found", ref)
}

func (f *fakeSource) Principal(_ context.Context, id uuid.UUID) (principals.Principal, error) {
	if p, ok := f.principalByID[id]; ok {
		return p, nil
	}
	return principals.Principal{}, resolveErr("principal id %s not found", id)
}

func (f *fakeSource) Connection(_ context.Context, id uuid.UUID) (connections.Connection, error) {
	if c, ok := f.connByID[id]; ok {
		return c, nil
	}
	return connections.Connection{}, resolveErr("connection id %s not found", id)
}

func (f *fakeSource) Permission(_ context.Context, id uuid.UUID) (inventory.Permission, error) {
	if p, ok := f.permByID[id]; ok {
		return p, nil
	}
	return inventory.Permission{}, resolveErr("permission id %s not found", id)
}

func (f *fakeSource) ManagedAccount(_ context.Context, connID, _ uuid.UUID, identity string) (AccountLookup, error) {
	return f.managed[managedKey{connID, identity}], nil
}

func (f *fakeSource) AccountBindings(_ context.Context, acctID uuid.UUID) ([]inventory.Binding, error) {
	return f.bindings[acctID], nil
}

func (f *fakeSource) PrincipalAccounts(_ context.Context, pid uuid.UUID) ([]inventory.Account, error) {
	return f.principalAccts[pid], nil
}

func (f *fakeSource) Connections(_ context.Context) ([]connections.Connection, error) {
	return f.allConns, nil
}

func (f *fakeSource) ConnectionAccounts(_ context.Context, connID uuid.UUID) ([]inventory.Account, error) {
	return f.connAccts[connID], nil
}

// kinds собирает виды действий плана в порядке следования.
func kinds(plan Plan) []string {
	out := make([]string, 0, len(plan.Actions))
	for i := range plan.Actions {
		out = append(out, plan.Actions[i].Kind)
	}
	return out
}

func manifestOf(env string, prune bool, entries ...Entry) Manifest {
	return Manifest{Version: Version, Environment: env, Prune: prune, Entries: entries}
}

func TestComputePlanCanonicalizesExclusiveAssignmentReplacement(t *testing.T) {
	f := newFakeSource()
	p := f.addPrincipal("svc", "svc", "Service")
	conn := f.addConnection("rabbit", "rabbit", "test")
	oldPermission := f.setPermissionAssignment(conn,
		f.addPermission(conn, "template:old", "Old", true, false), "rabbitmq:vhost:etl")
	newPermission := f.setPermissionAssignment(conn,
		f.addPermission(conn, "template:new", "New", true, false), oldPermission.AssignmentKey)
	acct := f.addManagedAccount(conn, p, "svc", oldPermission)
	f.bindings[acct.ID][0].AssignmentKey = oldPermission.AssignmentKey

	// absent A намеренно идёт раньше present B: порядок entries не должен
	// оставлять независимый revoke перед replace.
	plan, err := computePlan(context.Background(), f, manifestOf("", false,
		Entry{Principal: "svc", Connection: "rabbit", Role: oldPermission.ExternalID, State: string(StateAbsent)},
		Entry{Principal: "svc", Connection: "rabbit", Role: newPermission.ExternalID},
	))
	if err != nil {
		t.Fatalf("computePlan: %v", err)
	}
	if got := kinds(plan); len(got) != 1 || got[0] != ActionReplace {
		t.Fatalf("actions = %v, want [replace]", got)
	}
	action := plan.Actions[0]
	if action.FromRole != oldPermission.ExternalID || action.Role != newPermission.ExternalID ||
		action.Resolved == nil || action.Resolved.Binding == nil ||
		action.Resolved.Binding.ID != f.bindings[acct.ID][0].ID {
		t.Fatalf("replace action = %+v", action)
	}
}

func TestComputePlanRejectsTwoTargetsForExclusiveAssignment(t *testing.T) {
	f := newFakeSource()
	p := f.addPrincipal("svc", "svc", "Service")
	conn := f.addConnection("rabbit", "rabbit", "test")
	first := f.setPermissionAssignment(conn,
		f.addPermission(conn, "template:first", "First", true, false), "rabbitmq:vhost:etl")
	second := f.setPermissionAssignment(conn,
		f.addPermission(conn, "template:second", "Second", true, false), first.AssignmentKey)
	acct := f.addManagedAccount(conn, p, "svc", first)
	f.bindings[acct.ID][0].AssignmentKey = first.AssignmentKey

	_, err := computePlan(context.Background(), f, manifestOf("", false,
		Entry{Principal: "svc", Connection: "rabbit", Role: first.ExternalID},
		Entry{Principal: "svc", Connection: "rabbit", Role: second.ExternalID},
	))
	if !errors.Is(err, ErrAmbiguousReplacement) {
		t.Fatalf("error = %v, want ErrAmbiguousReplacement", err)
	}
}

func TestComputePlanPresentCreatesAccountAndGrant(t *testing.T) {
	f := newFakeSource()
	f.addPrincipal("svc", "svc-sub", "Service")
	conn := f.addConnection("db", "db (test)", "test")
	f.addPermission(conn, "role:ro", "readonly", true, false)

	plan, err := computePlan(context.Background(), f, manifestOf("", false,
		Entry{Principal: "svc", Connection: "db", Role: "role:ro"}))
	if err != nil {
		t.Fatalf("computePlan: %v", err)
	}
	if got := kinds(plan); len(got) != 2 || got[0] != ActionCreateAccount || got[1] != ActionGrant {
		t.Fatalf("action kinds = %v, want [create_account grant]", got)
	}
	if len(plan.Unresolved) != 0 {
		t.Errorf("unresolved = %d, want 0", len(plan.Unresolved))
	}
	for i := range plan.Actions {
		if plan.Actions[i].AccountEngineIdentity != "svc-sub" {
			t.Errorf("action %d identity = %q, want svc-sub", i, plan.Actions[i].AccountEngineIdentity)
		}
		if plan.Actions[i].Resolved == nil {
			t.Errorf("action %d has nil Resolved", i)
		}
	}
}

func TestComputePlanPresentExistingBindingIsNoop(t *testing.T) {
	f := newFakeSource()
	p := f.addPrincipal("svc", "svc-sub", "Service")
	conn := f.addConnection("db", "db (test)", "test")
	perm := f.addPermission(conn, "role:ro", "readonly", true, false)
	f.addManagedAccount(conn, p, "svc-sub", perm)

	plan, err := computePlan(context.Background(), f, manifestOf("", false,
		Entry{Principal: "svc", Connection: "db", Role: "role:ro"}))
	if err != nil {
		t.Fatalf("computePlan: %v", err)
	}
	if len(plan.Actions) != 0 {
		t.Fatalf("actions = %v, want none (idempotent)", kinds(plan))
	}
}

func TestComputePlanPresentExistingAccountNoBindingGrants(t *testing.T) {
	f := newFakeSource()
	p := f.addPrincipal("svc", "svc-sub", "Service")
	conn := f.addConnection("db", "db (test)", "test")
	perm := f.addPermission(conn, "role:ro", "readonly", true, false)
	f.addManagedAccount(conn, p, "svc-sub") // аккаунт есть, без bindings

	plan, err := computePlan(context.Background(), f, manifestOf("", false,
		Entry{Principal: "svc", Connection: "db", Role: perm.ExternalID}))
	if err != nil {
		t.Fatalf("computePlan: %v", err)
	}
	if got := kinds(plan); len(got) != 1 || got[0] != ActionGrant {
		t.Fatalf("action kinds = %v, want [grant]", got)
	}
	if plan.Actions[0].Resolved.Account == nil {
		t.Error("grant action should carry resolved account")
	}
}

func TestComputePlanAbsentRevokes(t *testing.T) {
	f := newFakeSource()
	p := f.addPrincipal("svc", "svc-sub", "Service")
	conn := f.addConnection("db", "db (test)", "test")
	perm := f.addPermission(conn, "role:ro", "readonly", true, false)
	f.addManagedAccount(conn, p, "svc-sub", perm)

	plan, err := computePlan(context.Background(), f, manifestOf("", false,
		Entry{Principal: "svc", Connection: "db", Role: "role:ro", State: string(StateAbsent)}))
	if err != nil {
		t.Fatalf("computePlan: %v", err)
	}
	if got := kinds(plan); len(got) != 1 || got[0] != ActionRevoke {
		t.Fatalf("action kinds = %v, want [revoke]", got)
	}
	if plan.Actions[0].Resolved.Binding == nil {
		t.Error("revoke action should carry resolved binding")
	}
}

func TestComputePlanAbsentWithoutBindingIsNoop(t *testing.T) {
	f := newFakeSource()
	p := f.addPrincipal("svc", "svc-sub", "Service")
	conn := f.addConnection("db", "db (test)", "test")
	f.addPermission(conn, "role:ro", "readonly", true, false)
	f.addManagedAccount(conn, p, "svc-sub") // нет binding

	plan, err := computePlan(context.Background(), f, manifestOf("", false,
		Entry{Principal: "svc", Connection: "db", Role: "role:ro", State: string(StateAbsent)}))
	if err != nil {
		t.Fatalf("computePlan: %v", err)
	}
	if len(plan.Actions) != 0 {
		t.Fatalf("actions = %v, want none", kinds(plan))
	}
}

func TestComputePlanPruneRevokesExtraManagedRoles(t *testing.T) {
	f := newFakeSource()
	p := f.addPrincipal("svc", "svc-sub", "Service")
	conn := f.addConnection("db", "db (test)", "test")
	keep := f.addPermission(conn, "role:ro", "readonly", true, false)
	extra := f.addPermission(conn, "role:rw", "readwrite", true, false)
	// Аккаунт держит обе роли; манифест перечисляет только keep.
	f.addManagedAccount(conn, p, "svc-sub", keep, extra)

	manifest := manifestOf("", true, Entry{Principal: "svc", Connection: "db", Role: "role:ro"})

	// Без prune лишняя роль не трогается.
	noPrune, err := computePlan(context.Background(), f, manifestOf("", false, manifest.Entries[0]))
	if err != nil {
		t.Fatalf("computePlan no prune: %v", err)
	}
	if len(noPrune.Actions) != 0 {
		t.Fatalf("no-prune actions = %v, want none", kinds(noPrune))
	}

	// С prune лишняя роль отзывается (keep остаётся present).
	plan, err := computePlan(context.Background(), f, manifest)
	if err != nil {
		t.Fatalf("computePlan prune: %v", err)
	}
	if got := kinds(plan); len(got) != 1 || got[0] != ActionRevoke {
		t.Fatalf("prune action kinds = %v, want [revoke]", got)
	}
	if plan.Actions[0].Role != "role:rw" {
		t.Errorf("pruned role = %q, want role:rw", plan.Actions[0].Role)
	}
}

func TestComputePlanUnresolvedPrincipal(t *testing.T) {
	f := newFakeSource()
	conn := f.addConnection("db", "db (test)", "test")
	f.addPermission(conn, "role:ro", "readonly", true, false)

	plan, err := computePlan(context.Background(), f, manifestOf("", false,
		Entry{Principal: "ghost", Connection: "db", Role: "role:ro"}))
	if err != nil {
		t.Fatalf("computePlan: %v", err)
	}
	if len(plan.Actions) != 0 {
		t.Errorf("actions = %v, want none", kinds(plan))
	}
	if len(plan.Unresolved) != 1 || plan.Unresolved[0].Principal != "ghost" || plan.Unresolved[0].Reason == "" {
		t.Fatalf("unresolved = %+v, want one entry with reason", plan.Unresolved)
	}
}

func TestComputePlanDangerousMarked(t *testing.T) {
	f := newFakeSource()
	f.addPrincipal("svc", "svc-sub", "Service")
	conn := f.addConnection("db", "db (test)", "test")
	f.addPermission(conn, "role:super", "superuser", true, true)

	plan, err := computePlan(context.Background(), f, manifestOf("", false,
		Entry{Principal: "svc", Connection: "db", Role: "role:super"}))
	if err != nil {
		t.Fatalf("computePlan: %v", err)
	}
	// create_account + grant; grant помечен dangerous.
	var sawGrant bool
	for i := range plan.Actions {
		if plan.Actions[i].Kind == ActionGrant {
			sawGrant = true
			if !plan.Actions[i].Dangerous {
				t.Error("grant action for dangerous role is not marked dangerous")
			}
		}
	}
	if !sawGrant {
		t.Fatalf("no grant action, kinds = %v", kinds(plan))
	}
}

func TestComputePlanEnvironmentMismatchUnresolved(t *testing.T) {
	f := newFakeSource()
	f.addPrincipal("svc", "svc-sub", "Service")
	conn := f.addConnection("db", "db (test)", "test")
	f.addPermission(conn, "role:ro", "readonly", true, false)

	plan, err := computePlan(context.Background(), f, manifestOf("prod", false,
		Entry{Principal: "svc", Connection: "db", Role: "role:ro"}))
	if err != nil {
		t.Fatalf("computePlan: %v", err)
	}
	if len(plan.Actions) != 0 || len(plan.Unresolved) != 1 {
		t.Fatalf("actions=%v unresolved=%d, want 0 action / 1 unresolved", kinds(plan), len(plan.Unresolved))
	}
}

func TestComputePlanNotAssignableUnresolved(t *testing.T) {
	f := newFakeSource()
	f.addPrincipal("svc", "svc-sub", "Service")
	conn := f.addConnection("db", "db (test)", "test")
	f.addPermission(conn, "role:ro", "readonly", false, false) // not assignable

	plan, err := computePlan(context.Background(), f, manifestOf("", false,
		Entry{Principal: "svc", Connection: "db", Role: "role:ro"}))
	if err != nil {
		t.Fatalf("computePlan: %v", err)
	}
	if len(plan.Actions) != 0 || len(plan.Unresolved) != 1 {
		t.Fatalf("actions=%v unresolved=%d, want 0/1", kinds(plan), len(plan.Unresolved))
	}
}

func TestComputePlanIdentityConflictUnresolved(t *testing.T) {
	f := newFakeSource()
	f.addPrincipal("svc", "svc-sub", "Service")
	conn := f.addConnection("db", "db (test)", "test")
	f.addPermission(conn, "role:ro", "readonly", true, false)
	// identity занята unmanaged-аккаунтом (конфликт).
	f.managed[managedKey{conn.ID, "svc-sub"}] = AccountLookup{Conflict: true, ConflictReason: "taken by unmanaged account"}

	plan, err := computePlan(context.Background(), f, manifestOf("", false,
		Entry{Principal: "svc", Connection: "db", Role: "role:ro"}))
	if err != nil {
		t.Fatalf("computePlan: %v", err)
	}
	if len(plan.Actions) != 0 || len(plan.Unresolved) != 1 {
		t.Fatalf("actions=%v unresolved=%d, want 0/1", kinds(plan), len(plan.Unresolved))
	}
	if plan.Unresolved[0].Reason != "taken by unmanaged account" {
		t.Errorf("reason = %q, want conflict reason", plan.Unresolved[0].Reason)
	}
}

// Право, снятое снаружи, план обязан предложить выдать заново. Аудит показал
// обратное: access/plan и access/apply против реального дрифта возвращали
// пустой diff, а императивные пути отвечали 409 «уже назначено» — расхождение
// было видно и неустранимо ничем, кроме удаления binding с реальным отзывом.
func TestComputePlanRegrantsDriftedBinding(t *testing.T) {
	f := newFakeSource()
	p := f.addPrincipal("svc", "svc-sub", "Service")
	conn := f.addConnection("db", "db (test)", "test")
	perm := f.addPermission(conn, "role:ro", "readonly", true, false)
	acct := f.addManagedAccount(conn, p, "svc-sub")
	// Право затребовано, но в целевой системе его нет.
	f.bindings[acct.ID] = []inventory.Binding{driftedBinding(acct.ID, perm.ID)}

	plan, err := computePlan(context.Background(), f, manifestOf("", false,
		Entry{Principal: "svc", Connection: "db", Role: "role:ro"}))
	if err != nil {
		t.Fatalf("computePlan: %v", err)
	}
	if got := kinds(plan); len(got) != 1 || got[0] != string(ActionGrant) {
		t.Fatalf("actions = %v, want a single grant repairing the drift", got)
	}
}

// Право, выданное но не действующее (роль вне набора по умолчанию), — тот же
// случай: доступа нет, значит план обязан его починить.
func TestComputePlanRegrantsIneffectiveBinding(t *testing.T) {
	f := newFakeSource()
	p := f.addPrincipal("svc", "svc-sub", "Service")
	conn := f.addConnection("db", "db (test)", "test")
	perm := f.addPermission(conn, "role:ro", "readonly", true, false)
	acct := f.addManagedAccount(conn, p, "svc-sub")
	b := presentBinding(acct.ID, perm.ID)
	b.ObservedEffective = false
	f.bindings[acct.ID] = []inventory.Binding{b}

	plan, err := computePlan(context.Background(), f, manifestOf("", false,
		Entry{Principal: "svc", Connection: "db", Role: "role:ro"}))
	if err != nil {
		t.Fatalf("computePlan: %v", err)
	}
	if got := kinds(plan); len(got) != 1 || got[0] != string(ActionGrant) {
		t.Fatalf("actions = %v, want a single grant re-applying the ineffective role", got)
	}
}

// Провал применения — та же доказанная поломка: до следующего discovery
// binding живёт с observed=unknown, и без учёта status план давал бы ноль
// действий против права, которого в целевой системе нет.
func TestComputePlanRegrantsFailedBinding(t *testing.T) {
	f := newFakeSource()
	p := f.addPrincipal("svc", "svc-sub", "Service")
	conn := f.addConnection("db", "db (test)", "test")
	perm := f.addPermission(conn, "role:ro", "readonly", true, false)
	acct := f.addManagedAccount(conn, p, "svc-sub")
	b := presentBinding(acct.ID, perm.ID)
	b.ObservedState = inventory.BindingUnknown
	b.Status = inventory.BindingStatusFailed
	f.bindings[acct.ID] = []inventory.Binding{b}

	plan, err := computePlan(context.Background(), f, manifestOf("", false,
		Entry{Principal: "svc", Connection: "db", Role: "role:ro"}))
	if err != nil {
		t.Fatalf("computePlan: %v", err)
	}
	if got := kinds(plan); len(got) != 1 || got[0] != string(ActionGrant) {
		t.Fatalf("actions = %v, want a single grant repairing the failed apply", got)
	}
}
