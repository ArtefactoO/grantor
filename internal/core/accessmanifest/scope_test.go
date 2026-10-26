package accessmanifest

// Регрессии на права, неотделимые от своего ресурса (kafka topic-produce,
// mongodb role:<db>.<name>, rabbitmq vhost-access). Манифест обязан видеть
// такой доступ ровно там, где его создаёт apply — в собственной области
// permission-определения (inventory.EffectiveBindingScope). Иначе plan вечно
// предлагал бы повторный grant, export терял бы запись, а prune отзывал бы
// только что выданное.

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/principals"
)

// addScopedPermission регистрирует assignable permission с собственной
// областью действия (ресурс подключения).
func (f *fakeSource) addScopedPermission(conn connections.Connection, externalID, name string, scope uuid.UUID) inventory.Permission {
	p := f.addPermission(conn, externalID, name, true, false)
	p.ScopeResourceID = &scope
	f.permByRef[conn.ID][externalID] = p
	if name != "" {
		f.permByRef[conn.ID][name] = p
	}
	f.permByID[p.ID] = p
	return p
}

// addManagedAccountScoped регистрирует managed-аккаунт с present-bindings в
// собственной области каждого permission — то, что создаёт выдача после
// нормализации области.
func (f *fakeSource) addManagedAccountScoped(conn connections.Connection, p principals.Principal,
	identity string, perms ...inventory.Permission) inventory.Account {
	acct := f.addManagedAccount(conn, p, identity)
	for _, perm := range perms {
		b := presentBinding(acct.ID, perm.ID)
		b.ScopeResourceID = perm.ScopeResourceID
		f.bindings[acct.ID] = append(f.bindings[acct.ID], b)
	}
	return acct
}

// TestComputePlanScopedPermissionIsIdempotent — основная регрессия: выданный
// доступ на scoped-право план больше не предлагает выдать повторно.
func TestComputePlanScopedPermissionIsIdempotent(t *testing.T) {
	f := newFakeSource()
	p := f.addPrincipal("svc", "svc-sub", "Service")
	conn := f.addConnection("kafka", "kafka (test)", "test")
	topic := uuid.New()
	perm := f.addScopedPermission(conn, "topic-produce:app-topic-a", "produce app-topic-a", topic)
	f.addManagedAccountScoped(conn, p, "svc-sub", perm)

	plan, err := computePlan(context.Background(), f, manifestOf("", false,
		Entry{Principal: "svc", Connection: "kafka", Role: "topic-produce:app-topic-a"}))
	if err != nil {
		t.Fatalf("computePlan: %v", err)
	}
	if got := kinds(plan); len(got) != 0 {
		t.Fatalf("actions = %v, want none (role already granted)", got)
	}
}

// TestComputePlanScopedPermissionGrantsWhenOnlyForeignScopeExists проверяет,
// что binding, суженный оператором до чужого ресурса, не засчитывается как
// выданный доступ манифеста.
func TestComputePlanScopedPermissionGrantsWhenOnlyForeignScopeExists(t *testing.T) {
	f := newFakeSource()
	p := f.addPrincipal("svc", "svc-sub", "Service")
	conn := f.addConnection("kafka", "kafka (test)", "test")
	topic := uuid.New()
	perm := f.addScopedPermission(conn, "topic-produce:app-topic-a", "produce app-topic-a", topic)
	acct := f.addManagedAccount(conn, p, "svc-sub")
	foreign := uuid.New()
	b := presentBinding(acct.ID, perm.ID)
	b.ScopeResourceID = &foreign
	f.bindings[acct.ID] = append(f.bindings[acct.ID], b)

	plan, err := computePlan(context.Background(), f, manifestOf("", false,
		Entry{Principal: "svc", Connection: "kafka", Role: "topic-produce:app-topic-a"}))
	if err != nil {
		t.Fatalf("computePlan: %v", err)
	}
	if got := kinds(plan); len(got) != 1 || got[0] != ActionGrant {
		t.Fatalf("actions = %v, want single grant", got)
	}
}

// TestComputePlanAbsentRevokesScopedBinding — absent-запись отзывает доступ в
// области права (иначе манифест не смог бы отозвать то, что сам выдал).
func TestComputePlanAbsentRevokesScopedBinding(t *testing.T) {
	f := newFakeSource()
	p := f.addPrincipal("svc", "svc-sub", "Service")
	conn := f.addConnection("mongo", "mongo (test)", "test")
	db := uuid.New()
	perm := f.addScopedPermission(conn, "role:appdb.readWrite", "readWrite", db)
	f.addManagedAccountScoped(conn, p, "svc-sub", perm)

	plan, err := computePlan(context.Background(), f, manifestOf("", false,
		Entry{Principal: "svc", Connection: "mongo", Role: "role:appdb.readWrite", State: string(StateAbsent)}))
	if err != nil {
		t.Fatalf("computePlan: %v", err)
	}
	if got := kinds(plan); len(got) != 1 || got[0] != ActionRevoke {
		t.Fatalf("actions = %v, want single revoke", got)
	}
	if plan.Actions[0].Resolved.Binding == nil ||
		!inventory.SameScope(plan.Actions[0].Resolved.Binding.ScopeResourceID, perm.ScopeResourceID) {
		t.Fatalf("revoke resolved binding = %+v, want binding in permission scope", plan.Actions[0].Resolved.Binding)
	}
}

// TestComputePlanPruneKeepsCoveredScopedBinding — prune не отзывает доступ,
// покрытый present-записью манифеста, и отзывает непокрытый: обе ветви теперь
// работают с областью права, а не только с NULL.
func TestComputePlanPruneKeepsCoveredScopedBinding(t *testing.T) {
	f := newFakeSource()
	p := f.addPrincipal("svc", "svc-sub", "Service")
	conn := f.addConnection("kafka", "kafka (test)", "test")
	keep := f.addScopedPermission(conn, "topic-produce:keep", "produce keep", uuid.New())
	extra := f.addScopedPermission(conn, "topic-produce:extra", "produce extra", uuid.New())
	f.addManagedAccountScoped(conn, p, "svc-sub", keep, extra)

	plan, err := computePlan(context.Background(), f, manifestOf("", true,
		Entry{Principal: "svc", Connection: "kafka", Role: "topic-produce:keep"}))
	if err != nil {
		t.Fatalf("computePlan: %v", err)
	}
	if got := kinds(plan); len(got) != 1 || got[0] != ActionRevoke {
		t.Fatalf("prune actions = %v, want single revoke", got)
	}
	if plan.Actions[0].Role != "topic-produce:extra" {
		t.Fatalf("prune revoked %q, want topic-produce:extra", plan.Actions[0].Role)
	}
}

// TestComputePlanPruneSkipsForeignScopedBinding — binding, суженный оператором
// до чужого ресурса, вне модели манифеста: prune его не трогает.
func TestComputePlanPruneSkipsForeignScopedBinding(t *testing.T) {
	f := newFakeSource()
	p := f.addPrincipal("svc", "svc-sub", "Service")
	conn := f.addConnection("kafka", "kafka (test)", "test")
	keep := f.addScopedPermission(conn, "topic-produce:keep", "produce keep", uuid.New())
	acct := f.addManagedAccountScoped(conn, p, "svc-sub", keep)
	clusterWide := f.addPermission(conn, "role:extra", "extra", true, false)
	foreign := presentBinding(acct.ID, clusterWide.ID)
	narrowed := uuid.New()
	foreign.ScopeResourceID = &narrowed
	f.bindings[acct.ID] = append(f.bindings[acct.ID], foreign)

	plan, err := computePlan(context.Background(), f, manifestOf("", true,
		Entry{Principal: "svc", Connection: "kafka", Role: "topic-produce:keep"}))
	if err != nil {
		t.Fatalf("computePlan: %v", err)
	}
	if got := kinds(plan); len(got) != 0 {
		t.Fatalf("prune actions = %v, want none (foreign scope is outside the manifest)", got)
	}
}

// TestComputeExportIncludesScopedPermission — export симметричен apply:
// выданный на scoped-праве доступ попадает в манифест, суженный до чужого
// ресурса — нет.
func TestComputeExportIncludesScopedPermission(t *testing.T) {
	f := newFakeSource()
	p := f.addPrincipal("svc", "svc-sub", "Service")
	conn := f.addConnection("kafka", "kafka (test)", "test")
	perm := f.addScopedPermission(conn, "topic-produce:app-topic-a", "produce app-topic-a", uuid.New())
	acct := f.addManagedAccountScoped(conn, p, "svc-sub", perm)
	foreignPerm := f.addScopedPermission(conn, "topic-produce:app-topic-b", "produce app-topic-b", uuid.New())
	foreign := presentBinding(acct.ID, foreignPerm.ID)
	narrowed := uuid.New()
	foreign.ScopeResourceID = &narrowed
	f.bindings[acct.ID] = append(f.bindings[acct.ID], foreign)

	m, err := computeExport(context.Background(), f, "", uuid.Nil)
	if err != nil {
		t.Fatalf("computeExport: %v", err)
	}
	if len(m.Entries) != 1 {
		t.Fatalf("entries = %+v, want exactly one", m.Entries)
	}
	if m.Entries[0].Role != "topic-produce:app-topic-a" || m.Entries[0].Principal != "svc-sub" {
		t.Fatalf("entry = %+v, want svc-sub / topic-produce:app-topic-a", m.Entries[0])
	}

	// Round-trip: повторный plan по экспортированному манифесту пуст.
	plan, err := computePlan(context.Background(), f, manifestOf("", false, m.Entries...))
	if err != nil {
		t.Fatalf("computePlan on exported manifest: %v", err)
	}
	if got := kinds(plan); len(got) != 0 {
		t.Fatalf("plan on exported manifest = %v, want none", got)
	}
}
