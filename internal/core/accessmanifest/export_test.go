package accessmanifest

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/core/inventory"
)

func TestComputeExport(t *testing.T) {
	f := newFakeSource()
	pA := f.addPrincipal("a", "alice", "Alice")
	pB := f.addPrincipal("b", "bob", "Bob")

	connTest := f.addConnection("t", "db-test", "test")
	connProd := f.addConnection("p", "db-prod", "prod")

	ro := f.addPermission(connTest, "role:ro", "readonly", true, false)
	rw := f.addPermission(connTest, "role:rw", "readwrite", true, false)
	prodRole := f.addPermission(connProd, "role:app", "app", true, false)

	// Alice: две роли в test. Bob: одна роль в prod.
	f.addManagedAccount(connTest, pA, "alice", rw, ro)
	f.addManagedAccount(connProd, pB, "bob", prodRole)

	// Unmanaged-аккаунт и managed-аккаунт без principal — не экспортируются.
	f.connAccts[connTest.ID] = append(f.connAccts[connTest.ID],
		inventory.Account{ID: uuid.New(), ConnectionID: connTest.ID, Ownership: inventory.OwnershipUnmanaged, Status: inventory.AccountActive},
	)
	orphan := inventory.Account{ID: uuid.New(), ConnectionID: connTest.ID, Ownership: inventory.OwnershipManaged, Status: inventory.AccountActive}
	f.connAccts[connTest.ID] = append(f.connAccts[connTest.ID], orphan)

	// Scoped managed binding у Alice не экспортируется (модель без scope).
	aliceAcct := f.managed[managedKey{connTest.ID, "alice"}].Account
	scopeID := uuid.New()
	st := inventory.BindingPresent
	f.bindings[aliceAcct.ID] = append(f.bindings[aliceAcct.ID],
		inventory.Binding{ID: uuid.New(), AccountID: aliceAcct.ID, PermissionDefinitionID: ro.ID, ScopeResourceID: &scopeID, DesiredState: &st},
	)

	// Экспорт без фильтра: Alice(ro,rw в test) + Bob(app в prod), отсортировано.
	all, err := computeExport(context.Background(), f, "", uuid.Nil)
	if err != nil {
		t.Fatalf("computeExport: %v", err)
	}
	if all.Version != Version {
		t.Errorf("version = %q, want %q", all.Version, Version)
	}
	want := []Entry{
		{Principal: "alice", Connection: "db-test", Role: "role:ro", State: "present"},
		{Principal: "alice", Connection: "db-test", Role: "role:rw", State: "present"},
		{Principal: "bob", Connection: "db-prod", Role: "role:app", State: "present"},
	}
	if len(all.Entries) != len(want) {
		t.Fatalf("entries = %+v, want %+v", all.Entries, want)
	}
	for i := range want {
		if all.Entries[i] != want[i] {
			t.Errorf("entry[%d] = %+v, want %+v", i, all.Entries[i], want[i])
		}
	}

	// Фильтр по окружению test оставляет только записи test-подключения.
	onlyTest, err := computeExport(context.Background(), f, "test", uuid.Nil)
	if err != nil {
		t.Fatalf("computeExport test: %v", err)
	}
	if onlyTest.Environment != "test" {
		t.Errorf("environment = %q, want test", onlyTest.Environment)
	}
	for i := range onlyTest.Entries {
		if onlyTest.Entries[i].Connection != "db-test" {
			t.Errorf("entry %+v leaked from another environment", onlyTest.Entries[i])
		}
	}
	if len(onlyTest.Entries) != 2 {
		t.Fatalf("test entries = %d, want 2", len(onlyTest.Entries))
	}

	// Фильтр по connection prod оставляет только записи этого подключения:
	// две роли Alice в test исключены, остаётся одна запись Bob в prod.
	onlyProd, err := computeExport(context.Background(), f, "", connProd.ID)
	if err != nil {
		t.Fatalf("computeExport connProd: %v", err)
	}
	wantProd := []Entry{{Principal: "bob", Connection: "db-prod", Role: "role:app", State: "present"}}
	if len(onlyProd.Entries) != len(wantProd) || onlyProd.Entries[0] != wantProd[0] {
		t.Fatalf("connProd entries = %+v, want %+v", onlyProd.Entries, wantProd)
	}

	// Фильтр по connection test оставляет обе роли Alice и исключает Bob.
	onlyConnTest, err := computeExport(context.Background(), f, "", connTest.ID)
	if err != nil {
		t.Fatalf("computeExport connTest: %v", err)
	}
	if len(onlyConnTest.Entries) != 2 {
		t.Fatalf("connTest entries = %+v, want 2 (both Alice roles)", onlyConnTest.Entries)
	}
	for i := range onlyConnTest.Entries {
		if onlyConnTest.Entries[i].Connection != "db-test" || onlyConnTest.Entries[i].Principal != "alice" {
			t.Errorf("connTest entry %+v leaked from another connection", onlyConnTest.Entries[i])
		}
	}

	// environment и connection комбинируются: connection prod при env=test даёт
	// пусто (подключение prod не в окружении test).
	empty, err := computeExport(context.Background(), f, "test", connProd.ID)
	if err != nil {
		t.Fatalf("computeExport combined: %v", err)
	}
	if len(empty.Entries) != 0 {
		t.Fatalf("combined env=test connProd entries = %+v, want 0", empty.Entries)
	}
}

func TestComputeExportEmptyIsNonNil(t *testing.T) {
	f := newFakeSource()
	m, err := computeExport(context.Background(), f, "", uuid.Nil)
	if err != nil {
		t.Fatalf("computeExport: %v", err)
	}
	if m.Entries == nil {
		t.Error("Entries is nil, want non-nil empty slice for stable JSON")
	}
}
