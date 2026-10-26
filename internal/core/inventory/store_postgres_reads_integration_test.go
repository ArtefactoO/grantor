//go:build integration

package inventory_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

func TestPostgresSummaryAndKeysetPagesPreserveInventory(t *testing.T) {
	ctx := t.Context()
	pool := pgtest.Pool(t)
	store := inventory.NewStore()
	conn := newTestConnection(ctx, t, pool)
	snapshot := fullSnapshot()
	const objects = 37
	for i := range objects {
		name := fmt.Sprintf("table_%03d", i)
		scope := "table:app.public." + name
		snapshot.Resources = append(snapshot.Resources, adapter.ObservedResource{Kind: "table", ExternalID: scope, ParentExternalID: "schema:app.public", Name: name, CanonicalPath: "app.public." + name, Attributes: map[string]any{"owner": "owner"}, Fingerprint: name})
		for _, action := range []string{"SELECT", "UPDATE", "TRUNCATE"} {
			p := adapter.PostgresObjectPrivilege{TargetIdentity: "postgres:system:42", Database: "app", DatabaseOID: 10, Kind: "table", Schema: "public", SchemaOID: 11, Name: name, ObjectOID: uint32(i + 100), OwnerOID: 13, Privilege: action}
			snapshot.Permissions = append(snapshot.Permissions, adapter.ObservedPermission{ExternalID: p.PermissionID(), Name: action + " ON " + p.Label(), ScopeExternalID: scope, Assignable: true, Dangerous: action == "TRUNCATE", Attributes: map[string]any{"kind": "postgres_object_privilege", "object_kind": "table", "column": ""}})
			if action == "SELECT" || action == "TRUNCATE" && i == 1 {
				attributes := map[string]any{"direct_privilege": true}
				if i == 0 {
					attributes["managed_binding_eligible"] = false
				}
				snapshot.Bindings = append(snapshot.Bindings, adapter.ObservedBinding{AccountEngineIdentity: "svc", PermissionExternalID: p.PermissionID(), ScopeExternalID: scope, Attributes: attributes})
			}
			if action == "UPDATE" {
				snapshot.Bindings = append(snapshot.Bindings, adapter.ObservedBinding{AccountEngineIdentity: "readers", PermissionExternalID: p.PermissionID(), ScopeExternalID: scope, Attributes: map[string]any{"direct_privilege": true}})
			}
		}
	}
	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, snapshot, time.Now()); err != nil {
		t.Fatal(err)
	}
	subject := accountID(ctx, t, pool, store, conn.ID, "svc")
	summaries, err := store.DirectAccessSummaries(ctx, pool, conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	want := inventory.DirectAccessSummary{Objects: objects, Bindings: objects + 1, Unmanaged: objects, Dangerous: 1, ReadOnly: 1}
	if got := summaries[subject]; got != want {
		t.Fatalf("summary=%+v want=%+v", got, want)
	}
	roles, err := store.ListRoleBindingsByConnection(ctx, pool, conn.ID)
	if err != nil || len(roles) != 1 {
		t.Fatalf("role projection: %d %v", len(roles), err)
	}
	rolePermissions, err := store.ListRolePermissions(ctx, pool, conn.ID)
	if err != nil || len(rolePermissions) != 1 {
		t.Fatalf("role definitions: %d %v", len(rolePermissions), err)
	}
	seen := map[uuid.UUID]bool{}
	after := inventory.ObjectPrivilegeKey{}
	for {
		keys, total, err := store.ListObjectPrivilegeKeys(ctx, pool, subject, conn.ID, "", after, 8)
		if err != nil || total != objects {
			t.Fatalf("page total=%d %v", total, err)
		}
		hasMore := len(keys) > 8
		if hasMore {
			keys = keys[:8]
		}
		definitions, err := store.ObjectPrivilegeDefinitions(ctx, pool, subject, conn.ID, keys)
		if err != nil || len(definitions) != len(keys)*3 {
			t.Fatalf("bounded definitions: %d %v", len(definitions), err)
		}
		bindings, err := store.BindingsForDefinitions(ctx, pool, subject, definitions)
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range bindings {
			if b.AccountID != subject {
				t.Fatal("another account's grants escaped the page")
			}
		}
		for _, key := range keys {
			if seen[key.ScopeID] {
				t.Fatal("keyset pagination duplicated an object")
			}
			seen[key.ScopeID] = true
			after = key
		}
		if !hasMore {
			break
		}
	}
	if len(seen) != objects {
		t.Fatalf("lost objects: %d", len(seen))
	}
	keys, total, err := store.ListObjectPrivilegeKeys(ctx, pool, subject, conn.ID, "table_036", inventory.ObjectPrivilegeKey{}, 8)
	if err != nil || len(keys) != 1 || total != 1 {
		t.Fatalf("server search: %d/%d %v", len(keys), total, err)
	}
	foreign := newTestConnection(ctx, t, pool)
	if keys, _, err := store.ListObjectPrivilegeKeys(ctx, pool, subject, foreign.ID, "", inventory.ObjectPrivilegeKey{}, 8); err != nil || len(keys) != 0 {
		t.Fatal("connection boundary crossed")
	}
	if _, _, err := store.ListObjectPrivilegeKeys(ctx, pool, subject, conn.ID, "", inventory.ObjectPrivilegeKey{}, 0); err == nil {
		t.Fatal("unbounded page accepted")
	}
	all, err := store.ListBindingsByAccount(ctx, pool, subject)
	if err != nil || len(all) != objects+2 {
		t.Fatalf("full read contract or data changed: %d %v", len(all), err)
	}
	keys, _, err = store.ListObjectPrivilegeKeys(ctx, pool, subject, conn.ID, "table_000", inventory.ObjectPrivilegeKey{}, 8)
	if err != nil || len(keys) != 1 {
		t.Fatal("first object key missing", err)
	}
	definitions, err := store.ObjectPrivilegeDefinitions(ctx, pool, subject, conn.ID, keys)
	if err != nil {
		t.Fatal(err)
	}
	var missingBound, missingUnbound uuid.UUID
	for _, p := range definitions {
		if p.Name[:6] == "SELECT" {
			missingBound = p.ID
		}
		if p.Name[:6] == "UPDATE" {
			missingUnbound = p.ID
		}
	}
	if missingBound == uuid.Nil || missingUnbound == uuid.Nil {
		t.Fatal("missing regression fixture permissions")
	}
	if _, err := pool.Exec(ctx, `update permission_definitions set status='missing' where id=any($1::uuid[])`, []uuid.UUID{missingBound, missingUnbound}); err != nil {
		t.Fatal(err)
	}
	definitions, err = store.ObjectPrivilegeDefinitions(ctx, pool, subject, conn.ID, keys)
	if err != nil || len(definitions) != 2 {
		t.Fatalf("historical definitions leaked into object actions: %d %v", len(definitions), err)
	}
	foundBound := false
	for _, p := range definitions {
		if p.ID == missingUnbound {
			t.Fatal("unbound historical definition returned")
		}
		if p.ID == missingBound {
			foundBound = true
		}
	}
	if !foundBound {
		t.Fatal("historical definition with observed binding was hidden")
	}
	columnPermission := uuid.New()
	if _, err := pool.Exec(ctx, `insert into permission_definitions(id,connection_id,engine,external_id,name,scope_resource_id,attributes,status) values($1,$2,'postgres','pgacl:v1:column-fixture','SELECT ON app.public.table_000.secret',$3,'{"column":"secret"}','observed')`, columnPermission, conn.ID, keys[0].ScopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `insert into bindings(account_id,permission_definition_id,scope_resource_id,source,observed_state) values($1,$2,$3,'external','present')`, subject, columnPermission, keys[0].ScopeID); err != nil {
		t.Fatal(err)
	}
	keys, total, err = store.ListObjectPrivilegeKeys(ctx, pool, subject, conn.ID, "table_000", inventory.ObjectPrivilegeKey{}, 8)
	if err != nil || total != 2 || len(keys) != 2 {
		t.Fatalf("column and relation groups were collapsed: %d/%d %v", len(keys), total, err)
	}
	for _, key := range keys {
		if key.Column != "secret" {
			continue
		}
		defs, err := store.ObjectPrivilegeDefinitions(ctx, pool, subject, conn.ID, []inventory.ObjectPrivilegeKey{key})
		if err != nil || len(defs) != 1 || defs[0].ID != columnPermission {
			t.Fatal("column page crossed the relation boundary", err)
		}
	}
}
