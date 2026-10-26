//go:build integration

package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

func TestIntegrationObjectACLDeltaPreservesUnmanagedAccountAndOtherAccess(t *testing.T) {
	dsn := os.Getenv("GRANTOR_TEST_TARGET_PG_DSN")
	if dsn == "" {
		t.Skip("GRANTOR_TEST_TARGET_PG_DSN is required")
	}
	cc, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	registerPostgresOnceAPI.Do(func() { adapter.Register(postgres.Engine, func() adapter.Adapter { return postgres.New() }) })
	env := newCascadeWorkerEnv(t, newTestVault(t))
	ctx := t.Context()
	admin, operator := session(auth.RoleAdmin), session(auth.RoleOperator)
	name := "acl_api_" + uniqueSuffix()[:8]
	subject := name + "_subject"
	peer := name + "_peer"
	target, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close(ctx) //nolint:errcheck
	exec := func(sql string) {
		t.Helper()
		if _, err := target.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	quote := func(s string) string { return pgx.Identifier{s}.Sanitize() }
	table := pgx.Identifier{"public", name}.Sanitize()
	other := pgx.Identifier{"public", name + "_other"}.Sanitize()
	exec("create role " + quote(subject) + " nologin")
	exec("create role " + quote(peer) + " nologin")
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), dsn)
		if err != nil {
			return
		}
		defer c.Close(context.Background()) //nolint:errcheck
		for _, sql := range []string{"drop table if exists " + table, "drop table if exists " + other, "drop role if exists " + quote(subject), "drop role if exists " + quote(peer)} {
			_, _ = c.Exec(context.Background(), sql)
		}
	})
	exec("create table " + table + " (id int)")
	exec("insert into " + table + " values(17)")
	exec("create table " + other + " (id int)")
	exec("grant select,insert on " + table + " to " + quote(subject))
	exec("grant select on " + other + " to " + quote(peer))
	connID := createTargetConnection(t, env, admin, operator, "object-acl", targetConnectionParams{engine: postgres.Engine, endpoint: fmt.Sprintf("%s:%d", cc.Host, cc.Port), adminUser: cc.User, adminPassword: cc.Password, discoveryConfig: map[string]string{"database": cc.Database}})
	store := inventory.NewStore()
	accounts, err := store.ListAccounts(ctx, env.pool, connID)
	if err != nil {
		t.Fatal(err)
	}
	var account inventory.Account
	for _, a := range accounts {
		if a.EngineIdentity == subject {
			account = a
		}
	}
	if account.ID == uuid.Nil || account.Ownership != inventory.OwnershipUnmanaged {
		t.Fatal("external fixture account lost")
	}
	permissions, err := store.ListPermissions(ctx, env.pool, connID)
	if err != nil {
		t.Fatal(err)
	}
	var selectPerm, updatePerm, otherPerm inventory.Permission
	for _, permission := range permissions {
		p, err := adapter.ParsePostgresObjectPrivilege(permission.ExternalID)
		if err != nil || p.Kind != "table" {
			continue
		}
		if p.Name == name && p.Privilege == "SELECT" {
			selectPerm = permission
		}
		if p.Name == name && p.Privilege == "UPDATE" {
			updatePerm = permission
		}
		if p.Name == name+"_other" && p.Privilege == "SELECT" {
			otherPerm = permission
		}
	}
	if selectPerm.ID == uuid.Nil || updatePerm.ID == uuid.Nil || otherPerm.ID == uuid.Nil {
		t.Fatal("object catalog incomplete")
	}
	bindings, err := store.ListBindingsByAccount(ctx, env.pool, account.ID)
	if err != nil {
		t.Fatal(err)
	}
	var selectBinding inventory.Binding
	for _, b := range bindings {
		if b.PermissionDefinitionID == selectPerm.ID {
			selectBinding = b
		}
	}
	if selectBinding.ID == uuid.Nil {
		t.Fatal("direct external SELECT missing from inventory")
	}
	path := "/api/v1/accounts/" + account.ID.String()
	requireStatus(t, env.do(t, http.MethodPost, path+"/roles", map[string]any{"add_permission_ids": []uuid.UUID{updatePerm.ID}, "remove_binding_ids": []uuid.UUID{}}, &operator, true), http.StatusBadRequest)
	requireStatus(t, env.do(t, http.MethodPost, path+"/object-privileges", map[string]any{"add_permission_ids": []uuid.UUID{otherPerm.ID}, "remove_binding_ids": []uuid.UUID{selectBinding.ID}}, &operator, true), http.StatusBadRequest)
	response := env.do(t, http.MethodPost, path+"/object-privileges", map[string]any{"add_permission_ids": []uuid.UUID{updatePerm.ID}, "remove_binding_ids": []uuid.UUID{selectBinding.ID}}, &operator, true)
	requireStatus(t, response, http.StatusAccepted)
	var out struct {
		OperationID uuid.UUID `json:"operation_id"`
		Children    []struct {
			OperationID uuid.UUID `json:"operation_id"`
		} `json:"children"`
	}
	if err := json.NewDecoder(response.Body).Decode(&out); err != nil || len(out.Children) != 2 {
		t.Fatal("invalid object delta receipt")
	}
	for _, child := range out.Children {
		op, err := operations.NewStore().Get(ctx, env.pool, child.OperationID)
		if err != nil {
			t.Fatal(err)
		}
		if op.Kind != jobs.KindPostgresObjectACLGrantV1 && op.Kind != jobs.KindPostgresObjectACLRevokeV1 {
			t.Fatal("object ACL used generic worker kind")
		}
		waitOperation(t, env, child.OperationID, operations.StatusSuccess, 20*time.Second)
	}
	waitOperation(t, env, out.OperationID, operations.StatusSuccess, 20*time.Second)
	var selected, updated, inserted, peerSelect bool
	var total int
	if err := target.QueryRow(ctx, `select has_table_privilege($1,$3,'SELECT'),has_table_privilege($1,$3,'UPDATE'),has_table_privilege($1,$3,'INSERT'),has_table_privilege($2,$4,'SELECT')`, subject, peer, table, other).Scan(&selected, &updated, &inserted, &peerSelect); err != nil || selected || !updated || !inserted || !peerSelect {
		t.Fatal("object delta changed unrelated access")
	}
	if err := target.QueryRow(ctx, "select sum(id)::int from "+table).Scan(&total); err != nil || total != 17 {
		t.Fatal("object delta changed table data")
	}
	after, err := store.GetAccount(ctx, env.pool, account.ID)
	if err != nil || after.Ownership != inventory.OwnershipUnmanaged || after.PrincipalID != nil || after.VaultPath != "" {
		t.Fatal("direct delta took over the external account")
	}
	bindings, err = store.ListBindingsByAccount(ctx, env.pool, account.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range bindings {
		if b.PermissionDefinitionID == updatePerm.ID && len(b.ObservedAttributes) == 0 {
			t.Fatal("worker lost exact read-back grantors")
		}
	}
}
