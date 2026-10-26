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
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

func TestIntegrationStatsMembershipUsesVerifiedCreationReceiptAndDirectAPI(t *testing.T) {
	dsn := os.Getenv("GRANTOR_TEST_TARGET_PG_DSN")
	if dsn == "" {
		t.Skip("GRANTOR_TEST_TARGET_PG_DSN is not set")
	}
	cc, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	registerPostgresOnceAPI.Do(func() { adapter.Register(postgres.Engine, func() adapter.Adapter { return postgres.New() }) })
	env := newCascadeWorkerEnv(t, newTestVault(t))
	admin, operator := session(auth.RoleAdmin), session(auth.RoleOperator)
	connID := createTargetConnection(t, env, admin, operator, "stats", targetConnectionParams{engine: postgres.Engine,
		endpoint: fmt.Sprintf("%s:%d", cc.Host, cc.Port), adminUser: cc.User, adminPassword: cc.Password, discoveryConfig: map[string]string{"database": cc.Database}})
	permission := findPermission(t, env.pool, connID, postgres.StatsPermission)
	if !permission.Assignable {
		t.Fatal("direct statistics role not assignable")
	}
	var systemAccounts int
	if err := env.pool.QueryRow(t.Context(), `select count(*) from accounts where connection_id=$1 and engine_identity like 'pg\_%'`, connID).Scan(&systemAccounts); err != nil || systemAccounts != 0 {
		t.Fatal("builtin acquired an account lifecycle row")
	}
	principal := createPrincipalRow(t, env.pool, "Stats monitor "+uniqueSuffix()[:8])
	name := "stats_api_" + uniqueSuffix()[:8]
	t.Cleanup(func() {
		targetExec(context.Background(), t, dsn, "drop role if exists "+pgx.Identifier{name}.Sanitize())
	})
	response := env.do(t, http.MethodPost, "/api/v1/principals/"+principal.ID.String()+"/access", map[string]any{
		"engine_identity": name, "items": []map[string]any{{"connection_id": connID, "permission_id": permission.ID}}}, &operator, true)
	requireStatus(t, response, http.StatusAccepted)
	var out struct {
		Children []principalAccessChildBody `json:"children"`
	}
	if err := json.NewDecoder(response.Body).Decode(&out); err != nil || len(out.Children) != 1 {
		t.Fatal("invalid principal access receipt")
	}
	child := out.Children[0]
	if child.AccountCreateOperationID == nil {
		t.Fatal("new LOGIN has no creation dependency")
	}
	grant, err := operations.NewStore().Get(t.Context(), env.pool, child.GrantOperationID)
	if err != nil || grant.Kind != jobs.KindPostgresStatsGrantV1 {
		t.Fatal("builtin used the legacy membership worker kind")
	}
	var pinned jobs.AccessPayload
	if err := json.Unmarshal(grant.Payload, &pinned); err != nil || pinned.StatsMembership == nil || pinned.StatsMembership.SubjectOID != 0 || pinned.StatsCreationOperationID != *child.AccountCreateOperationID {
		t.Fatal("new LOGIN OID was guessed instead of deferred to creation proof")
	}
	waitOperation(t, env, child.GrantOperationID, operations.StatusSuccess, 20*time.Second)
	if !targetQueryBool(t.Context(), t, dsn, `select pg_has_role($1,$2,'USAGE')`, name, postgres.StatsRole) {
		t.Fatal("statistics access not effective")
	}
	if targetQueryBool(t.Context(), t, dsn, `select rolsuper or rolcreaterole or rolreplication or rolbypassrls from pg_roles where rolname=$1`, name) {
		t.Fatal("statistics user elevated")
	}
	response = env.do(t, http.MethodDelete, "/api/v1/bindings/"+child.BindingID.String(), nil, &operator, true)
	requireStatus(t, response, http.StatusAccepted)
	var revoked struct {
		OperationID uuid.UUID `json:"operation_id"`
	}
	if err := json.NewDecoder(response.Body).Decode(&revoked); err != nil {
		t.Fatal(err)
	}
	waitOperation(t, env, revoked.OperationID, operations.StatusSuccess, 20*time.Second)
	binding, err := inventory.NewStore().GetBinding(t.Context(), env.pool, child.BindingID)
	if err != nil || binding.DesiredState == nil || *binding.DesiredState != inventory.BindingAbsent {
		t.Fatal("revoke lifecycle not retained")
	}
	if targetQueryBool(t.Context(), t, dsn, `select pg_has_role($1,$2,'MEMBER')`, name, postgres.StatsRole) {
		t.Fatal("statistics access still present")
	}
	requireStatus(t, env.do(t, http.MethodPost, "/api/v1/accounts", map[string]any{"connection_id": connID,
		"engine_identity": postgres.StatsRole, "credential": map[string]string{"mode": "generated"}}, &operator, true), http.StatusBadRequest)
	if err := env.pool.QueryRow(t.Context(), `select count(*) from accounts where connection_id=$1 and engine_identity like 'pg\_%'`, connID).Scan(&systemAccounts); err != nil || systemAccounts != 0 {
		t.Fatal("protected builtin reservation was created")
	}
	// Changing the route without discovery invalidates the old authority pins.
	if _, err := env.pool.Exec(t.Context(), `update connections set execution_mode=$2 where id=$1`, connID, connections.ExecutionModeConnector); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, env.do(t, http.MethodPost, "/api/v1/bindings", map[string]any{"account_id": child.AccountID, "permission_id": permission.ID}, &operator, true), http.StatusConflict)
}
