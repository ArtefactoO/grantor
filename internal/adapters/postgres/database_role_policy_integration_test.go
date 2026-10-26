//go:build integration

package postgres

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/postgresconfig"
)

func TestRolePolicyDirectDatabaseIncarnationFences(t *testing.T) {
	dsn := os.Getenv("GRANTOR_TEST_TARGET_PG_DSN")
	if dsn == "" {
		t.Skip("GRANTOR_TEST_TARGET_PG_DSN is not configured")
	}
	cc, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cluster, err := pgx.ConnectConfig(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	defer closeQuietly(t.Context(), cluster)
	var superuser bool
	if err := cluster.QueryRow(t.Context(), `select rolsuper from pg_roles where rolname=session_user`).Scan(&superuser); err != nil {
		t.Fatal(err)
	}
	if !superuser {
		t.Skip("target DSN user is not SUPERUSER")
	}

	suffix := strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	database := "gr_fence_db_" + suffix
	owner := "gr_fence_owner_" + suffix
	otherOwner := "gr_fence_other_" + suffix
	policyRole := "gr_fence_role_" + suffix
	roles := []string{owner, otherOwner, policyRole}
	for _, role := range roles[:2] {
		if _, err := cluster.Exec(t.Context(), "create role "+pgx.Identifier{role}.Sanitize()+" nologin"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := cluster.Exec(t.Context(), "create database "+pgx.Identifier{database}.Sanitize()+
		" owner "+pgx.Identifier{owner}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		cleanup, err := pgx.ConnectConfig(ctx, cc)
		if err != nil {
			return
		}
		defer closeQuietly(ctx, cleanup)
		_, _ = cleanup.Exec(ctx, "drop database if exists "+pgx.Identifier{database}.Sanitize()+" with (force)")
		for i := len(roles) - 1; i >= 0; i-- {
			_, _ = cleanup.Exec(ctx, "drop owned by "+pgx.Identifier{roles[i]}.Sanitize()+" cascade")
			_, _ = cleanup.Exec(ctx, "drop role if exists "+pgx.Identifier{roles[i]}.Sanitize())
		}
	})

	var systemIdentifier string
	var databaseOID, ownerOID uint32
	if err := cluster.QueryRow(t.Context(), `select system_identifier::text from pg_control_system()`).Scan(&systemIdentifier); err != nil {
		t.Fatal(err)
	}
	if err := cluster.QueryRow(t.Context(), `
		select d.oid,r.oid from pg_database d join pg_roles r on r.oid=d.datdba where d.datname=$1`, database).
		Scan(&databaseOID, &ownerOID); err != nil {
		t.Fatal(err)
	}
	connection := adapter.Connection{
		ID: "database-fence-" + suffix, Engine: Engine,
		Endpoints: []string{net.JoinHostPort(cc.Host, strconv.Itoa(int(cc.Port)))},
		TLS:       adapter.TLSConfig{Mode: "disabled"}, Attributes: map[string]any{"database": cc.Database},
		ConfigIncarnation: "integration-" + suffix, AdminCredentialIncarnation: 1,
		AdminCredential: adapter.Credential{Kind: "password", Username: cc.User, Secret: []byte(cc.Password)},
	}
	spec := rolePolicySpec(postgresconfig.RolePolicyTemplate{
		Key: "fence-" + suffix, Name: "fence", Description: "database incarnation fence",
		RoleName: policyRole, Database: database, Schemas: []string{"public"},
		OwnerRoles: []string{owner}, CreatorRoles: []string{owner}, Profile: postgresconfig.ProfileRead,
	})
	base := adapter.DesiredChange{
		Kind:       adapter.ChangePostgresRolePolicyCreateDatabaseV2,
		Connection: connection, RolePolicySpec: &spec,
		ExpectedAdminIdentity:    cc.User,
		ExpectedTargetIdentity:   "postgres:system:" + systemIdentifier,
		ExpectedDatabaseOID:      databaseOID,
		ExpectedDatabaseOwner:    owner,
		ExpectedDatabaseOwnerOID: ownerOID,
	}
	ad := New()
	currentDatabaseOID := databaseOID
	assertRoleAbsent := func(t *testing.T) {
		t.Helper()
		exists, err := roleExists(t.Context(), cluster, policyRole)
		if err != nil || exists {
			t.Fatalf("fence created role: exists=%v err=%v", exists, err)
		}
	}

	for name, mutate := range map[string]func(*adapter.DesiredChange){
		"system identity":    func(c *adapter.DesiredChange) { c.ExpectedTargetIdentity = "postgres:system:0" },
		"database oid":       func(c *adapter.DesiredChange) { c.ExpectedDatabaseOID++ },
		"database owner":     func(c *adapter.DesiredChange) { c.ExpectedDatabaseOwner = otherOwner },
		"database owner oid": func(c *adapter.DesiredChange) { c.ExpectedDatabaseOwnerOID++ },
		"admin identity":     func(c *adapter.DesiredChange) { c.ExpectedAdminIdentity = otherOwner },
		"missing oid":        func(c *adapter.DesiredChange) { c.ExpectedDatabaseOID = 0 },
		"missing owner":      func(c *adapter.DesiredChange) { c.ExpectedDatabaseOwner = "" },
		"missing owner oid":  func(c *adapter.DesiredChange) { c.ExpectedDatabaseOwnerOID = 0 },
		"missing admin pin":  func(c *adapter.DesiredChange) { c.ExpectedAdminIdentity = "" },
	} {
		t.Run("plan_rejects_"+name, func(t *testing.T) {
			change := base
			mutate(&change)
			if _, err := ad.Plan(t.Context(), change); err == nil {
				t.Fatalf("invalid %s accepted", name)
			}
			assertRoleAbsent(t)
		})
	}

	t.Run("owner_changes_after_plan", func(t *testing.T) {
		plan, err := ad.Plan(t.Context(), base)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cluster.Exec(t.Context(), "alter database "+pgx.Identifier{database}.Sanitize()+
			" owner to "+pgx.Identifier{otherOwner}.Sanitize()); err != nil {
			t.Fatal(err)
		}
		if _, err := ad.Apply(t.Context(), *plan); !errors.Is(err, adapter.ErrTargetIdentityConflict) {
			t.Fatalf("changed owner Apply error = %v", err)
		}
		assertRoleAbsent(t)
		if _, err := cluster.Exec(t.Context(), "alter database "+pgx.Identifier{database}.Sanitize()+
			" owner to "+pgx.Identifier{owner}.Sanitize()); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("drop_recreate_same_name_after_plan", func(t *testing.T) {
		plan, err := ad.Plan(t.Context(), base)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cluster.Exec(t.Context(), "drop database "+pgx.Identifier{database}.Sanitize()+" with (force)"); err != nil {
			t.Fatal(err)
		}
		if _, err := cluster.Exec(t.Context(), "create database "+pgx.Identifier{database}.Sanitize()+
			" owner "+pgx.Identifier{owner}.Sanitize()); err != nil {
			t.Fatal(err)
		}
		var replacementOID uint32
		if err := cluster.QueryRow(t.Context(), `select oid from pg_database where datname=$1`, database).Scan(&replacementOID); err != nil {
			t.Fatal(err)
		}
		if replacementOID == databaseOID {
			t.Fatal("drop/recreate unexpectedly reused database OID")
		}
		currentDatabaseOID = replacementOID
		if _, err := ad.Apply(t.Context(), *plan); !errors.Is(err, adapter.ErrTargetIdentityConflict) {
			t.Fatalf("recreated database Apply error = %v", err)
		}
		if _, err := ad.Verify(t.Context(), *plan); !errors.Is(err, adapter.ErrTargetIdentityConflict) {
			t.Fatalf("recreated database Verify error = %v", err)
		}
		assertRoleAbsent(t)
	})

	t.Run("owner_transfer_drop_recreate_same_name_restore", func(t *testing.T) {
		change := base
		change.ExpectedDatabaseOID = currentDatabaseOID
		plan, err := ad.Plan(t.Context(), change)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cluster.Exec(t.Context(), "alter database "+pgx.Identifier{database}.Sanitize()+
			" owner to "+pgx.Identifier{otherOwner}.Sanitize()); err != nil {
			t.Fatal(err)
		}
		if _, err := cluster.Exec(t.Context(), "drop role "+pgx.Identifier{owner}.Sanitize()); err != nil {
			t.Fatalf("drop original owner after transfer: %v", err)
		}
		if _, err := cluster.Exec(t.Context(), "create role "+pgx.Identifier{owner}.Sanitize()+" nologin"); err != nil {
			t.Fatalf("recreate owner with same name: %v", err)
		}
		var replacementOwnerOID uint32
		if err := cluster.QueryRow(t.Context(), `select oid from pg_roles where rolname=$1`, owner).
			Scan(&replacementOwnerOID); err != nil {
			t.Fatal(err)
		}
		if replacementOwnerOID == ownerOID {
			t.Fatal("drop/recreate unexpectedly reused owner role OID")
		}
		if _, err := cluster.Exec(t.Context(), "alter database "+pgx.Identifier{database}.Sanitize()+
			" owner to "+pgx.Identifier{owner}.Sanitize()); err != nil {
			t.Fatal(err)
		}
		if _, err := ad.Apply(t.Context(), *plan); !errors.Is(err, adapter.ErrTargetIdentityConflict) {
			t.Fatalf("recreated owner Apply error = %v", err)
		}
		if _, err := ad.Verify(t.Context(), *plan); !errors.Is(err, adapter.ErrTargetIdentityConflict) {
			t.Fatalf("recreated owner Verify error = %v", err)
		}
		assertRoleAbsent(t)
	})
}
