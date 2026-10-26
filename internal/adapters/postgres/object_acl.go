package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
)

const stepObjectACL = "postgres-object-acl-v1"

func (a *Adapter) objectACLTransaction(ctx context.Context, c adapter.DesiredChange) (*pgx.Conn, pgx.Tx, adapter.PostgresObjectPrivilege, error) {
	var p adapter.PostgresObjectPrivilege
	if err := adapter.ValidatePostgresObjectACLChange(c); err != nil {
		return nil, nil, p, err
	}
	p, _ = adapter.ParsePostgresObjectPrivilege(c.Permission)
	f := c.ObjectACL
	if c.Connection.ConfigIncarnation != f.ConfigIncarnation || c.Connection.AdminCredentialIncarnation != f.CredentialIncarnation {
		return nil, nil, p, adapter.ErrTargetIdentityConflict
	}
	conn, err := a.connect(ctx, c.Connection, p.Database)
	if err != nil {
		return nil, nil, p, err
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		closeQuietly(ctx, conn)
		return nil, nil, p, err
	}
	if _, err = tx.Exec(ctx, `set local search_path=pg_catalog`); err == nil {
		err = checkObjectACLIdentity(ctx, tx, c, p)
	}
	if err != nil {
		_ = tx.Rollback(ctx)
		closeQuietly(ctx, conn)
		return nil, nil, p, err
	}
	return conn, tx, p, nil
}

func checkObjectACLIdentity(ctx context.Context, q rolePolicyQuerier, c adapter.DesiredChange, p adapter.PostgresObjectPrivilege) error {
	if err := requireLiveProvisioningAuthority(ctx, q, c); err != nil {
		return err
	}
	var databaseOID, subjectOID uint32
	if err := q.QueryRow(ctx, `select oid from pg_catalog.pg_database where datname=current_database()`).Scan(&databaseOID); err != nil {
		return err
	}
	if err := q.QueryRow(ctx, `select oid from pg_catalog.pg_roles where rolname=$1`, c.Account.EngineIdentity).Scan(&subjectOID); err != nil {
		return err
	}
	if databaseOID != p.DatabaseOID || subjectOID != c.ObjectACL.SubjectOID || subjectOID == p.OwnerOID {
		return adapter.ErrTargetIdentityConflict
	}
	_, err := readObjectACL(ctx, q, p)
	return err
}

func readObjectACL(ctx context.Context, q rolePolicyQuerier, p adapter.PostgresObjectPrivilege) ([]objectACLRow, error) {
	var kind, schema, name, column string
	var oid, owner, schemaOID uint32
	var columnNumber int16
	var raw []byte
	err := q.QueryRow(ctx, `select * from (`+objectACLObjectsSQL+`) object_acl where oid=$1 and kind=$2 and column_number=0`, p.ObjectOID, p.Kind).
		Scan(&kind, &schema, &name, &oid, &owner, &schemaOID, &column, &columnNumber, &raw)
	if err != nil {
		return nil, fmt.Errorf("object ACL identity is unavailable: %w", err)
	}
	if kind != p.Kind || schema != p.Schema || name != p.Name || oid != p.ObjectOID || owner != p.OwnerOID || schemaOID != p.SchemaOID {
		return nil, adapter.ErrTargetIdentityConflict
	}
	var rows []objectACLRow
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func objectSubjectGrantors(rows []objectACLRow, subject uint32, privilege string) []adapter.PostgresACLGrantor {
	out := make([]adapter.PostgresACLGrantor, 0)
	for _, r := range rows {
		if r.GranteeOID == subject && r.Privilege == privilege {
			out = append(out, adapter.PostgresACLGrantor{OID: r.GrantorOID, Name: r.Grantor, GrantOption: r.GrantOption})
		}
	}
	slices.SortFunc(out, func(a, b adapter.PostgresACLGrantor) int {
		if a.OID < b.OID {
			return -1
		}
		if a.OID > b.OID {
			return 1
		}
		return 0
	})
	return out
}

func unrelatedObjectACL(rows []objectACLRow, subject uint32, privilege string) []objectACLRow {
	out := make([]objectACLRow, 0)
	for _, r := range rows {
		if r.GranteeOID != subject || r.Privilege != privilege {
			out = append(out, r)
		}
	}
	return out
}

func objectACLTargetSQL(p adapter.PostgresObjectPrivilege) (string, error) {
	if p.Validate() != nil || p.Kind == "column" {
		return "", adapter.ErrPostgresObjectACL
	}
	switch p.Kind {
	case "database":
		return "database " + sanitizeIdent(p.Database), nil
	case "schema":
		return "schema " + sanitizeIdent(p.Schema), nil
	case "sequence":
		return "sequence " + pgx.Identifier{p.Schema, p.Name}.Sanitize(), nil
	case "table", "view", "materialized_view":
		return "table " + pgx.Identifier{p.Schema, p.Name}.Sanitize(), nil
	default:
		return "", adapter.ErrPostgresObjectACL
	}
}

func (a *Adapter) planObjectACL(ctx context.Context, c adapter.DesiredChange) (*adapter.Plan, error) {
	conn, tx, p, err := a.objectACLTransaction(ctx, c)
	if err != nil {
		return nil, err
	}
	defer closeQuietly(ctx, conn)
	defer tx.Rollback(ctx) //nolint:errcheck
	return adapterutil.SingleStepPlan(c, stepObjectACL, fmt.Sprintf("change direct %s on %s for %q", p.Privilege, p.Label(), c.Account.EngineIdentity), nil), nil
}

func (a *Adapter) applyObjectACL(ctx context.Context, plan adapter.Plan) (*adapter.Result, error) {
	if len(plan.Steps) != 1 || plan.Steps[0].Kind != stepObjectACL || len(plan.Steps[0].Attributes) != 0 {
		return nil, adapter.ErrPostgresObjectACL
	}
	c := plan.Change
	conn, tx, p, err := a.objectACLTransaction(ctx, c)
	if err != nil {
		return nil, err
	}
	defer closeQuietly(ctx, conn)
	defer tx.Rollback(ctx) //nolint:errcheck
	before, err := readObjectACL(ctx, tx, p)
	if err != nil {
		return nil, err
	}
	actual := objectSubjectGrantors(before, c.ObjectACL.SubjectOID, p.Privilege)
	grant := c.Kind == adapter.ChangePostgresObjectACLGrantV1
	for _, g := range actual {
		if g.GrantOption {
			return nil, fmt.Errorf("delegating ACL must be reviewed separately: %w", adapter.ErrPostgresObjectACL)
		}
	}
	status := adapter.StepSkipped
	if (grant && len(actual) == 0) || (!grant && len(actual) > 0) {
		target, err := objectACLTargetSQL(p)
		if err != nil {
			return nil, err
		}
		if grant {
			var owner string
			if err := tx.QueryRow(ctx, `select rolname from pg_catalog.pg_roles where oid=$1`, p.OwnerOID).Scan(&owner); err != nil {
				return nil, err
			}
			if _, err := tx.Exec(ctx, "set local role "+sanitizeIdent(owner)); err != nil {
				return nil, err
			}
			if _, err := tx.Exec(ctx, "grant "+p.Privilege+" on "+target+" to "+sanitizeIdent(c.Account.EngineIdentity)); err != nil {
				return nil, err
			}
			if _, err := tx.Exec(ctx, "reset role"); err != nil {
				return nil, err
			}
		} else {
			expected := slices.Clone(c.ObjectACL.Grantors)
			slices.SortFunc(expected, func(a, b adapter.PostgresACLGrantor) int {
				if a.OID < b.OID {
					return -1
				}
				if a.OID > b.OID {
					return 1
				}
				return 0
			})
			if !reflect.DeepEqual(actual, expected) {
				return nil, fmt.Errorf("direct ACL grantors changed: %w", adapter.ErrTargetIdentityConflict)
			}
			var columns bool
			if err := tx.QueryRow(ctx, `select exists(select 1 from pg_catalog.pg_attribute a
			 cross join lateral pg_catalog.aclexplode(a.attacl) acl where a.attrelid=$1 and a.attnum>0 and not a.attisdropped
			 and acl.grantee=$2 and acl.privilege_type=$3)`, p.ObjectOID, c.ObjectACL.SubjectOID, p.Privilege).Scan(&columns); err != nil {
				return nil, err
			}
			if p.Kind != "database" && p.Kind != "schema" && columns {
				return nil, fmt.Errorf("table revoke would remove column privileges: %w", adapter.ErrPostgresObjectACL)
			}
			for _, g := range actual {
				var oid uint32
				if err := tx.QueryRow(ctx, `select oid from pg_catalog.pg_roles where rolname=$1`, g.Name).Scan(&oid); err != nil {
					return nil, err
				}
				if oid != g.OID {
					return nil, adapter.ErrTargetIdentityConflict
				}
				if _, err := tx.Exec(ctx, "set local role "+sanitizeIdent(g.Name)); err != nil {
					return nil, err
				}
				if _, err := tx.Exec(ctx, "revoke "+p.Privilege+" on "+target+" from "+sanitizeIdent(c.Account.EngineIdentity)+" restrict"); err != nil {
					return nil, err
				}
				if _, err := tx.Exec(ctx, "reset role"); err != nil {
					return nil, err
				}
			}
		}
		status = adapter.StepApplied
	}
	after, err := readObjectACL(ctx, tx, p)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(unrelatedObjectACL(before, c.ObjectACL.SubjectOID, p.Privilege), unrelatedObjectACL(after, c.ObjectACL.SubjectOID, p.Privilege)) {
		return nil, fmt.Errorf("unrelated object ACL changed: %w", adapter.ErrExternalIdentityConflict)
	}
	if (len(objectSubjectGrantors(after, c.ObjectACL.SubjectOID, p.Privilege)) > 0) != grant {
		return nil, adapter.ErrExternalIdentityConflict
	}
	// A fresh catalog snapshot detects DDL/name races hidden by the transaction's snapshot.
	fresh, err := a.connect(ctx, c.Connection, p.Database)
	if err != nil {
		return nil, err
	}
	err = checkObjectACLIdentity(ctx, fresh, c, p)
	closeQuietly(ctx, fresh)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &adapter.Result{Steps: []adapter.StepResult{{Step: plan.Steps[0], Status: status}}}, nil
}

func (a *Adapter) verifyObjectACL(ctx context.Context, plan adapter.Plan) (*adapter.Verification, error) {
	conn, tx, p, err := a.objectACLTransaction(ctx, plan.Change)
	if err != nil {
		return nil, err
	}
	defer closeQuietly(ctx, conn)
	defer tx.Rollback(ctx) //nolint:errcheck
	rows, err := readObjectACL(ctx, tx, p)
	if err != nil {
		return nil, err
	}
	present := len(objectSubjectGrantors(rows, plan.Change.ObjectACL.SubjectOID, p.Privilege)) > 0
	for _, grantor := range objectSubjectGrantors(rows, plan.Change.ObjectACL.SubjectOID, p.Privilege) {
		if grantor.GrantOption {
			return nil, adapter.ErrPostgresObjectACL
		}
	}
	v := adapterutil.VerifyResult(present == (plan.Change.Kind == adapter.ChangePostgresObjectACLGrantV1),
		"direct ACL matches intent; role, PUBLIC and ownership access is independent")
	v.Observed = map[string]any{"grantors": objectSubjectGrantors(rows, plan.Change.ObjectACL.SubjectOID, p.Privilege), "direct_privilege": true}
	return v, nil
}
