package postgres

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/postgresconfig"
)

type directACLTarget struct {
	kind    string
	name1   string
	name2   string
	name3   string
	oid     uint32
	grantor string
}

func collectDirectPolicyRevokes(
	ctx context.Context,
	tx pgx.Tx,
	role string,
	admin string,
) ([]directPolicyStatement, error) {
	targets, err := collectDirectACLTargets(ctx, tx, role)
	if err != nil {
		return nil, err
	}
	defaults, err := collectDirectDefaultACLRevokes(ctx, tx, role)
	if err != nil {
		return nil, err
	}
	byGrantor := make(map[string][]directPolicyStatement)
	seen := make(map[string]struct{}, len(targets)+len(defaults))
	for _, target := range targets {
		statement, err := directACLRevokeStatement(target, role)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[statement.sql]; duplicate {
			continue
		}
		seen[statement.sql] = struct{}{}
		byGrantor[target.grantor] = append(byGrantor[target.grantor], statement)
	}
	grantors := make([]string, 0, len(byGrantor))
	for grantor := range byGrantor {
		grantors = append(grantors, grantor)
		slices.SortFunc(byGrantor[grantor], compareDirectPolicyStatement)
	}
	slices.Sort(grantors)
	out := make([]directPolicyStatement, 0, len(targets)+len(defaults)+2*len(grantors))
	for _, grantor := range grantors {
		if grantor != admin {
			out = append(out, directPolicyStatement{kind: "set-acl-grantor-role",
				sql: "set local role " + sanitizeIdent(grantor)})
		}
		out = append(out, byGrantor[grantor]...)
		if grantor != admin {
			out = append(out, directPolicyStatement{kind: "reset-acl-grantor-role", sql: "reset role"})
		}
	}
	slices.SortFunc(defaults, compareDirectPolicyStatement)
	for _, statement := range defaults {
		if _, duplicate := seen[statement.sql]; duplicate {
			continue
		}
		seen[statement.sql] = struct{}{}
		out = append(out, statement)
	}
	return out, nil
}

func compareDirectPolicyStatement(left, right directPolicyStatement) int {
	if left.kind != right.kind {
		if left.kind < right.kind {
			return -1
		}
		return 1
	}
	if left.sql < right.sql {
		return -1
	}
	if left.sql > right.sql {
		return 1
	}
	return 0
}

func collectDirectACLTargets(
	ctx context.Context,
	tx pgx.Tx,
	role string,
) ([]directACLTarget, error) {
	rows, err := tx.Query(ctx, `
		select distinct target_kind, name1, name2, name3, object_oid, grantor_name
		from (
			select 'database'::text as target_kind, d.datname::text as name1,
			       ''::text as name2, ''::text as name3, 0::oid as object_oid,
			       grantor.rolname::text as grantor_name
			from pg_catalog.pg_database d
			cross join lateral pg_catalog.aclexplode(d.datacl) acl
			join pg_catalog.pg_roles grantee on grantee.oid = acl.grantee
			join pg_catalog.pg_roles grantor on grantor.oid = acl.grantor
			where grantee.rolname = $1
			union all
			select 'schema', n.nspname, '', '', 0::oid, grantor.rolname
			from pg_catalog.pg_namespace n
			cross join lateral pg_catalog.aclexplode(n.nspacl) acl
			join pg_catalog.pg_roles grantee on grantee.oid = acl.grantee
			join pg_catalog.pg_roles grantor on grantor.oid = acl.grantor
			where grantee.rolname = $1
			union all
			select case when c.relkind = 'S' then 'sequence' else 'table' end,
			       n.nspname, c.relname, '', 0::oid, grantor.rolname
			from pg_catalog.pg_class c
			join pg_catalog.pg_namespace n on n.oid = c.relnamespace
			cross join lateral pg_catalog.aclexplode(c.relacl) acl
			join pg_catalog.pg_roles grantee on grantee.oid = acl.grantee
			join pg_catalog.pg_roles grantor on grantor.oid = acl.grantor
			where grantee.rolname = $1 and c.relkind in ('r','p','v','m','f','S')
			union all
			select 'column', n.nspname, c.relname, a.attname, 0::oid, grantor.rolname
			from pg_catalog.pg_attribute a
			join pg_catalog.pg_class c on c.oid = a.attrelid
			join pg_catalog.pg_namespace n on n.oid = c.relnamespace
			cross join lateral pg_catalog.aclexplode(a.attacl) acl
			join pg_catalog.pg_roles grantee on grantee.oid = acl.grantee
			join pg_catalog.pg_roles grantor on grantor.oid = acl.grantor
			where grantee.rolname = $1 and a.attnum > 0 and not a.attisdropped
			union all
			select 'routine', p.oid::pg_catalog.regprocedure::text, '', '', 0::oid, grantor.rolname
			from pg_catalog.pg_proc p
			cross join lateral pg_catalog.aclexplode(p.proacl) acl
			join pg_catalog.pg_roles grantee on grantee.oid = acl.grantee
			join pg_catalog.pg_roles grantor on grantor.oid = acl.grantor
			where grantee.rolname = $1
			union all
			select 'type', n.nspname, t.typname, '', 0::oid, grantor.rolname
			from pg_catalog.pg_type t
			join pg_catalog.pg_namespace n on n.oid = t.typnamespace
			cross join lateral pg_catalog.aclexplode(t.typacl) acl
			join pg_catalog.pg_roles grantee on grantee.oid = acl.grantee
			join pg_catalog.pg_roles grantor on grantor.oid = acl.grantor
			where grantee.rolname = $1
			union all
			select 'large-object', '', '', '', l.oid, grantor.rolname
			from pg_catalog.pg_largeobject_metadata l
			cross join lateral pg_catalog.aclexplode(l.lomacl) acl
			join pg_catalog.pg_roles grantee on grantee.oid = acl.grantee
			join pg_catalog.pg_roles grantor on grantor.oid = acl.grantor
			where grantee.rolname = $1
			union all
			select 'foreign-data-wrapper', f.fdwname, '', '', 0::oid, grantor.rolname
			from pg_catalog.pg_foreign_data_wrapper f
			cross join lateral pg_catalog.aclexplode(f.fdwacl) acl
			join pg_catalog.pg_roles grantee on grantee.oid = acl.grantee
			join pg_catalog.pg_roles grantor on grantor.oid = acl.grantor
			where grantee.rolname = $1
			union all
			select 'foreign-server', s.srvname, '', '', 0::oid, grantor.rolname
			from pg_catalog.pg_foreign_server s
			cross join lateral pg_catalog.aclexplode(s.srvacl) acl
			join pg_catalog.pg_roles grantee on grantee.oid = acl.grantee
			join pg_catalog.pg_roles grantor on grantor.oid = acl.grantor
			where grantee.rolname = $1
			union all
			select 'language', l.lanname, '', '', 0::oid, grantor.rolname
			from pg_catalog.pg_language l
			cross join lateral pg_catalog.aclexplode(l.lanacl) acl
			join pg_catalog.pg_roles grantee on grantee.oid = acl.grantee
			join pg_catalog.pg_roles grantor on grantor.oid = acl.grantor
			where grantee.rolname = $1
			union all
			select 'tablespace', t.spcname, '', '', 0::oid, grantor.rolname
			from pg_catalog.pg_tablespace t
			cross join lateral pg_catalog.aclexplode(t.spcacl) acl
			join pg_catalog.pg_roles grantee on grantee.oid = acl.grantee
			join pg_catalog.pg_roles grantor on grantor.oid = acl.grantor
			where grantee.rolname = $1
			union all
			select 'parameter', p.parname, '', '', 0::oid, grantor.rolname
			from pg_catalog.pg_parameter_acl p
			cross join lateral pg_catalog.aclexplode(p.paracl) acl
			join pg_catalog.pg_roles grantee on grantee.oid = acl.grantee
			join pg_catalog.pg_roles grantor on grantor.oid = acl.grantor
			where grantee.rolname = $1
		) targets
		order by target_kind, name1, name2, name3, object_oid, grantor_name`, role)
	if err != nil {
		return nil, fmt.Errorf("query direct role policy ACL targets: %w", err)
	}
	defer rows.Close()
	var out []directACLTarget
	for rows.Next() {
		var target directACLTarget
		if err := rows.Scan(&target.kind, &target.name1, &target.name2, &target.name3,
			&target.oid, &target.grantor); err != nil {
			return nil, fmt.Errorf("scan direct role policy ACL target: %w", err)
		}
		out = append(out, target)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read direct role policy ACL targets: %w", err)
	}
	return out, nil
}

func directACLRevokeStatement(target directACLTarget, role string) (directPolicyStatement, error) {
	if target.grantor == "" {
		return directPolicyStatement{}, errors.New("direct ACL target has no grantor")
	}
	roleSQL := sanitizeIdent(role)
	grantorSQL := sanitizeIdent(target.grantor)
	var object string
	switch target.kind {
	case "database":
		object = "database " + sanitizeIdent(target.name1)
	case "schema":
		object = "schema " + sanitizeIdent(target.name1)
	case "table":
		object = "table " + pgx.Identifier{target.name1, target.name2}.Sanitize()
	case "sequence":
		object = "sequence " + pgx.Identifier{target.name1, target.name2}.Sanitize()
	case "column":
		return directPolicyStatement{kind: "revoke-column", sql: "revoke all privileges (" +
			sanitizeIdent(target.name3) + ") on table " +
			pgx.Identifier{target.name1, target.name2}.Sanitize() + " from " + roleSQL +
			" granted by " + grantorSQL + " restrict"}, nil
	case "routine":
		if err := validateCatalogRoutineIdentity(target.name1); err != nil {
			return directPolicyStatement{}, err
		}
		object = "routine " + target.name1
	case "type":
		object = "type " + pgx.Identifier{target.name1, target.name2}.Sanitize()
	case "large-object":
		if target.oid == 0 {
			return directPolicyStatement{}, errors.New("large object ACL target has an invalid OID")
		}
		object = "large object " + numericObjectIdentity(target.oid)
	case "foreign-data-wrapper":
		object = "foreign data wrapper " + sanitizeIdent(target.name1)
	case "foreign-server":
		object = "foreign server " + sanitizeIdent(target.name1)
	case "language":
		object = "language " + sanitizeIdent(target.name1)
	case "tablespace":
		object = "tablespace " + sanitizeIdent(target.name1)
	case "parameter":
		object = "parameter " + sanitizeIdent(target.name1)
	default:
		return directPolicyStatement{}, fmt.Errorf("direct ACL target kind %q is not in the closed vocabulary", target.kind)
	}
	return directPolicyStatement{kind: "revoke-" + target.kind,
		sql: "revoke all privileges on " + object + " from " + roleSQL +
			" granted by " + grantorSQL + " restrict"}, nil
}

func collectDirectDefaultACLRevokes(
	ctx context.Context,
	tx pgx.Tx,
	role string,
) ([]directPolicyStatement, error) {
	rows, err := tx.Query(ctx, `
		select distinct creator.rolname, coalesce(n.nspname, ''),
		       d.defaclobjtype::text, grantor.rolname
		from pg_catalog.pg_default_acl d
		join pg_catalog.pg_roles creator on creator.oid = d.defaclrole
		left join pg_catalog.pg_namespace n on n.oid = d.defaclnamespace
		cross join lateral pg_catalog.aclexplode(d.defaclacl) acl
		join pg_catalog.pg_roles grantee on grantee.oid = acl.grantee
		join pg_catalog.pg_roles grantor on grantor.oid = acl.grantor
		where grantee.rolname = $1
		order by creator.rolname, coalesce(n.nspname, ''), d.defaclobjtype::text, grantor.rolname`, role)
	if err != nil {
		return nil, fmt.Errorf("query direct role policy default ACL targets: %w", err)
	}
	defer rows.Close()
	var out []directPolicyStatement
	for rows.Next() {
		var creator, schema, objectType, grantor string
		if err := rows.Scan(&creator, &schema, &objectType, &grantor); err != nil {
			return nil, fmt.Errorf("scan direct role policy default ACL target: %w", err)
		}
		if grantor != creator {
			return nil, fmt.Errorf("default ACL for creator %q has alternate grantor %q", creator, grantor)
		}
		objectKind, ok := map[string]string{
			"r": "tables", "S": "sequences", "f": "functions", "T": "types", "n": "schemas",
		}[objectType]
		if !ok {
			return nil, fmt.Errorf("default ACL object type %q is not in the closed vocabulary", objectType)
		}
		prefix := "alter default privileges for role " + sanitizeIdent(creator)
		if schema != "" {
			if objectKind == "schemas" {
				return nil, errors.New("per-schema default privileges on schemas are not safely addressable")
			}
			prefix += " in schema " + sanitizeIdent(schema)
		}
		out = append(out, directPolicyStatement{kind: "revoke-default-" + objectKind,
			sql: prefix + " revoke all privileges on " + objectKind + " from " +
				sanitizeIdent(role) + " restrict"})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read direct role policy default ACL targets: %w", err)
	}
	return out, nil
}

func addDesiredCurrentObjectGrants(
	ctx context.Context,
	tx pgx.Tx,
	template postgresconfig.RolePolicyTemplate,
	statements []directPolicyStatement,
) ([]directPolicyStatement, error) {
	return appendCurrentObjectGrants(ctx, tx, template, statements)
}
