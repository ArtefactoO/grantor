package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

const objectACLObjectsSQL = `with objects as (
 select 'database'::text kind,''::text schema,d.datname name,d.oid,d.datdba owner_oid,
        0::oid schema_oid,d.datacl acl,''::text column_name,0::int2 column_number
 from pg_catalog.pg_database d where d.datname=current_database()
 union all
 select 'schema',n.nspname,n.nspname,n.oid,n.nspowner,n.oid,n.nspacl,'',0::int2
 from pg_catalog.pg_namespace n
 where n.nspname<>'information_schema' and n.nspname not like 'pg\_%'
 union all
 select case c.relkind when 'S' then 'sequence' when 'v' then 'view' when 'm' then 'materialized_view' else 'table' end,
 n.nspname,c.relname,c.oid,c.relowner,n.oid,c.relacl,'',0::int2
 from pg_catalog.pg_class c join pg_catalog.pg_namespace n on n.oid=c.relnamespace
 where c.relkind in ('r','p','f','v','m','S') and n.nspname<>'information_schema' and n.nspname not like 'pg\_%'
 union all
 select 'column',n.nspname,c.relname,c.oid,c.relowner,n.oid,a.attacl,a.attname,a.attnum
 from pg_catalog.pg_attribute a join pg_catalog.pg_class c on c.oid=a.attrelid
 join pg_catalog.pg_namespace n on n.oid=c.relnamespace
 where c.relkind in ('r','p','f') and a.attnum>0 and not a.attisdropped and a.attacl is not null
 and n.nspname<>'information_schema' and n.nspname not like 'pg\_%'
)
select o.kind,o.schema,o.name,o.oid,o.owner_oid,o.schema_oid,o.column_name,o.column_number,
 coalesce((select jsonb_agg(jsonb_build_object('grantee_oid',a.grantee::bigint,'grantee',coalesce(r.rolname,'PUBLIC'),
 'grantor_oid',a.grantor::bigint,'grantor',g.rolname,'privilege',a.privilege_type,'grant_option',a.is_grantable)
 order by a.grantee,a.privilege_type,a.grantor)
 from pg_catalog.aclexplode(o.acl) a left join pg_catalog.pg_roles r on r.oid=a.grantee
 join pg_catalog.pg_roles g on g.oid=a.grantor),'[]'::jsonb)
from objects o order by o.kind,o.schema,o.name,o.column_number`

type objectACLRow struct {
	GranteeOID  uint32 `json:"grantee_oid"`
	Grantee     string `json:"grantee"`
	GrantorOID  uint32 `json:"grantor_oid"`
	Grantor     string `json:"grantor"`
	Privilege   string `json:"privilege"`
	GrantOption bool   `json:"grant_option"`
}

type objectACLSnapshot struct {
	permissions []adapter.ObservedPermission
	bindings    []adapter.ObservedBinding
	public      map[string][]string
	defaults    []map[string]any
}

func (a *Adapter) discoverObjectACLs(ctx context.Context, cfg adapter.Connection, db databaseInfo,
	target string, assignable bool, known map[string]roleInfo,
) (objectACLSnapshot, error) {
	out := objectACLSnapshot{public: map[string][]string{}}
	conn, err := a.connect(ctx, cfg, db.name)
	if err != nil {
		return out, err
	}
	defer closeQuietly(ctx, conn)
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return out, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	rows, err := tx.Query(ctx, objectACLObjectsSQL)
	if err != nil {
		return out, fmt.Errorf("read object ACLs in %q: %w", db.name, err)
	}
	for rows.Next() {
		p := adapter.PostgresObjectPrivilege{TargetIdentity: target, Database: db.name, DatabaseOID: db.oid}
		var raw []byte
		if err := rows.Scan(&p.Kind, &p.Schema, &p.Name, &p.ObjectOID, &p.OwnerOID, &p.SchemaOID, &p.Column, &p.ColumnNumber, &raw); err != nil {
			rows.Close()
			return out, err
		}
		var grants []objectACLRow
		if err := json.Unmarshal(raw, &grants); err != nil {
			rows.Close()
			return out, err
		}
		for _, privilege := range adapter.PostgresObjectPrivileges(p.Kind) {
			p.Privilege = privilege
			if err := p.Validate(); err != nil {
				rows.Close()
				return out, err
			}
			id := p.PermissionID()
			out.permissions = append(out.permissions, adapter.ObservedPermission{
				ExternalID: id, Name: privilege + " ON " + p.Label(), ScopeExternalID: p.Scope(),
				Assignable: assignable && p.Kind != "column", Dangerous: privilege == "CREATE" || privilege == "TRIGGER" || privilege == "TRUNCATE",
				Attributes: map[string]any{"kind": "postgres_object_privilege", "object_kind": p.Kind, "database": p.Database,
					"schema": p.Schema, "object": p.Name, "privilege": privilege, "column": p.Column, "object_oid": p.ObjectOID},
			})
			bySubject := map[string][]adapter.PostgresACLGrantor{}
			for _, g := range grants {
				if g.Privilege != privilege {
					continue
				}
				if g.GranteeOID == 0 {
					label := privilege
					if p.Column != "" {
						label += " (" + p.Column + ")"
					}
					out.public[p.Scope()] = append(out.public[p.Scope()], label)
					continue
				}
				if g.GranteeOID == p.OwnerOID || ProtectedRole(g.Grantee) {
					continue
				}
				role, ok := known[g.Grantee]
				if !ok || role.oid != g.GranteeOID {
					rows.Close()
					return out, fmt.Errorf("role catalog changed during ACL discovery")
				}
				bySubject[g.Grantee] = append(bySubject[g.Grantee], adapter.PostgresACLGrantor{OID: g.GrantorOID, Name: g.Grantor, GrantOption: g.GrantOption})
			}
			for subject, grantors := range bySubject {
				eligible := p.Kind != "column"
				for _, g := range grantors {
					if g.GrantOption {
						eligible = false
					}
				}
				slices.SortFunc(grantors, func(a, b adapter.PostgresACLGrantor) int { return strings.Compare(a.Name, b.Name) })
				out.bindings = append(out.bindings, adapter.ObservedBinding{AccountEngineIdentity: subject, PermissionExternalID: id,
					ScopeExternalID: p.Scope(), Attributes: map[string]any{"grantors": grantors, "direct_privilege": true, "managed_binding_eligible": eligible}})
			}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, err
	}
	defaults, err := tx.Query(ctx, `select creator.rolname,coalesce(n.nspname,''),d.defaclobjtype::text,
		coalesce(grantee.rolname,'PUBLIC'),a.privilege_type,a.is_grantable
		from pg_catalog.pg_default_acl d join pg_catalog.pg_roles creator on creator.oid=d.defaclrole
		left join pg_catalog.pg_namespace n on n.oid=d.defaclnamespace
		cross join lateral pg_catalog.aclexplode(d.defaclacl) a left join pg_catalog.pg_roles grantee on grantee.oid=a.grantee
		order by creator.rolname,n.nspname,d.defaclobjtype,grantee.rolname,a.privilege_type`)
	if err != nil {
		return out, err
	}
	for defaults.Next() {
		var creator, schema, kind, grantee, privilege string
		var grantable bool
		if err := defaults.Scan(&creator, &schema, &kind, &grantee, &privilege, &grantable); err != nil {
			defaults.Close()
			return out, err
		}
		out.defaults = append(out.defaults, map[string]any{"database": db.name, "creator": creator, "schema": schema, "kind": kind,
			"grantee": grantee, "privilege": privilege, "grant_option": grantable})
	}
	defaults.Close()
	return out, defaults.Err()
}
