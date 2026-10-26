package inventory

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type DirectAccessSummary struct {
	Objects   int `json:"direct_objects"`
	Bindings  int `json:"direct_bindings"`
	Unmanaged int `json:"unmanaged_direct_bindings"`
	Dangerous int `json:"unmanaged_dangerous_direct_bindings"`
	ReadOnly  int `json:"readonly_direct_bindings"`
}

func (s *Store) DirectAccessSummaries(ctx context.Context, q Querier, connectionID uuid.UUID) (map[uuid.UUID]DirectAccessSummary, error) {
	rows, err := q.Query(ctx, `select b.account_id,
	 count(distinct coalesce(b.scope_resource_id,b.permission_definition_id)),count(*),
	 count(*) filter(where b.desired_state is null and b.observed_attributes->'managed_binding_eligible' is distinct from 'false'::jsonb),
	 count(*) filter(where b.desired_state is null and p.dangerous and b.observed_attributes->'managed_binding_eligible' is distinct from 'false'::jsonb),
	 count(*) filter(where b.desired_state is null and b.observed_attributes->'managed_binding_eligible'='false'::jsonb)
	 from bindings b join accounts a on a.id=b.account_id join permission_definitions p on p.id=b.permission_definition_id
	 where a.connection_id=$1 and p.connection_id=$1 and p.engine='postgres' and p.external_id like 'pgacl:v1:%'
	 and b.observed_state='present' group by b.account_id`, connectionID)
	if err != nil {
		return nil, fmt.Errorf("inventory: direct access summaries: %w", err)
	}
	defer rows.Close()
	out := map[uuid.UUID]DirectAccessSummary{}
	for rows.Next() {
		var id uuid.UUID
		var summary DirectAccessSummary
		if err := rows.Scan(&id, &summary.Objects, &summary.Bindings, &summary.Unmanaged, &summary.Dangerous, &summary.ReadOnly); err != nil {
			return nil, err
		}
		out[id] = summary
	}
	return out, rows.Err()
}

func (s *Store) ListRolePermissions(ctx context.Context, q Querier, connectionID uuid.UUID) ([]Permission, error) {
	rows, err := q.Query(ctx, `select `+permissionColumns+` from permission_definitions where connection_id=$1 and not(engine='postgres' and external_id like 'pgacl:v1:%') order by external_id`, connectionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Permission{}
	for rows.Next() {
		p, err := scanPermission(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) ListRoleBindingsByConnection(ctx context.Context, q Querier, connectionID uuid.UUID) ([]Binding, error) {
	rows, err := q.Query(ctx, `select `+bindingColumnsB+` from bindings b join accounts a on a.id=b.account_id join permission_definitions p on p.id=b.permission_definition_id
	 where a.connection_id=$1 and p.connection_id=$1 and not(p.engine='postgres' and p.external_id like 'pgacl:v1:%') order by b.account_id,b.created_at,b.id`, connectionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Binding{}
	for rows.Next() {
		b, err := scanBinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) ObjectPrivilegeRevision(ctx context.Context, q Querier, accountID uuid.UUID) (time.Time, error) {
	var stamp time.Time
	err := q.QueryRow(ctx, `select coalesce(max(b.updated_at),'epoch'::timestamptz) from bindings b join permission_definitions p on p.id=b.permission_definition_id where b.account_id=$1 and p.engine='postgres' and p.external_id like 'pgacl:v1:%'`, accountID).Scan(&stamp)
	return stamp, err
}

func (s *Store) ResourceNamesForPermissions(ctx context.Context, q Querier, connectionID uuid.UUID, permissions []Permission) (map[uuid.UUID]string, error) {
	ids := []uuid.UUID{}
	for _, p := range permissions {
		if p.ScopeResourceID != nil {
			ids = append(ids, *p.ScopeResourceID)
		}
	}
	out := map[uuid.UUID]string{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := q.Query(ctx, `select id,name from resources where connection_id=$1 and id=any($2::uuid[])`, connectionID, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		out[id] = name
	}
	return out, rows.Err()
}

func (s *Store) ListRoleBindingsByAccount(ctx context.Context, q Querier, accountID uuid.UUID) ([]Binding, error) {
	return s.listBindings(ctx, q, `account_id=$1 and permission_definition_id in(select id from permission_definitions where not(engine='postgres' and external_id like 'pgacl:v1:%'))`, accountID)
}

func (s *Store) ListResourcesByKind(ctx context.Context, q Querier, connectionID uuid.UUID, kind string) ([]Resource, error) {
	rows, err := q.Query(ctx, `select `+resourceColumns+` from resources where connection_id=$1 and kind=$2 order by external_id`, connectionID, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Resource{}
	for rows.Next() {
		r, err := scanResource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

type ObjectPrivilegeKey struct {
	ScopeID uuid.UUID `json:"scope_id"`
	Column  string    `json:"column"`
	Label   string    `json:"label"`
}

const observedObjectKeysSQL = `select p.scope_resource_id scope_id,coalesce(p.attributes->>'column','') column_name,
 min(r.canonical_path)||case when coalesce(p.attributes->>'column','')='' then '' else '.'||coalesce(p.attributes->>'column','') end label
 from bindings b join permission_definitions p on p.id=b.permission_definition_id join resources r on r.id=p.scope_resource_id
 where b.account_id=$1 and p.connection_id=$2 and r.connection_id=$2 and p.engine='postgres' and p.external_id like 'pgacl:v1:%'
 and (b.observed_state='present' or b.desired_state='present' or (b.desired_state is not null and b.status in ('pending','failed','drift')))
 and ($3='' or strpos(lower(p.name),lower($3))>0)
 group by p.scope_resource_id,coalesce(p.attributes->>'column','')`

func (s *Store) ListObjectPrivilegeKeys(ctx context.Context, q Querier, accountID, connectionID uuid.UUID, search string, after ObjectPrivilegeKey, limit int) ([]ObjectPrivilegeKey, int, error) {
	if limit < 1 || limit > 50 {
		return nil, 0, fmt.Errorf("inventory: object page limit is out of range")
	}
	var total int
	if err := q.QueryRow(ctx, `select count(*) from (`+observedObjectKeysSQL+`) keys`, accountID, connectionID, search).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := q.Query(ctx, `with keys as (`+observedObjectKeysSQL+`) select scope_id,column_name,label from keys
	 where $4='' or (label,scope_id,column_name)>($4,$5::uuid,$6) order by label,scope_id,column_name limit $7`, accountID, connectionID, search, after.Label, after.ScopeID, after.Column, limit+1)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []ObjectPrivilegeKey{}
	for rows.Next() {
		var key ObjectPrivilegeKey
		if err := rows.Scan(&key.ScopeID, &key.Column, &key.Label); err != nil {
			return nil, 0, err
		}
		out = append(out, key)
	}
	return out, total, rows.Err()
}

func (s *Store) ObjectPrivilegeDefinitions(ctx context.Context, q Querier, accountID, connectionID uuid.UUID, keys []ObjectPrivilegeKey) ([]Permission, error) {
	ids := make([]uuid.UUID, 0, len(keys))
	columns := make([]string, 0, len(keys))
	for _, key := range keys {
		ids = append(ids, key.ScopeID)
		columns = append(columns, key.Column)
	}
	rows, err := q.Query(ctx, `select `+permissionColumns+` from permission_definitions where connection_id=$1 and engine='postgres' and external_id like 'pgacl:v1:%'
	 and (scope_resource_id,coalesce(attributes->>'column','')) in(select * from unnest($2::uuid[],$3::text[]))
	 and (status='observed' or exists(select 1 from bindings b where b.account_id=$4 and b.permission_definition_id=permission_definitions.id
 and (b.observed_state='present' or b.desired_state='present' or (b.desired_state is not null and b.status in ('pending','failed','drift')))))
	 order by external_id`, connectionID, ids, columns, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Permission{}
	for rows.Next() {
		p, err := scanPermission(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Object ACL pages expose only bounded observation metadata. Mutation paths
// continue to read full grantor evidence through the ordinary binding methods.
const objectBindingAttributesSQL = `jsonb_strip_nulls(jsonb_build_object(
 'direct_privilege',case when jsonb_typeof(observed_attributes->'direct_privilege')='boolean' then observed_attributes->'direct_privilege' end,
 'managed_binding_eligible',case when jsonb_typeof(observed_attributes->'managed_binding_eligible')='boolean' then observed_attributes->'managed_binding_eligible' end,
 'grantors_count',case when jsonb_typeof(observed_attributes->'grantors')='array' then jsonb_array_length(observed_attributes->'grantors') end))`

func (s *Store) BindingsForDefinitions(ctx context.Context, q Querier, accountID uuid.UUID, definitions []Permission) ([]Binding, error) {
	ids := make([]uuid.UUID, 0, len(definitions))
	for _, p := range definitions {
		ids = append(ids, p.ID)
	}
	columns := strings.Replace(bindingColumns, "observed_attributes", objectBindingAttributesSQL, 1)
	rows, err := q.Query(ctx, `select `+columns+` from bindings where account_id=$1 and permission_definition_id=any($2::uuid[]) order by created_at,id`, accountID, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Binding{}
	for rows.Next() {
		b, err := scanBinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) ListObjectPrivilegeTargets(ctx context.Context, q Querier, connectionID uuid.UUID, search, afterLabel string, afterID uuid.UUID, limit int) ([]Resource, error) {
	if limit < 1 || limit > 50 {
		return nil, fmt.Errorf("inventory: target page limit is out of range")
	}
	rows, err := q.Query(ctx, `select `+resourceColumns+` from resources r where connection_id=$1 and status='observed'
	 and ($2='' or strpos(lower(canonical_path),lower($2))>0)
	 and ($3='' or (canonical_path,id)>($3,$4::uuid))
	 and exists(select 1 from permission_definitions p where p.connection_id=$1 and p.scope_resource_id=r.id and p.engine='postgres'
	 and p.external_id like 'pgacl:v1:%' and coalesce(p.attributes->>'column','')='' and p.assignable and p.status='observed')
	 order by canonical_path,id limit $5`, connectionID, search, afterLabel, afterID, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Resource{}
	for rows.Next() {
		r, err := scanResource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
