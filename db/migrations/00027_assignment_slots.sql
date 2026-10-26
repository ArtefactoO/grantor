-- +goose Up

-- Exclusive permission assignment foundation. Empty assignment_key preserves
-- the historical many-permissions-per-account model. A non-empty key names a
-- single logical slot (RabbitMQ vhost templates use one slot per vhost).
alter table permission_definitions
    add column assignment_key text not null default '';

alter table bindings
    add column assignment_key text not null default '',
    add column observed_permission_definition_id uuid
        references permission_definitions (id) on delete set null,
    add column observed_attributes jsonb not null default '{}',
    add column binding_version bigint not null default 0
        check (binding_version >= 0),
    add column transition_operation_id uuid
        references operations (id) on delete set null;

-- Existing RabbitMQ vhost-access:<vhost> is the backward-compatible full
-- access template. Backfill only that known namespace; tag permissions and
-- every other engine remain non-exclusive (assignment_key='').
update permission_definitions p
set assignment_key = 'rabbitmq:vhost:' ||
    substr(p.external_id, char_length('vhost-access:') + 1)
from connections c
where c.id = p.connection_id
  and c.engine = 'rabbitmq'
  and p.external_id like 'vhost-access:%'
  and char_length(p.external_id) > char_length('vhost-access:');

update bindings b
set assignment_key = p.assignment_key,
    observed_permission_definition_id = case
        when b.observed_state = 'present' then b.permission_definition_id
        else null
    end,
    observed_attributes = case
        when b.observed_state = 'present' and b.observed_effective
            then p.attributes
        else '{}'::jsonb
    end
from permission_definitions p
where p.id = b.permission_definition_id
  and p.assignment_key <> '';

-- Do not guess which duplicate should survive. CREATE UNIQUE INDEX is the
-- deliberate duplicate-abort gate: if legacy/manual data contains two rows in
-- one exclusive slot, the whole transactional migration fails and leaves the
-- pre-migration schema/data untouched for explicit operator resolution.
create unique index bindings_account_assignment_key_uidx
    on bindings (account_id, assignment_key)
    where assignment_key <> '';

create index bindings_observed_permission_definition_idx
    on bindings (observed_permission_definition_id)
    where observed_permission_definition_id is not null;

create index bindings_transition_operation_idx
    on bindings (transition_operation_id)
    where transition_operation_id is not null;

-- +goose Down
drop index if exists bindings_transition_operation_idx;
drop index if exists bindings_observed_permission_definition_idx;
drop index if exists bindings_account_assignment_key_uidx;

alter table bindings
    drop column transition_operation_id,
    drop column binding_version,
    drop column observed_attributes,
    drop column observed_permission_definition_id,
    drop column assignment_key;

alter table permission_definitions
    drop column assignment_key;
