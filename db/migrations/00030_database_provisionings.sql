-- +goose Up
-- A receipt is independent from the outer River transaction: discovering a
-- database with the same name is never evidence that this operation created it.
create table database_provisionings (
    operation_id uuid primary key references operations(id) on delete cascade,
    resource_id uuid not null references resources(id) on delete cascade,
    connection_id uuid not null references connections(id) on delete cascade,
    phase text not null default 'pending'
        check (phase in ('pending','database_creating','database_created','catalog_prepared','read_created','complete')),
    database_create_started boolean not null default false,
    database_created boolean not null default false,
    database_oid bigint not null default 0 check (database_oid between 0 and 4294967295),
    database_owner text not null default '',
    target_identity text not null default '',
    templates jsonb not null default '[]' check (jsonb_typeof(templates) = 'array'),
    read_policy_key text not null default '',
    read_write_policy_key text not null default '',
    read_created boolean not null default false,
    read_write_created boolean not null default false,
    error_code text not null default '',
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    check (not database_created or (database_create_started and database_oid > 0 and database_owner <> '' and target_identity <> '')),
    check (not read_created or database_created),
    check (not read_write_created or read_created),
    check (phase <> 'complete' or read_write_created),
    check (phase not in ('catalog_prepared','read_created','complete') or
        (database_created and jsonb_array_length(templates) = 2 and read_policy_key <> '' and read_write_policy_key <> ''))
);
create index database_provisionings_connection_idx on database_provisionings(connection_id);

-- +goose Down
drop table database_provisionings;
