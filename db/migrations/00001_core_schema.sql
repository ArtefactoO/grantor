-- +goose Up

-- Core metadata schema Grantor (docs/architecture.md, разделы 5–9, 19–22).
-- Требуется PostgreSQL 15+: UNIQUE NULLS NOT DISTINCT (см. ADR-0003).
-- Конвенции: uuid PK через gen_random_uuid(), text + CHECK вместо enum,
-- engine-specific детали в jsonb attributes, все timestamps — timestamptz.
-- Секреты в этой базе не хранятся никогда: только Vault paths и metadata.

create table connections (
    id                    uuid primary key default gen_random_uuid(),
    display_name          text not null,
    engine                text not null,
    environment           text not null default '',
    tags                  jsonb not null default '[]',
    endpoints             jsonb not null default '[]',
    execution_mode        text not null default 'direct'
        check (execution_mode in ('direct', 'connector')),
    -- Только несекретные параметры TLS; private material — в Vault.
    tls_config            jsonb not null default '{}',
    admin_credential_mode text not null default 'provided'
        check (admin_credential_mode in
               ('generated', 'provided', 'existing_vault_ref', 'external_identity')),
    vault_admin_path      text not null default '',
    -- Включённые для этого connection adapter capabilities (раздел 10.3).
    capabilities          jsonb not null default '[]',
    discovery_config      jsonb not null default '{}',
    status                text not null default 'draft'
        check (status in ('draft', 'validating', 'discovering', 'active',
                          'connection_failed', 'discovery_failed',
                          'degraded', 'disabled')),
    server_version        text not null default '',
    topology              jsonb not null default '{}',
    last_discovery_at     timestamptz,
    created_at            timestamptz not null default now(),
    updated_at            timestamptz not null default now()
);

create table resources (
    id             uuid primary key default gen_random_uuid(),
    connection_id  uuid not null references connections (id) on delete cascade,
    parent_id      uuid references resources (id) on delete cascade,
    kind           text not null,
    external_id    text not null,
    name           text not null,
    canonical_path text not null,
    attributes     jsonb not null default '{}',
    fingerprint    text not null default '',
    observed_at    timestamptz,
    status         text not null default 'observed'
        check (status in ('observed', 'planned', 'missing', 'stale')),
    ownership      text not null default 'unmanaged'
        check (ownership in ('managed', 'unmanaged')),
    created_at     timestamptz not null default now(),
    updated_at     timestamptz not null default now(),
    unique (connection_id, kind, external_id)
);

create index resources_connection_parent_idx on resources (connection_id, parent_id);

create table principals (
    id                uuid primary key default gen_random_uuid(),
    type              text not null check (type in ('human', 'service', 'group')),
    display_name      text not null,
    external_provider text not null default '',
    external_subject  text not null default '',
    status            text not null default 'active'
        check (status in ('active', 'disabled')),
    attributes        jsonb not null default '{}',
    created_at        timestamptz not null default now(),
    updated_at        timestamptz not null default now()
);

create unique index principals_external_identity_idx
    on principals (external_provider, external_subject)
    where external_provider <> '' and external_subject <> '';

create table accounts (
    id                   uuid primary key default gen_random_uuid(),
    principal_id         uuid references principals (id) on delete set null,
    connection_id        uuid not null references connections (id) on delete cascade,
    kind                 text not null default 'login'
        check (kind in ('login', 'group')),
    -- Уникален в рамках connection; adapter кодирует движковую дизамбигуацию
    -- (mysql user@host, mongo user@authdb) внутрь engine_identity.
    engine_identity      text not null,
    authentication_scope text not null default '',
    credential_mode      text
        check (credential_mode in
               ('generated', 'provided', 'existing_vault_ref', 'external_identity')),
    vault_path           text not null default '',
    status               text not null default 'active'
        check (status in ('active', 'disabled', 'deleted')),
    ownership            text not null default 'unmanaged'
        check (ownership in ('managed', 'unmanaged')),
    attributes           jsonb not null default '{}',
    created_at           timestamptz not null default now(),
    updated_at           timestamptz not null default now(),
    unique (connection_id, engine_identity)
);

create table permission_definitions (
    id                uuid primary key default gen_random_uuid(),
    connection_id     uuid not null references connections (id) on delete cascade,
    engine            text not null,
    external_id       text not null,
    name              text not null,
    scope_resource_id uuid references resources (id) on delete cascade,
    assignable        boolean not null default false,
    dangerous         boolean not null default false,
    attributes        jsonb not null default '{}',
    created_at        timestamptz not null default now(),
    updated_at        timestamptz not null default now(),
    unique (connection_id, external_id)
);

create table bindings (
    id                       uuid primary key default gen_random_uuid(),
    account_id               uuid not null references accounts (id) on delete cascade,
    permission_definition_id uuid not null
        references permission_definitions (id) on delete cascade,
    scope_resource_id        uuid references resources (id) on delete cascade,
    source                   text not null default 'service'
        check (source in ('service', 'external', 'inherited')),
    -- NULL desired_state — обнаруженный unmanaged binding без принятого
    -- решения (adopt / keep unmanaged / revoke).
    desired_state            text
        check (desired_state in ('present', 'absent')),
    observed_state           text not null default 'unknown'
        check (observed_state in ('present', 'absent', 'unknown')),
    status                   text not null default 'pending'
        check (status in ('synced', 'pending', 'drift', 'failed')),
    expires_at               timestamptz,
    created_at               timestamptz not null default now(),
    updated_at               timestamptz not null default now(),
    unique nulls not distinct (account_id, permission_definition_id, scope_resource_id)
);

create table operations (
    id              uuid primary key default gen_random_uuid(),
    parent_id       uuid references operations (id) on delete cascade,
    idempotency_key text,
    kind            text not null,
    status          text not null default 'pending'
        check (status in ('pending_approval', 'pending', 'running',
                          'success', 'partial', 'failed', 'cancelled')),
    connection_id   uuid references connections (id) on delete set null,
    principal_id    uuid references principals (id) on delete set null,
    account_id      uuid references accounts (id) on delete set null,
    resource_id     uuid references resources (id) on delete set null,
    binding_id      uuid references bindings (id) on delete set null,
    -- payload/plan/result — sanitized: без секретных значений.
    payload         jsonb not null default '{}',
    plan            jsonb,
    result          jsonb,
    error           text not null default '',
    actor_type      text not null default '',
    actor_id        text not null default '',
    approved_by     text,
    approved_at     timestamptz,
    correlation_id  text not null default '',
    created_at      timestamptz not null default now(),
    started_at      timestamptz,
    finished_at     timestamptz,
    updated_at      timestamptz not null default now()
);

create unique index operations_idempotency_key_idx
    on operations (idempotency_key)
    where idempotency_key is not null;
create index operations_connection_status_idx on operations (connection_id, status);
create index operations_parent_idx on operations (parent_id);

-- Append-only: без FK, чтобы события переживали удаление ссылочных строк;
-- update/delete запрещены триггером.
create table audit_events (
    id            bigint generated always as identity primary key,
    occurred_at   timestamptz not null default now(),
    actor_type    text not null,
    actor_id      text not null,
    action        text not null,
    connection_id uuid,
    resource_id   uuid,
    principal_id  uuid,
    account_id    uuid,
    operation_id  uuid,
    result        text not null default '',
    metadata      jsonb not null default '{}'
);

create index audit_events_occurred_idx on audit_events (occurred_at);
create index audit_events_connection_idx on audit_events (connection_id, occurred_at);

-- +goose StatementBegin
create function audit_events_append_only() returns trigger
language plpgsql as $$
begin
    raise exception 'audit_events is append-only';
end;
$$;
-- +goose StatementEnd

create trigger audit_events_no_update_delete
    before update or delete on audit_events
    for each row execute function audit_events_append_only();

-- +goose Down

drop trigger audit_events_no_update_delete on audit_events;
drop function audit_events_append_only();
drop table audit_events;
drop table operations;
drop table bindings;
drop table permission_definitions;
drop table accounts;
drop table principals;
drop table resources;
drop table connections;
