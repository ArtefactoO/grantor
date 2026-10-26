-- +goose Up
create table connection_credential_sources (
    id uuid primary key,
    name text not null check (length(name) between 1 and 160),
    owner_type text not null check (owner_type in ('service', 'user')),
    owner_id uuid not null,
    environment text not null check (length(environment) between 1 and 160),
    target_spec jsonb not null check (jsonb_typeof(target_spec) = 'object'),
    version integer not null default 0 check (version >= 0),
    status text not null default 'preparing' check (status in ('preparing', 'active', 'revoked')),
    cleanup_pending boolean not null default false,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    revoked_at timestamptz,
    check (status != 'active' or version > 0),
    check ((status = 'revoked') = (revoked_at is not null))
);
create index connection_credential_sources_owner_idx
    on connection_credential_sources(owner_type, owner_id, environment);

-- +goose StatementBegin
create function guard_connection_credential_source() returns trigger language plpgsql as $$
begin
    if row(new.id,new.name,new.owner_type,new.owner_id,new.environment,new.target_spec,new.created_at)
       is distinct from
       row(old.id,old.name,old.owner_type,old.owner_id,old.environment,old.target_spec,old.created_at) or
       (old.version > 0 and new.version <> old.version) or
       (old.status = 'revoked' and new.status <> 'revoked') or
       (old.status = 'active' and new.status = 'preparing') then
        raise exception 'connection credential source approval is immutable' using errcode = '23514';
    end if;
    return new;
end;
$$;
-- +goose StatementEnd
create trigger connection_credential_source_immutable before update on connection_credential_sources
    for each row execute function guard_connection_credential_source();

-- These IDs are reserved before Vault IO. They deliberately have no FK to
-- connection/operation rows, which do not exist until finalization and may
-- later be removed by normal lifecycle/retention. The receipt still prevents
-- accidental re-registration after such removal.
create table connection_registrations (
    id uuid primary key,
    owner_type text not null check (owner_type in ('service', 'user')),
    owner_id uuid not null,
    registration_key text not null check (length(registration_key) between 1 and 128),
    environment text not null,
    spec jsonb not null check (jsonb_typeof(spec) = 'object'),
    credential_source_id uuid not null references connection_credential_sources(id),
    credential_source_version integer not null check (credential_source_version > 0),
    connection_id uuid not null unique,
    operation_id uuid not null unique,
    phase text not null default 'preparing' check (phase in ('preparing', 'credential_ready', 'registered', 'canceling', 'cancelled')),
    canonical_version integer not null default 0 check (canonical_version >= 0),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique(owner_type, owner_id, registration_key),
    check ((phase = 'preparing' and canonical_version = 0) or
           (phase in ('credential_ready', 'registered') and canonical_version > 0) or
           phase in ('canceling', 'cancelled'))
);
create index connection_registrations_owner_idx on connection_registrations(owner_type, owner_id, created_at desc);

create table connection_registration_requests (
    owner_type text not null,
    owner_id uuid not null,
    request_id uuid not null,
    registration_id uuid not null references connection_registrations(id),
    primary key(owner_type, owner_id, request_id)
);
create index connection_registration_requests_registration_idx on connection_registration_requests(registration_id);

-- +goose StatementBegin
create function guard_connection_registration() returns trigger language plpgsql as $$
begin
    if row(new.id, new.owner_type, new.owner_id, new.registration_key, new.environment,
           new.spec, new.credential_source_id, new.credential_source_version,
           new.connection_id, new.operation_id, new.created_at)
       is distinct from
       row(old.id, old.owner_type, old.owner_id, old.registration_key, old.environment,
           old.spec, old.credential_source_id, old.credential_source_version,
           old.connection_id, old.operation_id, old.created_at) then
        raise exception 'connection registration intent is immutable' using errcode = '23514';
    end if;
    if (old.phase = 'registered' and new.phase <> 'registered') or
       (old.phase = 'cancelled' and new.phase <> 'cancelled') or
       (old.phase = 'canceling' and new.phase not in ('canceling', 'cancelled')) or
       (old.phase = 'credential_ready' and new.phase = 'preparing') or
       (old.canonical_version > 0 and new.canonical_version <> old.canonical_version) then
        raise exception 'connection registration phase cannot move backwards' using errcode = '23514';
    end if;
    return new;
end;
$$;
-- +goose StatementEnd
create trigger connection_registration_immutable before update on connection_registrations
    for each row execute function guard_connection_registration();

-- +goose Down
-- +goose StatementBegin
do $$ begin
    if exists(select 1 from connection_registrations where phase not in ('registered', 'cancelled')) or
       exists(select 1 from connection_credential_sources where status <> 'revoked' or cleanup_pending) then
        raise exception 'cannot remove connection registration receipts with active credential sources or unfinished registrations';
    end if;
end $$;
-- +goose StatementEnd
drop table connection_registration_requests;
drop table connection_registrations;
drop function guard_connection_registration();
drop table connection_credential_sources;
drop function guard_connection_credential_source();
