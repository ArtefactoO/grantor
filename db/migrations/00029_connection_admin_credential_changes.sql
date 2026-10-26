-- +goose Up

-- Durable, secret-free journal for switching or self-rotating the credential
-- Grantor itself uses to administer a connection. Candidate material lives
-- only under stage_vault_path in Vault; metadata stores coordinates, versions
-- and state-machine fences.
create table connection_admin_credential_changes (
    operation_id               uuid primary key references operations (id) on delete cascade,
    connection_id              uuid not null references connections (id) on delete cascade,
    request_id                 uuid not null,
    mode                       text not null check (mode in ('switch', 'rotate')),
    candidate_mode             text not null check (candidate_mode in ('generated', 'provided')),
    epoch                      bigint not null check (epoch > 0),
    stage_vault_path           text not null check (stage_vault_path <> ''),
    staged_vault_version       integer check (staged_vault_version is null or staged_vault_version > 0),
    expected_canonical_version integer not null check (expected_canonical_version >= 0),
    canonical_vault_version    integer check (canonical_vault_version > 0),
    expected_canonical_identity text not null default '',
    expected_authority_fingerprint text not null default '',
    expected_target_identity   text not null default '',
    previous_status            text not null
        check (previous_status in ('active', 'degraded', 'connection_failed',
                                   'discovery_failed')),
    phase                      text not null default 'preparing'
        check (phase in ('preparing', 'staged', 'candidate_proving', 'target_applying',
                         'target_applied', 'promoting', 'promoted',
                         'metadata_committing', 'completed', 'failed',
                         'cancelled')),
    target_side_effect_possible boolean not null default false,
    error_code                 text not null default '',
    completion_result          jsonb check (completion_result is null or jsonb_typeof(completion_result) = 'object'),
    stage_cleanup_pending      boolean not null default true,
    cancel_request_id          uuid,
    created_at                 timestamptz not null default now(),
    started_at                 timestamptz,
    finished_at                timestamptz,
    updated_at                 timestamptz not null default now(),
    unique (connection_id, request_id),
    unique (connection_id, epoch),
    check (phase <> 'preparing' or staged_vault_version is null),
    check (phase in ('preparing', 'failed', 'cancelled') or staged_vault_version is not null)
);

-- Exactly one credential transition may own a physical connection at once.
-- Terminal history remains queryable for UI/audit and does not block a later
-- epoch.
create unique index connection_admin_credential_changes_active_idx
    on connection_admin_credential_changes (connection_id)
    where phase not in ('completed', 'failed', 'cancelled');

create index connection_admin_credential_changes_latest_idx
    on connection_admin_credential_changes (connection_id, created_at desc);

-- +goose StatementBegin
create function enforce_admin_credential_change_transition() returns trigger
language plpgsql as $$
declare
    allowed boolean := false;
begin
    if old.phase = new.phase then
        return new;
    end if;
    allowed :=
        (old.phase = 'preparing' and new.phase = 'staged'
            and new.staged_vault_version is not null) or
        (old.phase = 'staged' and new.phase in ('candidate_proving', 'target_applying')) or
        (old.phase in ('candidate_proving', 'target_applying') and new.phase = 'target_applied') or
        (old.phase = 'target_applied' and new.phase = 'promoting') or
        (old.phase = 'promoting' and new.phase = 'promoted') or
        (old.phase = 'promoted' and new.phase = 'metadata_committing') or
        (old.phase = 'metadata_committing' and new.phase = 'completed'
            and new.canonical_vault_version is not null
            and new.completion_result is not null) or
        (new.phase in ('failed', 'cancelled')
            and old.phase not in ('completed', 'failed', 'cancelled')
            and not old.target_side_effect_possible);
    if not allowed then
        raise exception 'invalid admin credential change transition: % -> %', old.phase, new.phase
            using errcode = '55000',
                  constraint = 'connection_admin_credential_change_transition';
    end if;
    return new;
end;
$$;
-- +goose StatementEnd

create trigger connection_admin_credential_change_transition_guard
    before update on connection_admin_credential_changes
    for each row execute function enforce_admin_credential_change_transition();

alter table connections drop constraint connections_status_check;
alter table connections add constraint connections_status_check
    check (status in ('draft', 'validating', 'discovering', 'active',
                      'connection_failed', 'discovery_failed', 'degraded',
                      'disabled', 'credential_updating'));

-- Old API replicas and every mutation path are fenced at the metadata source
-- of truth as well as in Go. Existing queued operations are handled by the
-- River snooze fence; new operations cannot be inserted while an epoch owns
-- the connection.
-- +goose StatementBegin
create function reject_operation_during_admin_credential_change() returns trigger
language plpgsql as $$
begin
    if new.connection_id is not null and exists (
        select 1 from connection_admin_credential_changes
        where connection_id = new.connection_id
          and phase not in ('completed', 'failed', 'cancelled')
    ) then
        raise exception 'connection has an active admin credential change'
            using errcode = '55006',
                  constraint = 'connection_admin_credential_changes_active_idx';
    end if;
    return new;
end;
$$;
-- +goose StatementEnd

create trigger operations_admin_credential_change_fence
    before insert on operations
    for each row execute function reject_operation_during_admin_credential_change();

-- +goose Down

-- Forward-only target/CAS state cannot be represented by the previous binary.
-- Refuse rollback instead of destroying the only recovery journal and calling
-- a potentially unusable connection merely degraded.
-- +goose StatementBegin
do $$
begin
    if exists (select 1 from connections where status = 'credential_updating')
       or exists (select 1 from connection_admin_credential_changes where stage_cleanup_pending)
       or exists (
           select 1 from connection_admin_credential_changes c
           join operations o on o.id = c.operation_id
           where o.status not in ('success', 'failed', 'cancelled')
       ) then
        raise exception 'cannot roll back admin credential lifecycle while a change or stage cleanup is pending';
    end if;
end;
$$;
-- +goose StatementEnd
drop trigger if exists operations_admin_credential_change_fence on operations;
drop function if exists reject_operation_during_admin_credential_change();
drop trigger if exists connection_admin_credential_change_transition_guard
    on connection_admin_credential_changes;
drop function if exists enforce_admin_credential_change_transition();
alter table connections drop constraint connections_status_check;
alter table connections add constraint connections_status_check
    check (status in ('draft', 'validating', 'discovering', 'active',
                      'connection_failed', 'discovery_failed', 'degraded',
                      'disabled'));
drop index if exists connection_admin_credential_changes_latest_idx;
drop index if exists connection_admin_credential_changes_active_idx;
drop table connection_admin_credential_changes;
