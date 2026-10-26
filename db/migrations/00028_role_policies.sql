-- +goose Up

-- Generic materialized role-policy lifecycle. Policy specs and summaries are
-- secret-free, structured JSON; arbitrary SQL/BSON/commands are never stored
-- here or accepted by the public mutation API.
create table role_policies (
    id                       uuid primary key default gen_random_uuid(),
    connection_id            uuid not null references connections (id) on delete cascade,
    account_id               uuid references accounts (id) on delete set null,
    template_key             text not null check (template_key <> ''),
    name                     text not null,
    description              text not null default '',
    external_id              text not null check (external_id <> ''),
    desired_spec             jsonb not null check (jsonb_typeof(desired_spec) = 'object'),
    expected_fingerprint     text not null,
    observed_fingerprint     text not null default '',
    observed_summary         jsonb not null default '{"missing":[],"extra":[]}',
    managed                  boolean not null default false,
    exact                    boolean not null default false,
    dangerous                boolean not null default false,
    apply_supported          boolean not null default false,
    blocked_reason           text not null default '',
    status                   text not null default 'observed'
        check (status in ('observed', 'synced', 'drift', 'missing',
                          'pending', 'failed', 'blocked')),
    version                  bigint not null default 0 check (version >= 0),
    transition_operation_id  uuid references operations (id) on delete set null,
    target_started           boolean not null default false
        check (not target_started or transition_operation_id is not null),
    transition_retry_pending boolean not null default false
        check (not transition_retry_pending or transition_operation_id is not null),
    observed_at              timestamptz,
    created_at               timestamptz not null default now(),
    updated_at               timestamptz not null default now(),
    unique (connection_id, template_key),
    unique (connection_id, external_id)
);

create unique index role_policies_account_idx
    on role_policies (account_id)
    where account_id is not null;

create index role_policies_connection_status_idx
    on role_policies (connection_id, status, template_key);

create unique index role_policies_transition_operation_idx
    on role_policies (transition_operation_id)
    where transition_operation_id is not null;

-- Durable success receipt for the window where policy metadata and its audit
-- event have committed, but the outer River transaction has not yet marked
-- the operation successful. A redelivered immutable operation recognizes this
-- row and completes without touching the target or appending another audit
-- event. The receipt is intentionally append-only for the operation lifetime:
-- a later policy transition must not make an older successful job look stale.
create table role_policy_operation_completions (
    operation_id             uuid primary key references operations (id) on delete cascade,
    role_policy_id           uuid not null references role_policies (id) on delete cascade,
    expected_version         bigint not null check (expected_version > 0),
    observed_fingerprint     text not null check (observed_fingerprint <> ''),
    expected_fingerprint     text not null check (expected_fingerprint <> ''),
    desired_spec             jsonb not null check (jsonb_typeof(desired_spec) = 'object'),
    plan                     jsonb,
    result                   jsonb,
    completed_at             timestamptz not null default now(),
    unique (role_policy_id, expected_version)
);

create index role_policy_operation_completions_policy_idx
    on role_policy_operation_completions (role_policy_id, completed_at desc);

-- +goose Down
drop index if exists role_policy_operation_completions_policy_idx;
drop table if exists role_policy_operation_completions;
drop index if exists role_policies_transition_operation_idx;
drop index if exists role_policies_connection_status_idx;
drop index if exists role_policies_account_idx;
drop table role_policies;
