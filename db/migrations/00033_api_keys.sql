-- +goose Up

-- UI identities are not target-cluster principals. Subject is opaque and is
-- scoped to the verified issuer; neither email nor directory pk is an owner key.
create table api_users (
    id uuid primary key default gen_random_uuid(),
    issuer text not null,
    subject text not null,
    username text not null default '',
    directory_uid text not null default '',
    email text not null,
    role text not null check (role in ('viewer', 'operator', 'admin', '')),
    active boolean not null check (not active or role <> ''),
    directory_managed boolean not null default false,
    authorized_until timestamptz not null,
    authenticated_at timestamptz not null,
    identity_bound_at timestamptz not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (issuer, subject)
);

create table personal_api_keys (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references api_users(id) on delete cascade,
    name text not null check (length(name) between 1 and 128),
    token_hash text not null unique,
    role text not null check (role in ('viewer', 'operator', 'admin')),
    -- NULL inherits owner scope; a nonempty array can only narrow it.
    environments text[] check (environments is null or cardinality(environments) > 0),
    expires_at timestamptz not null,
    created_at timestamptz not null default now(),
    last_used_at timestamptz,
    revoked_at timestamptz,
    check (expires_at > created_at)
);

create index personal_api_keys_user_idx on personal_api_keys(user_id);

-- +goose Down
drop table personal_api_keys;
drop table api_users;
