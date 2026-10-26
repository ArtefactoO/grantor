-- +goose Up
create table connection_favorites (
    id uuid primary key default gen_random_uuid(),
    user_id uuid references api_users(id) on delete cascade,
    user_identity_bound_at timestamptz,
    service_principal_id uuid references principals(id) on delete cascade,
    connection_id uuid not null references connections(id) on delete cascade,
    created_at timestamptz not null default now(),
    check (
        (user_id is not null and user_identity_bound_at is not null and service_principal_id is null)
        or (user_id is null and user_identity_bound_at is null and service_principal_id is not null)
    ),
    unique (user_id, user_identity_bound_at, connection_id),
    unique (service_principal_id, connection_id)
);
create index connection_favorites_connection_idx on connection_favorites(connection_id);

-- +goose Down
drop table connection_favorites;
