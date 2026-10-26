-- +goose Up
create table account_creation_receipts (
    operation_id uuid primary key references operations(id) on delete cascade,
    account_id uuid not null references accounts(id) on delete cascade,
    connection_id uuid not null references connections(id) on delete cascade,
    engine_identity text not null,
    target_identity text not null,
    admin_identity text not null,
    config_incarnation text not null,
    admin_credential_incarnation integer not null check (admin_credential_incarnation > 0),
    lifecycle_version bigint not null check (lifecycle_version >= 0),
    credential_path text not null,
    credential_version integer not null check (credential_version > 0),
    phase text not null default 'planned' check (phase in ('planned','creating','created','verified')),
    role_oid bigint not null default 0 check (role_oid between 0 and 4294967295),
    verified_operation_id uuid references operations(id) on delete set null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    check ((phase in ('planned','creating') and role_oid=0) or
           (phase in ('created','verified') and role_oid>0))
);
create index account_creation_receipts_account_idx on account_creation_receipts(account_id);

-- +goose Down
drop table account_creation_receipts;
