-- +goose Up

-- Monotonic generation for account lifecycle jobs. A queued mutation carries
-- the reserved value and must match it before touching Vault or the target.
-- This makes jobs from an earlier delete/restore incarnation fail closed.
alter table accounts
    add column lifecycle_version bigint not null default 0
        check (lifecycle_version >= 0);

-- +goose Down

alter table accounts drop column lifecycle_version;
