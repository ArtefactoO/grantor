-- +goose Up
alter table database_provisionings
    add column database_owner_oid bigint not null default 0
        check (database_owner_oid between 0 and 4294967295);

-- Historical helper-era receipts cannot be assigned an owner-role OID from
-- metadata alone: looking it up by name would silently adopt a reincarnated
-- role. Keep 0 for those immutable history rows. The v2 Store refuses to
-- confirm a new database receipt without a positive owner OID.

-- +goose Down
alter table database_provisionings drop column database_owner_oid;
