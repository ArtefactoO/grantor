-- +goose Up

-- Зеркало состояния внешней identity отделено от локального lifecycle
-- principal.status. В частности, deleted здесь означает отсутствие субъекта
-- в каталоге, а не локальный необратимый tombstone principal.
alter table principals
    add column external_identity_status text
        check (external_identity_status in ('active', 'disabled', 'deleted')),
    add column external_identity_checked_at timestamptz,
    add column external_identity_status_changed_at timestamptz;

-- +goose Down

alter table principals
    drop column external_identity_status_changed_at,
    drop column external_identity_checked_at,
    drop column external_identity_status;
