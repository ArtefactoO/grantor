-- Статус наблюдения права. До этой миграции у permission_definitions не было
-- пометки исчезновения вовсе: роль, удалённая из целевой системы, вечно
-- оставалась assignable и предлагалась в диалогах выдачи. 'observed' /
-- 'missing' симметричны статусам resources и accounts; момент пометки даёт
-- updated_at (missing-строку больше ничто не обновляет). ADD COLUMN с
-- константным дефолтом — metadata-only, существующие строки корректно
-- считаются наблюдаемыми до первого discovery.

-- +goose Up
alter table permission_definitions
    add column status text not null default 'observed'
        check (status in ('observed', 'missing'));

-- +goose Down
alter table permission_definitions
    drop column status;
