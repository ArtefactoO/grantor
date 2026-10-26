-- +goose Up

-- Информация об удалении аккаунта на tombstone (soft delete, status='deleted'):
-- кто, когда и почему удалил. Заполняется worker'ом на успехе account.delete;
-- у старых tombstone'ов актора и причины нет — колонки остаются NULL.
-- delete_reason — необязательный текст оператора (или каскада offboard),
-- не секрет; ограничение длины контролирует API (<= 500 символов).
alter table accounts add column deleted_at timestamptz;
alter table accounts add column deleted_by text;
alter table accounts add column delete_reason text;

-- Backfill deleted_at существующих tombstone'ов моментом завершения последней
-- успешной операции account.delete по аккаунту. Актор и причина не
-- восстанавливаются: их у старых операций в payload нет.
update accounts a
set deleted_at = o.finished_at
from (
    select account_id, max(finished_at) as finished_at
    from operations
    where kind = 'account.delete' and status = 'success' and account_id is not null
    group by account_id
) o
where a.id = o.account_id and a.status = 'deleted' and a.deleted_at is null;

-- +goose Down

alter table accounts drop column delete_reason;
alter table accounts drop column deleted_by;
alter table accounts drop column deleted_at;
