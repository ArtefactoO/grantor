-- +goose Up

-- Offboarding принципала (уровень 2 каскада): необратимое удаление всех
-- managed-аккаунтов принципала завершается tombstone — status='deleted'.
-- Строка principals сохраняется ради истории операций и audit (как soft
-- delete у accounts); из deleted нет переходов. CHECK-ограничение колонки
-- расширяется третьим значением.
alter table principals drop constraint principals_status_check;
alter table principals add constraint principals_status_check
    check (status in ('active', 'disabled', 'deleted'));

-- +goose Down

-- Откат возможен только пока deleted-принципалов нет: строки в этом
-- статусе нарушат восстановленное ограничение.
alter table principals drop constraint principals_status_check;
alter table principals add constraint principals_status_check
    check (status in ('active', 'disabled'));
