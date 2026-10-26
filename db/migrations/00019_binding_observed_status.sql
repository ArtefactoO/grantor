-- +goose Up
-- Статус binding, которым grantor не управляет.
--
-- Обнаруженный discovery, но не принятый binding получал status='pending' —
-- «ожидает применения». Применять его никто не собирается: desired_state у
-- него NULL, решение оператора ещё не принято, и никакая операция в очереди
-- его не ждёт. Оператор читал это как «сейчас доедет» и ждал.
--
-- Отдельное значение 'observed' называет ровно то, чем такая строка является:
-- право наблюдается в целевой системе и под управлением не находится.
-- 'pending' остаётся за bindings с desired_state, у которых применение
-- действительно впереди.
alter table bindings drop constraint bindings_status_check;
alter table bindings add constraint bindings_status_check
    check (status in ('synced', 'pending', 'drift', 'failed', 'observed'));

-- Существующие непринятые bindings переводятся сразу: держать их в 'pending'
-- означало бы сохранить ту же ложь до следующего discovery.
update bindings set status = 'observed'
where desired_state is null and status = 'pending';

-- +goose Down
update bindings set status = 'pending' where status = 'observed';
alter table bindings drop constraint bindings_status_check;
alter table bindings add constraint bindings_status_check
    check (status in ('synced', 'pending', 'drift', 'failed'));
