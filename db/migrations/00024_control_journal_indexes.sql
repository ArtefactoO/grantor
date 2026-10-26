-- +goose Up
-- Индексы под объединённую ленту «Контроля»: она читает операции верхнего
-- уровня и audit-события вне операций, а деталь операции — её собственный
-- след событий.

-- След конкретной операции в детальной панели. Частичный: у большинства
-- событий operation_id пуст, и они этому запросу не нужны.
create index audit_events_operation_idx
    on audit_events (operation_id)
    where operation_id is not null;

-- Базовый предикат ленты (события вне операций, от новых к старым).
create index audit_events_standalone_occurred_idx
    on audit_events (occurred_at desc)
    where operation_id is null;

-- Каждая страница операций сортируется по (created_at desc, id desc), но
-- индекса под этот порядок не было: глобальный список без фильтра по
-- подключению сортировал seq scan.
create index operations_created_idx on operations (created_at desc, id desc);

-- Индексы под action и actor_id не заводятся намеренно: эти фильтры
-- используются точечно (разбор инцидента), и скан по окну времени для них
-- дешевле постоянной поддержки ещё двух индексов на горячей вставке.

-- +goose Down
drop index if exists operations_created_idx;
drop index if exists audit_events_standalone_occurred_idx;
drop index if exists audit_events_operation_idx;
