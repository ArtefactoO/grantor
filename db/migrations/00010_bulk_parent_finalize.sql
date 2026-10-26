-- +goose Up

-- Одноразовая data-миграция: parent bulk-операции, застрявшие в running
-- при уже завершённых детях. До введения финализации parent в коде
-- (operations.Store.FinalizeParent) worker parent не исполнял, а сводный
-- статус вычислялся только при чтении detail-ответа API — в базе parent
-- оставался running навсегда. Здесь такие строки доводятся до итогового
-- статуса той же семантикой агрегации (AggregateChildren): все success —
-- success; часть неуспешна (failed/cancelled/partial) при наличии
-- успешных — partial; все неуспешны — failed. finished_at берётся по
-- последнему завершившемуся ребёнку.
--
-- Идемпотентно: предикат (родитель в running, есть >= 1 ребёнок, все дети
-- finished) после обновления не выполняется; актуальный код финализирует
-- parent в транзакции терминального перехода последнего ребёнка, поэтому
-- новых строк в таком состоянии не появляется (кроме короткоживущих
-- retry-окон, где дети снова pending/running и предикат ложен).
update operations p
set status      = agg.status,
    finished_at = coalesce(agg.last_finished_at, now()),
    updated_at  = now()
from (
    select c.parent_id,
           case
               when bool_and(c.status = 'success') then 'success'
               when bool_or(c.status = 'success') then 'partial'
               else 'failed'
           end as status,
           max(c.finished_at) as last_finished_at
    from operations c
    where c.parent_id is not null
    group by c.parent_id
    having bool_and(c.status in ('success', 'partial', 'failed', 'cancelled'))
) agg
where p.id = agg.parent_id
  and p.status = 'running';

-- +goose Down

-- Откат данных не выполняется: возвращать parent-операции в вечный
-- running бессмысленно, а исходное множество затронутых строк после
-- обновления неотличимо от финализированных кодом.
select 1;
