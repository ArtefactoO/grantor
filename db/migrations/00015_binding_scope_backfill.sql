-- +goose Up

-- Одноразовая data-миграция: managed bindings, созданные без области
-- действия на правах, которые от неё неотделимы (kafka topic-produce/
-- topic-consume, mongodb role:<db>.<name>, rabbitmq vhost-access).
--
-- До вывода области в коде (inventory.EffectiveBindingScope) выдача без явного
-- scope_resource_id создавала строку с scope_resource_id IS NULL, тогда как
-- discovery фиксировал наблюдаемый доступ строкой с конкретным ресурсом.
-- Unique-ключ bindings — (account_id, permission_definition_id,
-- scope_resource_id) с `nulls not distinct`, поэтому это ДВЕ разные строки:
-- managed навсегда оставалась в drift (observed absent), а наблюдаемая —
-- «внешним грантом» без принятого решения. Само по себе это не сходится: и
-- повторный discovery, и refresh лишь подтверждают обе строки.
--
-- Миграция переносит managed-строку в область её права, предварительно убрав
-- наблюдаемого двойника. Затрагиваются только строки с принятым решением
-- (desired_state IS NOT NULL) на правах с собственной областью; cluster-wide
-- права (postgres, mysql, redis, роли clickhouse) под условие не подпадают,
-- поэтому для них миграция — no-op.
--
-- Идемпотентна и безопасна при повторном выполнении: после прогона ни одна
-- строка не удовлетворяет предикату «managed без области на праве с
-- областью», а NOT EXISTS во втором шаге страхует unique-ключ.

-- Шаг 1. Удалить наблюдаемого двойника managed-строки. Берётся только
-- неусыновлённый (desired_state IS NULL): решения по нему не принималось,
-- операции на него не ссылаются, и ближайший discovery воссоздаст
-- наблюдаемое состояние уже на сохранённой managed-строке. Если по двойнику
-- решение принято, обе строки выражают разные намерения оператора —
-- автоматическое слияние потеряло бы одно из них, поэтому такая пара не
-- трогается и остаётся оператору.
delete from bindings observed
using permission_definitions perm, bindings managed
where perm.id = observed.permission_definition_id
  and perm.scope_resource_id is not null
  and observed.scope_resource_id = perm.scope_resource_id
  and observed.desired_state is null
  and managed.account_id = observed.account_id
  and managed.permission_definition_id = observed.permission_definition_id
  and managed.scope_resource_id is null
  and managed.desired_state is not null;

-- Шаг 2. Перенести managed-строку в область её права. Наблюдаемое состояние
-- сбрасывается в 'unknown'/'pending': в этой области сервис фактического
-- состояния ещё не видел, и это честнее прежнего ложного 'drift'. Ближайший
-- discovery (ручной refresh или GRANTOR_DISCOVERY_INTERVAL) доводит строку до
-- synced. NOT EXISTS страхует unique-ключ и пропускает конфликтные пары
-- из шага 1.
update bindings b
set scope_resource_id = perm.scope_resource_id,
    observed_state    = 'unknown',
    status            = 'pending',
    updated_at        = now()
from permission_definitions perm
where perm.id = b.permission_definition_id
  and perm.scope_resource_id is not null
  and b.scope_resource_id is null
  and b.desired_state is not null
  and not exists (
      select 1
      from bindings other
      where other.account_id = b.account_id
        and other.permission_definition_id = b.permission_definition_id
        and other.scope_resource_id = perm.scope_resource_id
  );

-- +goose Down

-- Откат данных не выполняется: он воссоздавал бы ложный drift и фантомные
-- внешние гранты, а исходное множество затронутых строк после переноса
-- неотличимо от строк, созданных уже исправленным кодом.
select 1;
