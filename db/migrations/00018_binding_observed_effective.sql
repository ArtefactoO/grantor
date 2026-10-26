-- +goose Up
-- Признак «право выдано, но не действует».
--
-- Проблема, найденная аудитом. Движки различают «грант существует» и «грант
-- даёт доступ»: в MySQL и ClickHouse роль, не входящая в набор ролей по
-- умолчанию, числится выданной и не даёт ничего. Адаптеры это вычисляют и
-- кладут в ObservedBinding.Attributes, но ядро атрибуты не сохраняло —
-- признак умирал между адаптером и хранилищем. В результате binding получал
-- status='synced', дрифт был пуст, а пользователь получал отказ в доступе.
-- Ровно та ложная зелень, ради которой аудит и проводился.
--
-- Почему отдельный столбец, а не новое значение observed_state. Значение
-- 'ineffective' пришлось бы учесть в 26 местах, где observed_state
-- сравнивается напрямую (SQL и Go), и любое пропущенное сравнение молча
-- изменило бы смысл существующего отчёта. Булев столбец аддитивен: прежние
-- запросы продолжают видеть 'present' и работают как раньше, а решение о
-- статусе принимает одно место — ResolveBindingStatus.
--
-- Умолчание true: движок, который различия не делает (postgres, redis,
-- rabbitmq, mongodb, kafka), сообщает о выданном праве как о действующем,
-- и существующие строки сохраняют прежний смысл.

alter table bindings
    add column observed_effective boolean not null default true;

comment on column bindings.observed_effective is
    'Whether the observed grant actually takes effect (MySQL/ClickHouse default roles)';

-- Частичный индекс под выборку дрифта: интересны только недействующие
-- гранты, их заведомо меньшинство.
create index bindings_ineffective_idx
    on bindings (account_id)
    where not observed_effective;

-- +goose Down
drop index if exists bindings_ineffective_idx;
alter table bindings drop column if exists observed_effective;
