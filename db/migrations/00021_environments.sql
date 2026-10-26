-- +goose Up

-- Реестр окружений.
--
-- До него окружение существовало только как строка в connections.environment:
-- список окружений везде выводился из фактических подключений, и подготовить
-- credential принципала для окружения БЕЗ подключений было невозможно —
-- create отвечал 400 "environment does not exist in visible connections".
--
-- Таблица — аддитивный реестр имён, а не источник ссылочной целостности:
-- connections.environment остаётся свободным текстом, потому что пустая
-- строка там нормализуется в "default" на уровне API и FK сломал бы эту
-- семантику. Имя окружения одновременно служит сегментом Vault-пути
-- principals/<id>/environments/<env>/credential, поэтому валидация имени
-- (непустое, без '/') выполняется на уровне API до записи.
create table environments (
    name text primary key,
    created_at timestamptz not null default now()
);

-- Уже используемые окружения попадают в реестр сразу, чтобы оба источника
-- (реестр и подключения) не расходились с первого дня.
insert into environments (name)
select distinct environment from connections where environment <> ''
on conflict (name) do nothing;

-- +goose Down

drop table environments;
