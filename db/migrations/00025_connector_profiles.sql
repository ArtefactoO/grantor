-- +goose Up

-- Операторские данные о connector'е отдельно от наблюдаемых.
--
-- connector_sessions — наблюдение gateway: строка появляется при подключении
-- и перезаписывается heartbeat'ами. Имя там — CN клиентского сертификата, оно
-- же идентификатор в PKI, путях Vault и релизе агента, поэтому переименовать
-- его нельзя без перевыпуска сертификата. Человеческое название и уточнение
-- типа развёртывания — это, наоборот, решение оператора, которое должно
-- переживать переподключения и не зависеть от того, на связи ли агент сейчас.
create table connector_profiles (
    -- Тот же CN, что и в connector_sessions; FK не ставится намеренно:
    -- профиль можно завести до первого подключения.
    connector_id text primary key,
    -- Отображаемое имя; пусто — показывается сам connector_id.
    display_name text not null default '',
    -- Переопределение типа развёртывания оператором. Пусто — показывается
    -- то, что сообщил о себе агент.
    deployment_kind text not null default '' check (
        deployment_kind in ('', 'kubernetes', 'vm', 'other')
    ),
    updated_by text not null default '',
    updated_at timestamptz not null default now()
);

-- Тип развёртывания, объявленный самим агентом в Hello: наблюдение, поэтому
-- живёт рядом с остальными наблюдениями. Старые агенты поля не шлют — пусто
-- означает «не сообщил», а не «неизвестный тип».
alter table connector_sessions
    add column deployment_kind text not null default '';

-- +goose Down
alter table connector_sessions drop column deployment_kind;
drop table connector_profiles;
