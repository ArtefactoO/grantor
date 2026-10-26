-- +goose Up

-- Наблюдаемое состояние execution connector'ов (ADR-0002/ADR-0006).
--
-- Сессия connector'а живёт в памяти gateway, поэтому снаружи о нём нельзя
-- было узнать ничего: подключён ли он, когда его видели последний раз и до
-- какого числа действует его сертификат. Истечение сертификата при этом
-- обрывает связь бесповоротно и без предупреждения — агент перестаёт
-- проходить mTLS, а операции подключений сегмента начинают падать
-- retryable-ошибкой без внятной причины.
--
-- Таблица хранит именно наблюдения gateway, а не желаемое состояние:
-- запись появляется при первом подключении connector'а и обновляется его
-- heartbeat'ами. Секретов здесь нет — только идентификатор из CN
-- сертификата, срок его действия и время последнего кадра.
create table connector_sessions (
    -- connector_id — CN клиентского сертификата (identity сессии).
    connector_id text primary key,
    -- Момент последнего успешного handshake.
    connected_at timestamptz not null,
    -- Время последнего кадра от connector'а (результат либо heartbeat).
    last_seen_at timestamptz not null,
    -- notAfter клиентского сертификата: единственный источник, по которому
    -- control plane может предупредить об истечении заранее.
    certificate_not_after timestamptz not null,
    -- Объявленные в Hello capabilities: чем этот сегмент умеет управлять.
    capabilities text[] not null default '{}',
    protocol_version text not null default ''
);

-- +goose Down
drop table connector_sessions;
