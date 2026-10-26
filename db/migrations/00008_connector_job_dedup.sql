-- +goose Up

-- Durable-дедупликация заданий execution connector (этап 2; ADR-0002/ADR-0006,
-- docs/architecture.md раздел 24, R5 duplicate execution). In-memory store
-- gateway этапа 1 живёт только в пределах процесса и теряется при рестарте;
-- эта таблица хранит результаты УСПЕШНО завершённых заданий по ключу
-- дедупликации, поэтому повторная доставка того же задания (тот же
-- IdempotencyKey/Nonce) после рестарта gateway не исполняется второй раз.
--
-- Секретов в result нет и быть не может: JobResult несёт sanitized
-- plan/result/error по контракту internal/connector (раздел 24, "no secrets in
-- job payload/logs"); инвариант покрыт общим canary-sweep'ом
-- (TestIntegrationNoSecretsInMetadataDB перечисляет колонки динамически, так
-- что новая jsonb-колонка попадает под скан автоматически) и адресной
-- проверкой в интеграционном тесте connector phase 2.
--
-- Колонка connections.execution_mode ('direct'/'connector' с CHECK) существует
-- с 00001_core_schema.sql и здесь не добавляется.
create table connector_job_dedup (
    -- dedup_key — ключ дедупликации задания: "idem:<IdempotencyKey>" либо
    -- "nonce:<Nonce>" (см. dedupKey в internal/connector/gateway).
    dedup_key  text primary key,
    -- job_id — идентификатор задания, чей результат закеширован (диагностика).
    job_id     text not null,
    -- result — завершённый connector.JobResult (jsonb, sanitized, без секретов).
    result     jsonb not null,
    created_at timestamptz not null default now()
);

-- Индекс под TTL/GC: устаревшие записи удаляются cleanup-on-insert
-- (internal/core/connectorjobs), выборка идёт по created_at.
create index connector_job_dedup_created_at_idx on connector_job_dedup (created_at);

-- +goose Down

drop table connector_job_dedup;
