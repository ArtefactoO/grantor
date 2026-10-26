-- +goose Up

-- Security findings: старение admin credential connection (P1, R12, раздел
-- 17.3) и детекция аномальной частоты credential reveal/share (P1, разделы
-- 24/25). Механизм — audit security.* + Prometheus (ADR-0011): новых таблиц
-- findings/UI нет, здесь только источники данных для эвалуаций.

-- admin_credential_set_at — момент, когда admin credential подключения был
-- записан/ротирован в Vault. Источник истины возраста admin credential для
-- aging finding (эвалуация в internal/core/maintenance сравнивает
-- now() - admin_credential_set_at с порогом). Секрета не хранит: только
-- timestamp. NULL = credential в Vault не клали (нет vault_admin_path, либо
-- external_identity) → подключение из эвалуации старения исключается.
alter table connections
    add column admin_credential_set_at timestamptz;

-- Backfill для существующих подключений: admin credential кладётся в Vault в
-- момент создания connection (POST /connections), поэтому для уже созданных
-- подключений с сохранённым credential берём created_at как консервативную
-- нижнюю оценку возраста. Так aging finding осмыслен сразу после миграции, а
-- не только для подключений, созданных после неё.
update connections
    set admin_credential_set_at = created_at
    where vault_admin_path <> '';

-- credential_reveal_windows — per-subject скользящее окно частоты reveal/
-- share для детекции аномалии (internal/ratelimit.AnomalyDetector). Общий
-- счётчик между репликами api (как rate_limit_buckets): координация уже в
-- этой базе, инкремент атомарен на строке. Секретов не хранит: subject — IdP
-- subject / id принципала, не credential. last_alerted_at троттлит сигнал до
-- одного на субъект за окно.
create table credential_reveal_windows (
    -- subject — ключ окна: поверхность reveal/share + субъект сессии.
    subject         text primary key,
    -- window_start — начало текущего окна (время PostgreSQL: реплики
    -- согласованы по now() базы, как в rate_limit_buckets).
    window_start    timestamptz not null default now(),
    -- event_count — число событий reveal/share субъекта в текущем окне.
    event_count     integer not null default 0,
    -- last_alerted_at — момент последнего сигнала аномалии по субъекту;
    -- NULL = ещё не сигналили. Троттлит сигнал до одного за окно.
    last_alerted_at timestamptz
);

-- +goose Down

drop table credential_reveal_windows;
alter table connections drop column admin_credential_set_at;
