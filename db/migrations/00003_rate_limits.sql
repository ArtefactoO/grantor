-- +goose Up

-- Token-bucket rate limiting (ADR-0007, docs/threat-model.md, раздел 3.5).
-- Общий честный лимит между репликами api: координация уже в этой базе,
-- поэтому счётчики ведра живут здесь же, а не в памяти процесса. Одна строка
-- на ключ ("login:<ip>", "reveal:<subject>", "mutating:<subject>"); списание
-- атомарно на строке (см. internal/ratelimit). Секретов не хранит: ключ несёт
-- IP или IdP subject, не credential.
create table rate_limit_buckets (
    -- key — идентификатор ведра: поверхность + субъект (IP или subject).
    key        text primary key,
    -- tokens — текущий уровень ведра (дробный: refill накапливается плавно).
    tokens     double precision not null,
    -- updated_at — момент последнего пересчёта уровня (время PostgreSQL, а не
    -- Go: refill считается по now() базы, чтобы реплики были согласованы).
    updated_at timestamptz not null default now()
);

-- +goose Down

drop table rate_limit_buckets;
