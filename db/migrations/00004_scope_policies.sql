-- +goose Up

-- Scope policies и service tokens (ADR-0007; docs/threat-model.md: P0 scope
-- policies для operator, P1 machine access). scope_policies ограничивают роль
-- operator (и отдельных service-принципалов) окружениями connections;
-- service_tokens дают машинный доступ к API service-принципалам.
--
-- Секретов эта миграция не хранит: service_tokens держит только sha256-хекс
-- токена (token_hash) — сам токен (grt_...) в базу не попадает никогда.

create table scope_policies (
    id           uuid primary key default gen_random_uuid(),
    subject_kind text not null check (subject_kind in ('role', 'principal')),
    -- Для subject_kind='role' — имя роли ('operator'); для 'principal' — uuid
    -- принципала как текст.
    subject      text not null,
    -- Окружение, к которому даётся доступ; '*' = все окружения.
    environment  text not null,
    created_at   timestamptz not null default now(),
    unique (subject_kind, subject, environment)
);

-- Подбор политик при enforcement идёт по (subject_kind, subject).
create index scope_policies_subject_idx on scope_policies (subject_kind, subject);

create table service_tokens (
    id           uuid primary key default gen_random_uuid(),
    principal_id uuid not null references principals (id) on delete cascade,
    name         text not null,
    -- sha256-хекс токена; сам токен (grt_...) не хранится никогда.
    token_hash   text not null unique,
    created_at   timestamptz not null default now(),
    last_used_at timestamptz,
    revoked_at   timestamptz
);

-- Список токенов принципала (управление в UI) и каскад ON DELETE.
create index service_tokens_principal_idx on service_tokens (principal_id);

-- +goose Down

drop table service_tokens;
drop table scope_policies;
