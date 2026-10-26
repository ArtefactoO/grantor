-- +goose Up

-- Offboarding / IdP-sync (P1, R1, раздел 31 архитектуры; ADR-0012):
-- периодический poll identity directory помечает принципалов disabled, а
-- эвалуация offboarding эмитит security finding для disabled-принципалов с
-- ещё активными accounts/bindings. Механизм — audit security.* + Prometheus
-- (ADR-0011): новых таблиц findings/UI нет.

-- disabled_at — момент перевода принципала в status='disabled' (админом через
-- API или IdP-poll'ом обслуживания). Даёт находке offboarding_incomplete
-- поле disabled_since: видно, как долго выключенный принципал сохраняет
-- доступ. NULL = принципал active (или переведён в disabled до этой
-- миграции и обратно). Сбрасывается в NULL при повторном включении.
alter table principals
    add column disabled_at timestamptz;

-- Backfill для уже выключенных принципалов: точный момент перехода неизвестен,
-- updated_at — консервативная верхняя оценка (последнее изменение строки не
-- раньше самого перехода).
update principals
    set disabled_at = updated_at
    where status = 'disabled';

-- +goose Down

alter table principals drop column disabled_at;
