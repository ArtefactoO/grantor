-- +goose Up

-- Approval workflow enforcement (ADR-0010; docs/threat-model.md P1, R3).
-- Схема уже несёт статус operations.pending_approval и колонки
-- approved_by/approved_at (00001_core_schema.sql); эта миграция добавляет
-- недостающие части: причину решения (approve/reject) и индекс для выборки
-- операций, ожидающих подтверждения.
--
-- decision_reason — свободный текст, который подтверждающий/отклоняющий admin
-- указывает при approve/reject. Источник истины по «кто/когда/почему» —
-- append-only audit_events (operation.approved / operation.rejected); колонка
-- дублирует причину на строке операции, чтобы UI показывал её без join к
-- журналу. Секреты сюда не пишутся (инвариант раздела 17.2): значение —
-- пользовательский комментарий, а не credential.

alter table operations
    add column decision_reason text not null default '';

-- Частичный индекс под список ожидающих подтверждения (admin-эндпоинт
-- GET /api/v1/approvals): выборка идёт по status='pending_approval' с
-- сортировкой по created_at. operations_connection_status_idx ведёт с
-- connection_id и для чистой выборки по статусу не подходит.
create index operations_pending_approval_idx
    on operations (created_at)
    where status = 'pending_approval';

-- +goose Down

drop index operations_pending_approval_idx;
alter table operations drop column decision_reason;
