-- +goose Up

-- Resolution is operator acknowledgement, not a rewrite of execution history:
-- the operation keeps its failed/partial/cancelled status and error payload,
-- while active attention feeds can exclude acknowledged incidents.
alter table operations
    add column resolved_at timestamptz,
    add column resolved_by text;

create index operations_unresolved_failure_idx
    on operations (created_at desc)
    where resolved_at is null
      and status in ('failed', 'partial', 'cancelled');

-- +goose Down

drop index operations_unresolved_failure_idx;

alter table operations
    drop column resolved_by,
    drop column resolved_at;
