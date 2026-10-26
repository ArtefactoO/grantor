-- +goose Up
-- Baseline находок дрифта: находка, принятая оператором как ожидаемая,
-- перестаёт быть шумом в отчёте, но остаётся в нём отдельным списком.
-- Ключ находки — вид и id её объекта (binding/account/resource); сама
-- находка вычисляется на лету и своей строки не имеет.
create table drift_baselines (
    id uuid primary key default gen_random_uuid(),
    kind text not null check (kind in (
        'binding_drift', 'unmanaged_binding', 'missing_resource', 'missing_account'
    )),
    ref_id uuid not null,
    connection_id uuid not null references connections (id) on delete cascade,
    reason text not null default '',
    created_by text not null,
    created_at timestamptz not null default now(),
    unique (kind, ref_id)
);

create index drift_baselines_connection_idx on drift_baselines (connection_id);

-- +goose Down
drop table drift_baselines;
