-- +goose Up

-- Индексы на FK-колонки, по которым идут частые выборки и каскады
-- (аудит кода 2026-07-18): без них запросы по principal/scope/permission
-- дают seq scan и деградируют линейно с ростом данных.

-- accounts.principal_id: LEFT JOIN в principals.List, ListAccountsByPrincipal,
-- каскад ON DELETE SET NULL при удалении principal.
create index accounts_principal_idx on accounts (principal_id)
    where principal_id is not null;

-- bindings.scope_resource_id: ListBindingsByResource + каскад из resources.
create index bindings_scope_resource_idx on bindings (scope_resource_id)
    where scope_resource_id is not null;

-- bindings.permission_definition_id: каскад из permission_definitions.
create index bindings_permission_idx on bindings (permission_definition_id);

-- operations.binding_id/account_id: каскад ON DELETE SET NULL при soft-delete
-- account (удаление его bindings) и удалении binding.
create index operations_binding_idx on operations (binding_id)
    where binding_id is not null;
create index operations_account_idx on operations (account_id)
    where account_id is not null;

-- +goose Down

drop index operations_account_idx;
drop index operations_binding_idx;
drop index bindings_permission_idx;
drop index bindings_scope_resource_idx;
drop index accounts_principal_idx;
