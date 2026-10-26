// Единая типобезопасная фабрика query-ключей react-query. Собирает все
// ключи экранов routes/* в одно место, чтобы queryKey запросов и queryKey
// инвалидаций строились из одного источника: иначе префиксы легко
// разъезжаются (список кэшируется под одним ключом, а invalidateQueries
// бьёт по другому — и данные молча не обновляются).
//
// Инвалидация в react-query матчит по префиксу массива, поэтому
// qk.operations() (['operations']) накрывает и ['operations','recent'], и
// ['operations','list',...], и ['operations','detail',...]; аналогично
// qk.principals() накрывает список и деталь, а qk.drift() — весь отчёт.

/** Все query-ключи приложения; вызовы возвращают стабильные кортежи. */
export const qk = {
  // Подключения: список, деталь и вложенные коллекции инвентаря.
  connections: () => ['connections'] as const,
  favoriteConnections: () => ['me', 'favorite-connections'] as const,
  // Поиск по внешнему каталогу: ключ включает строку запроса — разные
  // запросы кэшируются раздельно, а инвалидация префиксом ['directory']
  // сбрасывает их разом после импорта.
  directorySearch: (query: string) => ['directory', 'users', query] as const,
  // Проверка доступности каталога отделена от поиска: она запрашивает одну
  // запись, и общий с поиском ключ отдавал бы диалогу обрезанный список из
  // кэша вместо полной выдачи.
  directoryProbe: () => ['directory', 'probe'] as const,
  connection: (id: string) => ['connections', id] as const,
  connectionAccounts: (id: string, view?: string) => view === undefined ? ['connections', id, 'accounts'] as const : ['connections', id, 'accounts', view] as const,
  connectionPermissions: (id: string, category?: string) => category === undefined ? ['connections', id, 'permissions'] as const : ['connections', id, 'permissions', category] as const,
  connectionRolePolicies: (id: string) => ['connections', id, 'role-policies'] as const,
  connectionResources: (id: string) => ['connections', id, 'resources'] as const,
  connectionResourceTree: (id: string) => ['connections', id, 'resources', 'tree'] as const,
  connectionHBA: (id: string) => ['connections', id, 'hba'] as const,
  // Выданные права подключения: экспорт managed-состояния, суженный по
  // connection (GET /access/export?connection=id). Префикс ['connections', id]
  // накрывает и деталь, и эту выборку — инвалидация на refresh их обновит.
  connectionAccess: (id: string) => ['connections', id, 'access'] as const,
  // Снапшот доступов подключения (export с sections=...): ключ включает
  // нормализованный список секций, чтобы разные выборки кэшировались
  // раздельно; префикс ['connections', id] по-прежнему накрывает всё.
  connectionAccessSnapshot: (id: string, sections: string) =>
    ['connections', id, 'access', 'snapshot', sections] as const,

  // Bindings: вложены под аккаунт и под ресурс соответственно.
  accountBindings: (accountId: string, category?: string) => category === undefined ? ['accounts', accountId, 'bindings'] as const : ['accounts', accountId, 'bindings', category] as const,
  accountObjectPrivileges: (accountId: string, query?: string) => query === undefined ? ['accounts', accountId, 'object-privileges'] as const : ['accounts', accountId, 'object-privileges', 'search', query] as const,
  accountObjectTarget: (accountId: string, scopeId: string) => ['accounts', accountId, 'object-privileges', 'target', scopeId] as const,
  accountDefaultPrivileges: (accountId: string, query: string) => ['accounts', accountId, 'default-privileges', query] as const,
  objectPrivilegeTargets: (connectionId: string, query: string) => ['connections', connectionId, 'object-privilege-targets', query] as const,
  accountProvisioning: (accountId: string) => ['accounts', accountId, 'provisioning'] as const,
  resourceBindings: (resourceId: string) => ['resources', resourceId, 'bindings'] as const,
  resource: (resourceId: string) => ['resources', resourceId] as const,
  // Корни инвалидации инвентаря: накрывают все accountBindings /
  // resourceBindings разом — например, после завершившегося discovery,
  // когда наблюдаемое состояние могло поменяться у любого аккаунта.
  accounts: () => ['accounts'] as const,
  resources: () => ['resources'] as const,

  // Операции: корень для инвалидации по префиксу и scoped выборки.
  operations: () => ['operations'] as const,
  operationsRecent: () => ['operations', 'recent'] as const,
  operationsPendingApproval: () => ['operations', 'pending-approval-count'] as const,
  operationsErrorCount: () => ['operations', 'error-count'] as const,
  // Список операций: ключ включает серверные фильтры (connection_id,
  // CSV статусов вкладки, CSV kind), чтобы выборки вкладок кэшировались
  // раздельно; префикс ['operations'] накрывает все.
  operationsList: (
    connectionId: string,
    status = '',
    kind = '',
    createdFrom = '',
    createdBefore = '',
    limit = 0,
  ) =>
    ['operations', 'list', connectionId, status, kind, createdFrom, createdBefore, limit] as const,
  operationsToday: (connectionId: string, createdFrom: string, createdBefore: string) =>
    ['operations', 'today', connectionId, createdFrom, createdBefore] as const,
  operation: (id: string) => ['operations', 'detail', id] as const,

  // Аудит: список с фильтром по подключению и отдельная «свежая» выборка.
  audit: (connectionId: string, from = '', before = '', limit = 0) =>
    ['audit', connectionId, from, before, limit] as const,
  auditByOperation: (operationId: string) => ['audit', 'operation', operationId] as const,
  auditRecent: () => ['audit', 'recent'] as const,

  // Принципалы: список и деталь (префикс ['principals'] накрывает оба).
  principals: () => ['principals'] as const,
  principal: (id: string) => ['principals', id] as const,
  principalCredentials: (id: string) => ['principals', id, 'credentials'] as const,
  // Реестр окружений: список общий для формы подключения, матрицы
  // scope-политик и карточек пользователей.
  environments: () => ['environments'] as const,
  // Ключи движков из registry бэкенда; состав меняется только с релизом.
  engines: () => ['engines'] as const,
  // Service tokens принципала: вложены под принципала (аналогично
  // connectionAccounts). Префикс ['principals', id] накрывает и деталь, и токены.
  principalTokens: (id: string) => ['principals', id, 'tokens'] as const,

  // Scope policies: admin-экран «Политики доступа».
  scopePolicies: () => ['scope-policies'] as const,
  runtimeConfig: () => ['runtime-config'] as const,

  // Ожидающие подтверждения операции: admin-экран «Подтверждения» (ADR-0010).
  approvals: () => ['approvals'] as const,
  operationsUnresolved: (connectionId: string) =>
    ['operations', 'unresolved', connectionId] as const,
  operationsPendingApprovalCount: (connectionId: string) =>
    ['operations', 'pending-approval-count', connectionId] as const,

  // Дрифт: без аргумента — корень (для инвалидации), с id — отчёт по
  // конкретному подключению.
  drift: (connectionId?: string) =>
    connectionId === undefined ? (['drift'] as const) : (['drift', connectionId] as const),
}
