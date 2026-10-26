// Отображение прав: подписи и сборка записей доступа.
//
// Разбор нотации движка живёт на backend (adapter.PermissionNormalizer), сюда
// приходит уже разобранное представление. Здесь остаётся только то, что и
// должно быть во frontend: русские подписи и склейка с фактами binding,
// которых у определения права нет — прямое или унаследованное, managed или
// unmanaged, present или missing.
import type { Binding, Permission, PermissionView, Resource } from './types'
import { shortId } from './status'

/** Подписи категорий права. Неизвестная категория — «право». */
const CATEGORY_LABELS: Record<string, string> = {
  role: 'роль',
  privilege: 'привилегия',
  acl: 'ACL',
  bundle: 'набор прав',
  tag: 'тег',
  vhost: 'vhost',
  topic: 'топик',
  unknown: 'право',
}

/** Заголовки групп в списках. Множественное число от категории. */
const CATEGORY_GROUPS: Record<string, string> = {
  role: 'роли',
  privilege: 'привилегии',
  acl: 'ACL',
  bundle: 'наборы прав',
  tag: 'теги',
  vhost: 'vhosts',
  topic: 'топики',
  unknown: 'права',
}

/**
 * Подписи характеристик права. Ключи задаёт адаптер; незнакомый ключ
 * показывается как есть — это осознанный запасной путь, чтобы новое поле
 * адаптера не исчезало из панели до правки frontend.
 */
const DETAIL_LABELS: Record<string, string> = {
  categories: 'категории команд',
  caveat: 'важно знать',
  channels: 'каналы',
  commands: 'команды',
  configure: 'configure',
  global_privileges: 'глобальные привилегии',
  group: 'consumer group',
  host: 'хост',
  inherited_roles: 'унаследованные роли',
  key_patterns: 'шаблоны ключей',
  operations: 'операции',
  other_rules: 'прочие правила',
  pattern: 'тип шаблона',
  permission: 'разрешение',
  privileges: 'привилегии',
  read: 'read',
  resource_type: 'тип ресурса',
  role_db: 'база роли',
  selectors: 'селекторы',
  storage: 'хранилище',
  write: 'write',
  builtin: 'встроенная',
  createdb: 'может создавать базы',
  createrole: 'может создавать роли',
  bypassrls: 'обходит RLS',
  replication: 'репликация',
  superuser: 'superuser',
}

export function categoryLabel(category: string): string {
  return CATEGORY_LABELS[category] ?? CATEGORY_LABELS.unknown
}

export function categoryGroup(category: string): string {
  return CATEGORY_GROUPS[category] ?? CATEGORY_GROUPS.unknown
}

export function detailLabel(key: string): string {
  return DETAIL_LABELS[key] ?? key
}

/**
 * Короткая подпись права для компактного показа.
 *
 * Собирается из разобранных полей, а не из сырого имени: «read: orders»
 * читается, а `acl:topic:literal:orders:read:allow` — нет. Если разобранных
 * полей нет (движок без нормализатора, незнакомая нотация), показывается
 * исходное выражение целиком — потерять право хуже, чем показать его сырым.
 *
 * Примеры:
 *   {action: 'read', resource: 'orders'}            -> 'read: orders'
 *   {action: 'SELECT', resource: 'ads', scope:'ads'}-> 'SELECT: ads'
 *   {category: 'role', resource: 'app_ro'}          -> 'app_ro'
 *   {category: 'role', resource: 'readWrite', scope: 'ads'} -> 'readWrite @ ads'
 *   {} (нераспознанное)                             -> сырое выражение
 */
export function permissionLabel(view: PermissionView): string {
  const { action, resource, scope } = view
  if (action !== '' && resource !== '') {
    return `${action}: ${resource}`
  }
  if (action !== '') {
    return action
  }
  if (resource === '') {
    return view.raw
  }
  // Scope дописывается, только если он добавляет информацию: у роли MongoDB
  // база принципиальна, у vhost RabbitMQ она дублирует имя.
  if (scope !== '' && scope !== resource) {
    return `${resource} @ ${scope}`
  }
  return resource
}

/**
 * Склейка «имя @ scope» для мест, где нормализованного представления нет:
 * снимок access-manifest несёт только сырые имена ролей, без определений.
 *
 * Это НЕ разбор нотации движка — здесь ничего не парсится. Scope опускается,
 * когда он уже входит в имя: у адаптеров распространён паттерн
 * `<verb>:<scope>`, и повтор лишь удлиняет строку.
 */
export function rawExpression(name: string, scope?: string | null): string {
  if (scope === undefined || scope === null || scope === '' || name.includes(scope)) {
    return name
  }
  return `${name} @ ${scope}`
}

/** Запись доступа: право плюс факты binding, которых у определения нет. */
export interface PermissionEntry {
  /** Стабильный ключ строки: id права и scope binding. */
  key: string
  permissionId: string
  /** Короткая подпись для компактного показа. */
  label: string
  /** Заголовок группы в сгруппированных списках. */
  group: string
  view: PermissionView
  /** Полное исходное выражение — для tooltip, поиска и копирования. */
  raw: string
  dangerous: boolean
  /** Право выдано через роль или группу, а не напрямую. */
  inherited: boolean
  /** Grantor управляет этим правом (есть desired state). */
  managed: boolean
  /** Право фактически присутствует в целевой системе. */
  present: boolean
  /** Статус синхронизации binding: synced / pending / drift / failed. */
  status: string
  /**
   * Binding, который можно отозвать: управляемый, требуемый (desired
   * present) и НЕ унаследованный. null — отзывать нечего: право обнаружено
   * discovery, отзыв уже идёт либо право получено через роль. Хранится сам
   * binding, а не флаг: вызывающему нужен его id.
   */
  revocable: Binding | null
}

/**
 * Представление права, когда определение не найдено. Такое случается при
 * гонке между discovery и чтением: binding уже есть, определение ещё не
 * загружено в список. Право всё равно показывается — по короткому id.
 */
function missingPermissionView(permissionId: string): PermissionView {
  const raw = shortId(permissionId)
  return {
    category: 'unknown',
    action: '',
    resource: raw,
    scope: '',
    dangerous: false,
    danger_reason: '',
    details: null,
    raw,
  }
}

/**
 * Право относится к разделу, если оно либо требуется (desired present), либо
 * фактически есть в системе (observed present).
 *
 * Здесь НЕ используется isActiveAccessBinding: тот отбирает только фактически
 * действующий доступ, а разделу нужен и недостающий — право, которое grantor
 * должен был выдать, но discovery его не видит. Именно эта строка объясняет
 * оператору, почему доступ не работает, поэтому скрывать её нельзя.
 *
 * Отбрасывается единственный случай: отзыв уже завершён (desired absent и
 * observed absent) — показывать нечего.
 */
export function isRelevantPermissionBinding(binding: Binding): boolean {
  return binding.desired_state === 'present' || binding.observed_state === 'present'
}

/**
 * buildPermissionEntries собирает записи доступа аккаунта из его bindings.
 *
 * Дедупликация — по паре «право + scope»: одно и то же право может прийти и
 * от discovery, и от grantor. При склейке берётся худший случай: если хотя
 * бы один binding управляем — запись управляемая, если хотя бы один
 * отсутствует в системе — запись считается отсутствующей. Так строка не
 * выглядит благополучнее, чем реальность.
 */
export function buildPermissionEntries(
  bindings: Binding[],
  permissionsById: Map<string, Permission>,
  resourcesById: Map<string, Resource>,
): PermissionEntry[] {
  const byKey = new Map<string, PermissionEntry>()

  for (const binding of bindings.filter(isRelevantPermissionBinding)) {
    const permission = permissionsById.get(binding.permission_definition_id)
    const view = permission?.normalized ?? missingPermissionView(binding.permission_definition_id)
    const scopeId = binding.scope_resource_id ?? permission?.scope_resource_id ?? null
    const scopeName = scopeId !== null ? (resourcesById.get(scopeId)?.name ?? '') : ''
    const key = `${binding.permission_definition_id}:${scopeId ?? ''}`

    const entry: PermissionEntry = {
      key,
      permissionId: binding.permission_definition_id,
      label: permissionLabel(view),
      group: categoryGroup(view.category),
      view: scopeName !== '' && view.scope === '' ? { ...view, scope: scopeName } : view,
      raw: view.raw,
      dangerous: view.dangerous,
      inherited: binding.source === 'inherited',
      managed: binding.desired_state !== null,
      present: binding.observed_state === 'present',
      status: binding.status,
      // Унаследованное право отозвать нельзя: прямого ребра в целевой
      // системе нет, и API отвечает 409. Кнопку не показываем, иначе
      // оператор упирался бы в отказ; отзывать нужно роль-источник.
      revocable:
        binding.desired_state === 'present' && binding.source !== 'inherited'
          ? binding
          : null,
    }

    const existing = byKey.get(key)
    byKey.set(key, existing === undefined ? entry : mergeEntries(existing, entry))
  }

  return [...byKey.values()]
}

/** Склейка двух записей одного права: пессимистичная по каждому признаку. */
function mergeEntries(a: PermissionEntry, b: PermissionEntry): PermissionEntry {
  return {
    ...a,
    dangerous: a.dangerous || b.dangerous,
    managed: a.managed || b.managed,
    present: a.present && b.present,
    inherited: a.inherited && b.inherited,
    // Отзываемым считается любой из склеенных binding: достаточно одного
    // управляемого, чтобы у строки было что снимать.
    revocable: a.revocable ?? b.revocable,
  }
}

/** Сводка по набору прав для свёрнутого раздела. */
export interface PermissionSummary {
  total: number
  direct: number
  inherited: number
  dangerous: number
  unmanaged: number
  missing: number
}

export function summarizePermissions(entries: PermissionEntry[]): PermissionSummary {
  const summary: PermissionSummary = {
    total: entries.length,
    direct: 0,
    inherited: 0,
    dangerous: 0,
    unmanaged: 0,
    missing: 0,
  }
  for (const entry of entries) {
    if (entry.inherited) summary.inherited += 1
    else summary.direct += 1
    if (entry.dangerous) summary.dangerous += 1
    if (!entry.managed) summary.unmanaged += 1
    if (!entry.present) summary.missing += 1
  }
  return summary
}

/** Фильтры раздела прав. null — «не фильтровать по этому признаку». */
export interface PermissionFilters {
  query: string
  inherited: boolean | null
  managed: boolean | null
  present: boolean | null
  dangerous: boolean | null
}

export const EMPTY_PERMISSION_FILTERS: PermissionFilters = {
  query: '',
  inherited: null,
  managed: null,
  present: null,
  dangerous: null,
}

/**
 * Поиск идёт по действию, ресурсу и исходному выражению: пользователь ищет
 * и по тому, что видит в списке, и по тому, что скопировал из кластера.
 */
export function matchesQuery(entry: PermissionEntry, query: string): boolean {
  const q = query.trim().toLowerCase()
  if (q === '') return true
  return (
    entry.label.toLowerCase().includes(q) ||
    entry.raw.toLowerCase().includes(q) ||
    entry.view.action.toLowerCase().includes(q) ||
    entry.view.resource.toLowerCase().includes(q) ||
    entry.view.scope.toLowerCase().includes(q)
  )
}

export function filterPermissions(
  entries: PermissionEntry[],
  filters: PermissionFilters,
): PermissionEntry[] {
  return entries.filter((entry) => {
    if (!matchesQuery(entry, filters.query)) return false
    if (filters.inherited !== null && entry.inherited !== filters.inherited) return false
    if (filters.managed !== null && entry.managed !== filters.managed) return false
    if (filters.present !== null && entry.present !== filters.present) return false
    if (filters.dangerous !== null && entry.dangerous !== filters.dangerous) return false
    return true
  })
}
