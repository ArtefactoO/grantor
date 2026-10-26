// Единая сборка отображаемых прав аккаунта из сырых bindings. Используется
// и в подключении, и в профиле пользователя: подписи, scope, dangerous и
// unmanaged-семантика не должны расходиться между экранами.
//
// Подписи берутся из нормализованного представления, которое собирает адаптер
// на backend (adapter.PermissionNormalizer). Собственных парсеров нотаций
// движков здесь нет и быть не должно: они дублировали бы логику адаптера и
// расходились с ней при первом же её изменении.
import { activeAccessBindings } from './active-access'
import { buildPermissionEntries, categoryGroup, permissionLabel } from './permission-view'
import type { Binding, Permission, Resource } from './types'

/** Нормализованная запись доступа для чипов и поповеров. */
export interface AccessEntry {
  /** Короткая подпись чипа. */
  label: string
  /** Заголовок группы в поповере («роли», «vhosts», «теги», «acl»…). */
  group: string
  /** Право помечено dangerous — в чипе красная точка (не красный чип). */
  dangerous: boolean
  /** Полное несокращённое выражение — для title и поповера. */
  full: string
}

/**
 * buildAccessEntries строит чипы действующего доступа.
 *
 * В отличие от раздела «Права доступа», здесь показывается только фактически
 * действующий доступ (activeAccessBindings): чип в таблице отвечает на вопрос
 * «что этот аккаунт может прямо сейчас», а не «что должно быть выдано».
 * Недостающие права видны в разделе прав и в дрифте.
 */
export function buildAccessEntries(
  bindings: Binding[],
  permissionsById: Map<string, Permission>,
  resourcesById: Map<string, Resource>,
): AccessEntry[] {
  return buildPermissionEntries(
    activeAccessBindings(bindings),
    permissionsById,
    resourcesById,
  ).map((entry) => ({
    label: entry.label,
    group: entry.managed ? categoryGroup(entry.view.category) : 'вне управления',
    dangerous: entry.dangerous,
    // Unmanaged-пометка остаётся в полном значении: чип узкий, а различие
    // между управляемым и обнаруженным правом важно при чтении поповера.
    full: entry.managed ? entry.raw : `${entry.raw} (unmanaged)`,
  }))
}

/**
 * Подпись одного права по его определению. Используется там, где показывается
 * не binding, а само определение (каталог ролей, выбор роли при выдаче).
 * fallback нужен, когда определение ещё не загружено.
 */
export function permissionNameLabel(permission: Permission | undefined, fallback: string): string {
  return permission === undefined ? fallback : permissionLabel(permission.normalized)
}

/**
 * Запись доступа по определению права — для списков, где нет полноценного
 * binding (например unmanaged-права в диалоге принятия под управление).
 */
export function permissionAccessEntry(
  permission: Permission | undefined,
  fallback: string,
): AccessEntry {
  if (permission === undefined) {
    return { label: fallback, group: 'права', dangerous: false, full: fallback }
  }
  return {
    label: permissionLabel(permission.normalized),
    group: categoryGroup(permission.normalized.category),
    dangerous: permission.normalized.dangerous,
    full: permission.normalized.raw,
  }
}
