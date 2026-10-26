// Единый предикат доступности действий над учётной записью: одна точка
// правды для панели аккаунта. Зеркалит гварды бэкенда (kind / ownership /
// status / наличие credential / RBAC), поэтому UI не показывает кнопки,
// которые всё равно вернут 409. Движко-нейтрально: опирается на категорию
// kind, а не на имя движка.
import type { Account, Connection, Permission } from './types'
import { roleAtLeast } from '../auth/AuthProvider'
import { SHARED_CREDENTIAL_MODE } from '../routes/principal-detail-shared'

// Групповые kind (group/role) — общие NOLOGIN-роли: у них нет ни владельца-
// пользователя, ни собственного пароля. Их выдают людям (со стороны
// принципала) и удаляют; личные действия (креды/ротация/привязка/lifecycle)
// к ним неприменимы. Всё остальное (login и неизвестные kind новых движков)
// считаем идентичностью с логином/credential — деградируем к полному набору,
// бэкенд остаётся финальным гардом.
export function isSharedRoleKind(kind: string): boolean {
  return kind === 'group' || kind === 'role'
}

/**
 * Находит permission, которой представлена обнаруженная групповая роль.
 *
 * Адаптеры публикуют одну и ту же роль как account (для lifecycle) и как
 * assignable permission (для membership). Сопоставление централизовано здесь,
 * чтобы экраны не повторяли engine-specific эвристики. Неоднозначный результат
 * безопасно считается отсутствующим: UI не должен выдать не ту роль.
 */
export function sharedRolePermission(
  account: Pick<Account, 'connection_id' | 'engine_identity' | 'kind'>,
  permissions: readonly Permission[],
): Permission | null {
  if (!isSharedRoleKind(account.kind)) return null

  const eligible = permissions.filter(
    (permission) =>
      permission.connection_id === account.connection_id &&
      permission.assignable &&
      permission.status !== 'missing',
  )
  const byExternalId = eligible.filter(
    (permission) => permission.external_id === `role:${account.engine_identity}`,
  )
  if (byExternalId.length === 1) return byExternalId[0]
  if (byExternalId.length > 1) return null

  const byName = eligible.filter(
    (permission) => permission.name === account.engine_identity,
  )
  return byName.length === 1 ? byName[0] : null
}

/** У аккаунта есть управляемый grantor credential в Vault. */
export function accountHasCredential(account: Account): boolean {
  return (
    account.vault_path !== '' ||
    (account.credential_mode !== null && account.credential_mode !== '')
  )
}

/**
 * Учётка, под которой grantor управляет самим подключением. Отметку ставит
 * discovery в attributes.connection_admin (adapter.AttrConnectionAdmin);
 * принимать её под управление нельзя ни adopt, ни link-and-manage — grantor
 * сменил бы ей пароль и потерял доступ к подключению.
 */
export function isConnectionAdminAccount(account: Account): boolean {
  const attributes = account.attributes
  if (typeof attributes !== 'object' || attributes === null) return false
  return (attributes as Record<string, unknown>).connection_admin === true
}

/**
 * Аккаунт на ЛИЧНОМ пароле: живой managed-носитель credential, который не
 * сидит на общем секрете своего пользователя. Зеркалит backend-предикат
 * accountOnOwnCredential — вместе с «на общем секрете» покрывает всех
 * ротируемых без пересечения.
 *
 * Приближение по метаданным: владеет ли grantor паролем на самом деле,
 * знает только Vault, и решает это бэкенд. Здесь достаточно точности, чтобы
 * показать оператору список и оценку до подтверждения.
 */
export function accountOnOwnCredential(account: Account, principalId: string): boolean {
  const sharesPrincipalCredential =
    account.credential_mode === SHARED_CREDENTIAL_MODE &&
    account.vault_path.startsWith(`principals/${principalId}/`)
  return (
    account.ownership === 'managed' &&
    account.status === 'active' &&
    !isSharedRoleKind(account.kind) &&
    !sharesPrincipalCredential
  )
}

/** Единый frontend guard link-and-manage; соответствует backend helper
 * adapter.HasManagedCredentialCapabilities. account.restore намеренно не
 * участвует: восстановление tombstone — отдельная lifecycle capability. */
export function supportsManagedCredentialLink(connection?: Connection): boolean {
  return connection?.status === 'active' &&
    connection.capabilities.includes('credential.rotate') &&
    connection.capabilities.includes('credential.prove')
}

/** Набор доступных действий над аккаунтом для текущей роли. Каждое поле —
 * показывать ли кнопку; поля *Reason несут причину неактивности для tooltip. */
export interface AccountActions {
  grant: boolean
  share: boolean
  shareReason?: string
  rotate: boolean
  /**
   * Вернуть аккаунт на общий пароль его пользователя: доступно отвязанному
   * аккаунту с личным паролем, у которого пользователь есть. Обратная
   * операция к «отвязать и выдать собственный пароль» в диалоге ротации.
   */
  attachShared: boolean
  disable: boolean
  enable: boolean
  delete: boolean
  link: boolean
  /**
   * Принять связанную, но ещё не управляемую учётку под управление и
   * посадить её на общий credential принципала. Для уже управляемого
   * аккаунта то же действие выполняет `attachShared`.
   */
  manageLinked: boolean
  adopt: boolean
  restore: boolean
  /** Безвозвратно удалить уже удалённый metadata tombstone. */
  purge: boolean
  /** Есть ли хоть одно primary-действие (грант/креды/ротация/adopt/lifecycle
   * /delete) — чтобы не рисовать пустой блок кнопок. */
  anyPrimary: boolean
}

export type RestoreBindingEligibility =
  | 'not_applicable'
  | 'loading'
  | 'error'
  | 'eligible'
  | 'blocked'

/** Restore требует доказанного пустого списка bindings, не optimistic zero. */
export function restoreBindingEligibility(
  restoreAction: boolean,
  query: { data: readonly unknown[] | undefined; isPending: boolean; isError: boolean },
): RestoreBindingEligibility {
  if (!restoreAction) return 'not_applicable'
  if (query.isPending) return 'loading'
  if (query.isError || query.data === undefined) return 'error'
  return query.data.length === 0 ? 'eligible' : 'blocked'
}

export function accountActions(
  account: Account,
  role: string,
  connection?: Connection,
): AccountActions {
  const operator = roleAtLeast(role, 'operator')
  const admin = roleAtLeast(role, 'admin')
  // A provisioning reservation does not prove that Grantor owns the target
  // identity or its saved credential. Only the dedicated recovery flow may
  // release it; normal mutations could affect a pre-existing target account.
  const alive = account.status !== 'deleted' && account.status !== 'provisioning'
  // Missing — учётки на target больше нет: adopt/link ей недоступны, пока
  // discovery не увидит её снова (зеркало 409 бэкенда).
  const live = account.status === 'active' || account.status === 'disabled'
  const managed = account.ownership === 'managed'
  // Служебная учётка подключения: adopt и link-and-manage для неё закрыты на
  // бэкенде (409), кнопки прячем, чтобы отказ не приходил постфактум.
  const connectionAdmin = isConnectionAdminAccount(account)
  const shared = isSharedRoleKind(account.kind)
  const credentialIdentity = !shared
  const hasCredential = accountHasCredential(account)

  // Общая роль: её выдают людям со стороны принципала, а из панели самой роли
  // никаких действий нет. Ни принятия под управление, ни удаления: бэкенд
  // отвечает на них 409, потому что account.delete для такой роли означает на
  // целевой системе DROP ROLE — уничтожение права и каскадный отзыв доступа у
  // всех её членов. Управление самим правом идёт через permission, а не через
  // «аккаунт».
  const grant = operator && alive && credentialIdentity
  const share =
    operator && alive && managed && credentialIdentity && hasCredential
  const rotate = operator && alive && managed && credentialIdentity
  // Общий пароль скоуплен пользователем: без привязки возвращать не к чему,
  // а аккаунт уже на общем пароле возвращать некуда.
  const attachShared =
    operator &&
    alive &&
    managed &&
    credentialIdentity &&
    account.principal_id !== null &&
    account.credential_mode !== SHARED_CREDENTIAL_MODE
  const disable =
    operator && alive && managed && credentialIdentity && account.status === 'active'
  const enable =
    operator && alive && managed && credentialIdentity && account.status === 'disabled'
  const del = admin && alive && managed && credentialIdentity
  const link =
    operator && live && credentialIdentity && !connectionAdmin && account.principal_id === null
  const supportsManagedLink = supportsManagedCredentialLink(connection)
  // link-and-manage — путь принятия ЧУЖОЙ учётки: связать с принципалом и
  // посадить на его общий пароль. Уже managed + linked аккаунт сюда не
  // попадает: возврат на общий пароль делает rotate {"attach":true}
  // (attachShared), и два механизма одного действия не нужны.
  const manageLinked =
    operator &&
    account.status === 'active' &&
    credentialIdentity &&
    account.principal_id !== null &&
    supportsManagedLink &&
    !connectionAdmin &&
    !managed
  // Linked-аккаунт нельзя проводить через generic adopt: этот путь создаёт
  // per-account credential и обходит общий credential принципала.
  // Общая роль принимается под управление только как metadata (у неё нет
  // пароля), поэтому credentialIdentity здесь не требуется — кредовые режимы
  // диалог для неё не показывает, а бэкенд отвечает на них 409.
  const adopt = operator && live && !managed && !connectionAdmin && account.principal_id === null
  const restore =
    admin &&
    account.status === 'deleted' &&
    managed &&
    account.kind === 'login' &&
    connection?.status === 'active' &&
    connection.capabilities.includes('account.restore')
  const purge = admin && account.status === 'deleted' && managed

  return {
    grant,
    share,
    shareReason:
      operator && alive && managed && credentialIdentity && !hasCredential
        ? 'У аккаунта нет credential в Vault. Сделайте ротацию, чтобы создать пароль.'
        : undefined,
    rotate,
    attachShared,
    disable,
    enable,
    delete: del,
    link,
    manageLinked,
    adopt,
    restore,
    purge,
    anyPrimary:
      grant ||
      share ||
      rotate ||
      attachShared ||
      disable ||
      enable ||
      del ||
      manageLinked ||
      adopt ||
      restore ||
      purge,
  }
}
