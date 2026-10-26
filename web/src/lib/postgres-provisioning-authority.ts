import type { Connection } from './types'

export const POSTGRES_SUPERUSER_DIRECT_CAPABILITY = 'postgres.superuser_direct.v1'

export function postgresProvisioningReady(connection: Connection): boolean {
  const authority = connection.postgres_provisioning_authority
  return connection.engine === 'postgres' && connection.status === 'active' &&
    connection.capabilities.includes(POSTGRES_SUPERUSER_DIRECT_CAPABILITY) &&
    authority?.status === 'confirmed' && authority.reason === 'superuser_confirmed'
}

/** Recovery-oriented copy for every PostgreSQL creation surface. */
export function postgresProvisioningIssue(connection: Connection): string | null {
  if (connection.engine !== 'postgres' || postgresProvisioningReady(connection)) return null
  const authority = connection.postgres_provisioning_authority
  switch (authority?.reason) {
    case 'superuser_required':
      return 'Admin credential подключения не является PostgreSQL SUPERUSER. Создание баз, ролей и role policies заблокировано. Выдайте SUPERUSER этой учётке и запустите синхронизацию.'
    case 'admin_identity_mismatch':
      return 'PostgreSQL возвращает другую admin identity. Проверьте учётку подключения и запустите синхронизацию.'
    case 'read_only_target':
      return 'Подключение ведёт на read-only узел. Для создания ресурсов укажите writable primary и запустите синхронизацию.'
    case 'admin_credential_missing':
    case 'credential_incarnation_missing':
      return 'Admin credential не подтверждён. Укажите учётку PostgreSQL SUPERUSER и запустите синхронизацию.'
    case 'target_identity_unavailable':
      return 'Не удалось подтвердить PostgreSQL-кластер. Проверьте доступ admin-учётки к системному идентификатору и запустите синхронизацию.'
    default:
      if (authority?.status === 'confirmed') {
        return 'Текущий control plane или connector не подтвердил контракт прямого PostgreSQL provisioning. Обновите компоненты и запустите синхронизацию.'
      }
      return 'Grantor ещё не подтвердил PostgreSQL SUPERUSER для этого подключения. Запустите синхронизацию после настройки admin credential.'
  }
}
