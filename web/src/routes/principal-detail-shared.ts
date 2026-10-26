// Общие для экрана «Пользователь» константы и хелперы окружения: режим
// managed-аккаунта на общем секрете и метка окружения подключения.
import type { Connection } from '../lib/types'

// Режим managed-аккаунта на общем секрете принципала
// (credentialModeExistingVaultRef бэкенда). Share доступен для такой
// ссылки; глобальная ротация окружения дополнительно возвращает на
// неё все managed-аккаунты пользователя в выбранном окружении.
export const SHARED_CREDENTIAL_MODE = 'existing_vault_ref'

// environmentLabel зеркалит environmentOf бэкенда: пустое окружение
// подключения скоупится сегментом "default" в пути общего секрета.
export function environmentLabel(connection: Connection): string {
  return connection.environment === '' ? 'default' : connection.environment
}
