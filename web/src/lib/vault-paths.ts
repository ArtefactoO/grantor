// Пути секретов в Vault для показа оператору. Зеркалят
// internal/providers/vault/paths.go — менять синхронно.
//
// Пути собираются на фронте, а не приходят с бэкенда: API отдаёт vault_path
// только у аккаунта, а общий секрет принципала существует до появления
// аккаунтов, и его всё равно нужно найти в Vault. Mount в путь не входит —
// он задаётся конфигурацией (по умолчанию grantor).

/**
 * Общий credential принципала в окружении:
 * principals/<principal-id>/environments/<environment>/credential.
 * Пустое окружение скоупится сегментом default — как environmentOf бэкенда.
 */
export function principalCredentialVaultPath(
  principalId: string,
  environment: string,
): string {
  const env = environment === '' ? 'default' : environment
  return `principals/${principalId}/environments/${env}/credential`
}
