// Форматирование внешней identity принципала для моноширинных колонок.
import type { Principal } from './types'

/**
 * Внешняя identity принципала: «provider/subject» либо '—', если identity
 * не задана.
 */
export function externalIdentity(principal: Principal): string {
  if (principal.external_provider === '' && principal.external_subject === '') {
    return '—'
  }
  return `${principal.external_provider}/${principal.external_subject}`
}
