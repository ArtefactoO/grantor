import type { Principal } from '../lib/types'
import { formatDateTime } from '../lib/time'
import { inventoryStatusTone } from '../lib/status'
import {
  externalIdentityStatusLabel,
  inventoryStatusLabel,
} from '../lib/ui-copy'
import { cn } from '@project/ui'
import { StatusChip } from './ui/badge'

export function hasExternalIdentity(
  principal: Pick<Principal, 'external_provider' | 'external_subject'>,
): boolean {
  return principal.external_provider !== '' && principal.external_subject !== ''
}

function externalStatusTitle(principal: Principal): string {
  const checked = formatDateTime(principal.external_identity_checked_at)
  const changed = formatDateTime(principal.external_identity_status_changed_at)
  return `Проверено: ${checked}. Статус изменён: ${changed}.`
}

export interface PrincipalIdentityChipsProps {
  principal: Principal
  className?: string
}

/**
 * Статус пользователя одним чипом.
 *
 * Раньше у пользователя из каталога показывались ДВА чипа — локальный статус
 * Grantor и статус внешней identity, — и было непонятно, какой из них главный.
 * Для такого пользователя источник истины — каталог, поэтому показывается его
 * статус.
 *
 * Но локальный и внешний статусы — разные факты: Grantor может выключить
 * пользователя, активного в каталоге, и наоборот. Прятать это нельзя —
 * расхождение и есть сигнал незавершённого offboarding, — поэтому оно
 * выносится ОТДЕЛЬНЫМ предупреждающим чипом, а не вторым равноправным
 * статусом.
 *
 * Пока каталог не опрошен (external status пуст), показывается локальный
 * статус: внешнего факта ещё нет, и выдавать его отсутствие за статус
 * пользователя неправильно.
 */
export function PrincipalIdentityChips({
  principal,
  className,
}: PrincipalIdentityChipsProps) {
  const external = hasExternalIdentity(principal)
  const externalStatus = principal.external_identity_status
  const externalKnown = external && externalStatus !== null && externalStatus !== undefined
  const diverged = externalKnown && externalStatus !== principal.status

  return (
    <span className={cn('inline-flex flex-wrap items-center gap-1.5', className)}>
      {externalKnown ? (
        <StatusChip
          tone={inventoryStatusTone(externalStatus)}
          title={externalStatusTitle(principal)}
        >
          {principal.external_provider} · {externalIdentityStatusLabel(externalStatus)}
        </StatusChip>
      ) : (
        <StatusChip
          tone={inventoryStatusTone(principal.status)}
          title="Локальный статус пользователя в Grantor"
        >
          {inventoryStatusLabel(principal.status)}
        </StatusChip>
      )}
      {external && !externalKnown && (
        <StatusChip tone="warn" title={externalStatusTitle(principal)}>
          {principal.external_provider} · {externalIdentityStatusLabel(externalStatus)}
        </StatusChip>
      )}
      {diverged && (
        <StatusChip
          tone="danger"
          title="Статус в Grantor не совпадает со статусом в каталоге: offboarding не доведён до конца"
        >
          Grantor: {inventoryStatusLabel(principal.status)}
        </StatusChip>
      )}
    </span>
  )
}
