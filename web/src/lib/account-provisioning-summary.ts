import type { Account } from './types'
import type { ChipTone } from '../components/ui/badge'
import { inventoryStatusLabel } from './ui-copy'
import { inventoryStatusTone } from './status'

export function accountProvisioningSummaryPresentation(
  account: Pick<Account, 'status' | 'provisioning_summary'>,
): { label: string; tone: ChipTone } {
  if (account.status !== 'provisioning') {
    return { label: inventoryStatusLabel(account.status), tone: inventoryStatusTone(account.status) }
  }
  switch (account.provisioning_summary?.state) {
    case 'running':
      return {
        label: account.provisioning_summary.operation_status === 'pending_approval'
          ? 'Ожидает подтверждения' : 'Есть незавершенная операция',
        tone: 'warn',
      }
    case 'verification_required':
      return { label: 'Нужна проверка входа', tone: 'warn' }
    case 'failed':
      return { label: 'Ошибка создания', tone: 'danger' }
    default:
      return { label: 'Результат не подтвержден', tone: 'warn' }
  }
}
