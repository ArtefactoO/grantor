import type { Account, Principal } from './types'

export interface ConnectionAccountPickerProjection {
  principals: Principal[]
  accountByPrincipalId: Map<string, Account>
  localDeletedAccounts: Account[]
}

/**
 * Единственная проекция данных для unified «Добавить аккаунт» picker.
 *
 * - deleted principals не являются кандидатами на новую выдачу;
 * - linked accounts представлены только через свой current principal;
 * - отдельными restore-кандидатами остаются только локальные tombstone;
 * - если у principal несколько логинов, live account важнее deleted,
 *   поэтому picker не предлагает restore при уже существующем account.
 */
export function buildConnectionAccountPickerProjection(
  principals: readonly Principal[],
  accounts: readonly Account[],
): ConnectionAccountPickerProjection {
  const currentPrincipals = principals.filter((principal) => principal.status !== 'deleted')
  const currentPrincipalIds = new Set(currentPrincipals.map((principal) => principal.id))
  const accountByPrincipalId = new Map<string, Account>()

  for (const account of accounts) {
    if (account.principal_id === null || !currentPrincipalIds.has(account.principal_id)) continue
    const current = accountByPrincipalId.get(account.principal_id)
    if (current === undefined || (current.status === 'deleted' && account.status !== 'deleted')) {
      accountByPrincipalId.set(account.principal_id, account)
    }
  }

  return {
    principals: currentPrincipals,
    accountByPrincipalId,
    localDeletedAccounts: accounts.filter(
      (account) =>
        account.principal_id === null &&
        account.status === 'deleted' &&
        account.ownership === 'managed' &&
        account.kind === 'login',
    ),
  }
}
