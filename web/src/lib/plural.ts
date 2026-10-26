// Русская плюрализация числительных. Тексты интерфейса русские, и числа в
// них попадают из данных (сколько аккаунтов затронет операция, сколько
// систем сменят пароль), поэтому форма слова обязана согласовываться —
// «1 аккаунт», «2 аккаунта», «5 аккаунтов». Без этого предупреждение перед
// опасным действием выглядит машинно и читается хуже.

/** Формы слова: [для 1, для 2-4, для 5-20]. */
export type PluralForms = readonly [one: string, few: string, many: string]

/**
 * Выбирает форму слова по числу. Правила русского: 11-14 — всегда «много»
 * (одиннадцать аккаунтов), иначе решает последняя цифра.
 */
export function plural(count: number, forms: PluralForms): string {
  const n = Math.abs(Math.trunc(count))
  const lastTwo = n % 100
  if (lastTwo >= 11 && lastTwo <= 14) return forms[2]
  const last = n % 10
  if (last === 1) return forms[0]
  if (last >= 2 && last <= 4) return forms[1]
  return forms[2]
}

/** Число вместе с согласованным словом: «3 аккаунта». */
export function pluralize(count: number, forms: PluralForms): string {
  return `${count} ${plural(count, forms)}`
}

/** Часто используемые наборы форм. */
export const PLURAL_ACCOUNTS: PluralForms = ['аккаунт', 'аккаунта', 'аккаунтов']
export const PLURAL_SYSTEMS: PluralForms = ['системе', 'системах', 'системах']
