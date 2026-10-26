import { describe, expect, it } from 'vitest'
import { plural, pluralize, PLURAL_ACCOUNTS } from './plural'

describe('plural', () => {
  it('выбирает форму по последней цифре', () => {
    expect(plural(1, PLURAL_ACCOUNTS)).toBe('аккаунт')
    expect(plural(2, PLURAL_ACCOUNTS)).toBe('аккаунта')
    expect(plural(4, PLURAL_ACCOUNTS)).toBe('аккаунта')
    expect(plural(5, PLURAL_ACCOUNTS)).toBe('аккаунтов')
    expect(plural(0, PLURAL_ACCOUNTS)).toBe('аккаунтов')
  })

  // 11-14 — исключение: последняя цифра говорит одно, а форма всегда «много».
  it('обрабатывает 11-14 как исключение', () => {
    expect(plural(11, PLURAL_ACCOUNTS)).toBe('аккаунтов')
    expect(plural(12, PLURAL_ACCOUNTS)).toBe('аккаунтов')
    expect(plural(14, PLURAL_ACCOUNTS)).toBe('аккаунтов')
  })

  it('учитывает разряды выше десятков', () => {
    expect(plural(21, PLURAL_ACCOUNTS)).toBe('аккаунт')
    expect(plural(22, PLURAL_ACCOUNTS)).toBe('аккаунта')
    expect(plural(25, PLURAL_ACCOUNTS)).toBe('аккаунтов')
    expect(plural(101, PLURAL_ACCOUNTS)).toBe('аккаунт')
    expect(plural(111, PLURAL_ACCOUNTS)).toBe('аккаунтов')
  })

  it('pluralize добавляет число', () => {
    expect(pluralize(1, PLURAL_ACCOUNTS)).toBe('1 аккаунт')
    expect(pluralize(5, PLURAL_ACCOUNTS)).toBe('5 аккаунтов')
  })
})
