import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { RadioOptionCard } from './radio-option-card'

describe('RadioOptionCard', () => {
  it('keeps the whole full-width card as one accessible radio target', async () => {
    const onSelect = vi.fn()
    const user = userEvent.setup()

    render(
      <RadioOptionCard
        name="scope"
        label="Все аккаунты пользователя"
        hint="test · окружение dev"
        tooltip="Затронет все подключения окружения"
        checked={false}
        onSelect={onSelect}
      />,
    )

    const radio = screen.getByRole('radio', { name: /Все аккаунты пользователя/ })
    expect(radio.closest('label')).toHaveClass('w-full')
    await user.click(screen.getByRole('note', { name: 'Подробнее' }))
    expect(onSelect).not.toHaveBeenCalled()
    await user.click(screen.getByText('Все аккаунты пользователя'))
    expect(onSelect).toHaveBeenCalledOnce()
  })

  it('reuses the shared selected surface instead of a page-local highlight', () => {
    render(
      <RadioOptionCard
        name="scope"
        label="Все аккаунты пользователя"
        hint="test · окружение dev"
        checked
        onSelect={vi.fn()}
      />,
    )

    expect(screen.getByRole('radio').closest('label')).toHaveClass(
      'ui-selection-surface',
      'bg-selected',
      '[box-shadow:inset_0_0_0_1px_var(--selection-outline)]',
    )
  })
})
