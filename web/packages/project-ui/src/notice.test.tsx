import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { InlineNotice } from './notice'

describe('InlineNotice', () => {
  it('uses the shared close action with native keyboard activation', async () => {
    const user = userEvent.setup()
    const onClose = vi.fn()
    render(<InlineNotice text="Изменения сохранены" onClose={onClose} />)
    const close = screen.getByRole('button', { name: 'Скрыть уведомление' })
    expect(close).toHaveClass('ui-control-feedback', 'grantor-touch-target')
    close.focus()
    await user.keyboard('{Enter}')
    expect(onClose).toHaveBeenCalledOnce()
  })
})
