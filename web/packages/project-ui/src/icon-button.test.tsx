import { fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { X } from './icons'
import { IconButton } from './icon-button'

describe('IconButton', () => {
  it('uses one canonical Russian action for the accessible name and tooltip', () => {
    render(<IconButton label="Закрыть панель" icon={<X />} />)

    const button = screen.getByRole('button', { name: 'Закрыть панель' })
    fireEvent.focus(button)

    expect(screen.getByRole('tooltip')).toHaveTextContent('Закрыть панель')
  })

  it('appends diagnostics without replacing the action name', () => {
    render(
      <IconButton
        label="Повторить синхронизацию"
        tooltipDetails="подключение недоступно"
        icon={<X />}
      />,
    )

    const button = screen.getByRole('button', { name: 'Повторить синхронизацию' })
    fireEvent.focus(button)

    expect(screen.getByRole('tooltip')).toHaveTextContent(
      'Повторить синхронизацию: подключение недоступно',
    )
  })

  it('shares feedback and touch sizing while retaining compact keyboard actions', async () => {
    const user = userEvent.setup()
    const onClick = vi.fn()
    const { rerender } = render(
      <IconButton compact label="Закрыть панель" icon={<X />} onClick={onClick} />,
    )
    const button = screen.getByRole('button', { name: 'Закрыть панель' })
    expect(button).toHaveClass('size-6', 'ui-control-feedback', 'grantor-touch-target')
    button.focus()
    await user.keyboard('{Enter}')
    expect(onClick).toHaveBeenCalledOnce()

    rerender(<IconButton compact busy label="Закрыть панель" icon={<X />} onClick={onClick} />)
    expect(button).toBeDisabled()
    expect(button).toHaveAttribute('aria-busy', 'true')
    await user.click(button)
    expect(onClick).toHaveBeenCalledOnce()
  })
})
