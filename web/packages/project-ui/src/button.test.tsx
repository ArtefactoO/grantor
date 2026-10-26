import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { FormEvent } from 'react'
import { describe, expect, it, vi } from 'vitest'
import { Button } from './button'

describe('Button', () => {
  it('uses the shared tactile interaction surface without changing button semantics', async () => {
    const user = userEvent.setup()
    const onClick = vi.fn()

    render(<Button onClick={onClick}>Сохранить</Button>)

    const button = screen.getByRole('button', { name: 'Сохранить' })
    expect(button).toHaveAttribute('type', 'button')
    expect(button).toHaveClass('ui-button', 'ui-control-feedback', 'grantor-touch-target')
    expect(button).not.toHaveClass('ui-action-sheen')

    await user.click(button)
    expect(onClick).toHaveBeenCalledOnce()
  })

  it('keeps native keyboard activation and disabled behavior in forms', async () => {
    const user = userEvent.setup()
    const onClick = vi.fn()
    const onSubmit = vi.fn((event: FormEvent<HTMLFormElement>) => event.preventDefault())
    const { rerender } = render(
      <form onSubmit={onSubmit}><Button onClick={onClick}>Сохранить</Button></form>,
    )

    const button = screen.getByRole('button', { name: 'Сохранить' })
    button.focus()
    await user.keyboard('{Enter}')
    expect(onClick).toHaveBeenCalledOnce()
    expect(onSubmit).not.toHaveBeenCalled()

    rerender(<form onSubmit={onSubmit}><Button disabled onClick={onClick}>Сохранить</Button></form>)
    await user.click(button)
    expect(button).toBeDisabled()
    expect(onClick).toHaveBeenCalledOnce()
    expect(onSubmit).not.toHaveBeenCalled()
  })
})
