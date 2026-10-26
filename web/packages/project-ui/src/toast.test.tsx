import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

const motionPreference = vi.hoisted(() => ({ reduced: false }))
vi.mock('motion/react', async (importOriginal) => ({
  ...await importOriginal<typeof import('motion/react')>(),
  useReducedMotion: () => motionPreference.reduced,
}))
import { ToastProvider, useToast } from './toast'

afterEach(() => { motionPreference.reduced = false })

function Trigger({ onUndo }: { onUndo?: () => void }) {
  const toast = useToast()
  return (
    <button
      type="button"
      onClick={() => toast.show({
        message: 'Роль admin снята',
        action: onUndo === undefined ? undefined : { label: 'Вернуть', onAct: onUndo },
      })}
    >
      снять
    </button>
  )
}

describe('уведомления с отменой', () => {
  it('предлагает вернуть только что снятое', async () => {
    const undo = vi.fn()
    render(<ToastProvider><Trigger onUndo={undo} /></ToastProvider>)

    await userEvent.click(screen.getByRole('button', { name: 'снять' }))
    expect(screen.getByText('Роль admin снята')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: 'Вернуть' }))
    expect(undo).toHaveBeenCalledOnce()
    // Уведомление уходит: отмена уже запущена, второй раз её жать нечего.
    await waitFor(() => expect(screen.queryByText('Роль admin снята')).not.toBeInTheDocument())
  })

  it('закрывается вручную', async () => {
    render(<ToastProvider><Trigger /></ToastProvider>)

    await userEvent.click(screen.getByRole('button', { name: 'снять' }))
    await userEvent.click(screen.getByRole('button', { name: 'Закрыть уведомление' }))

    await waitFor(() => expect(screen.queryByText('Роль admin снята')).not.toBeInTheDocument())
  })

  it('закрывается с клавиатуры без запуска действия отмены', async () => {
    const user = userEvent.setup()
    const undo = vi.fn()
    render(<ToastProvider><Trigger onUndo={undo} /></ToastProvider>)
    await user.click(screen.getByRole('button', { name: 'снять' }))
    const close = screen.getByRole('button', { name: 'Закрыть уведомление' })
    expect(close).toHaveClass('ui-control-feedback', 'grantor-touch-target')
    close.focus()
    await user.keyboard('{Enter}')
    await waitFor(() => expect(screen.queryByText('Роль admin снята')).not.toBeInTheDocument())
    expect(undo).not.toHaveBeenCalled()
  })

  it('показывает итог сразу и сохраняет отмену при reduced motion', async () => {
    motionPreference.reduced = true
    const user = userEvent.setup()
    const undo = vi.fn()
    render(<ToastProvider><Trigger onUndo={undo} /></ToastProvider>)
    await user.click(screen.getByRole('button', { name: 'снять' }))
    expect(screen.getByRole('status')).toHaveStyle({ opacity: '1' })
    await user.click(screen.getByRole('button', { name: 'Вернуть' }))
    expect(undo).toHaveBeenCalledOnce()
    await waitFor(() => expect(screen.queryByRole('status')).not.toBeInTheDocument())
  })

  // Уведомление вспомогательное: без провайдера действие обязано работать.
  it('не ломает действие вне провайдера', async () => {
    render(<Trigger />)

    await userEvent.click(screen.getByRole('button', { name: 'снять' }))
    expect(screen.queryByText('Роль admin снята')).not.toBeInTheDocument()
  })
})
