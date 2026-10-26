import { useRef, useState } from 'react'
import type { ComponentType } from 'react'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { Dialog } from './dialog'
import type { DialogProps } from './dialog'
import { Drawer } from './drawer'

const motionPreference = vi.hoisted(() => ({ reduced: false }))

vi.mock('motion/react', async (importOriginal) => ({
  ...await importOriginal<typeof import('motion/react')>(),
  useReducedMotion: () => motionPreference.reduced,
}))

beforeEach(() => {
  motionPreference.reduced = false
})

type ModalKind = 'dialog' | 'drawer'

function ModalHarness({
  kind,
  closeOnOverlayClick = true,
  explicitInitialFocus = true,
}: {
  kind: ModalKind
  closeOnOverlayClick?: boolean
  explicitInitialFocus?: boolean
}) {
  const [open, setOpen] = useState(false)
  const initialFocusRef = useRef<HTMLButtonElement>(null)
  const Modal = (kind === 'dialog' ? Dialog : Drawer) as ComponentType<DialogProps>

  return (
    <>
      <button type="button" onClick={() => setOpen(true)}>
        Открыть {kind}
      </button>
      <a href="#background">Фоновая ссылка</a>
      <Modal
        open={open}
        onClose={() => setOpen(false)}
        title="Выдать доступ"
        description="Выберите параметры нового доступа"
        initialFocusRef={explicitInitialFocus ? initialFocusRef : undefined}
        closeOnOverlayClick={closeOnOverlayClick}
      >
        <button ref={initialFocusRef} type="button">
          Первый контрол
        </button>
        <button type="button">Второй контрол</button>
      </Modal>
    </>
  )
}

describe.each<ModalKind>(['dialog', 'drawer'])('%s accessibility foundation', (kind) => {
  it('has a labelled title and description and moves initial focus', async () => {
    const user = userEvent.setup()
    render(<ModalHarness kind={kind} />)

    await user.click(screen.getByRole('button', { name: `Открыть ${kind}` }))

    const modal = screen.getByRole('dialog', { name: 'Выдать доступ' })
    expect(modal).toHaveAccessibleDescription('Выберите параметры нового доступа')
    expect(modal).toHaveClass('shadow-[var(--shadow-floating)]')
    expect(modal).not.toHaveClass('shadow-2xl')
    expect(screen.getByRole('button', { name: 'Первый контрол' })).toHaveFocus()
  })

  it('skips the close action when choosing default initial focus', async () => {
    const user = userEvent.setup()
    render(<ModalHarness kind={kind} explicitInitialFocus={false} />)

    await user.click(screen.getByRole('button', { name: `Открыть ${kind}` }))

    expect(screen.getByRole('button', { name: 'Первый контрол' })).toHaveFocus()
    expect(screen.getByRole('button', { name: 'Закрыть' })).not.toHaveFocus()
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()
  })

  it('contains Tab focus inside the modal', async () => {
    const user = userEvent.setup()
    render(<ModalHarness kind={kind} />)

    await user.click(screen.getByRole('button', { name: `Открыть ${kind}` }))
    await user.tab()
    expect(screen.getByRole('button', { name: 'Второй контрол' })).toHaveFocus()

    await user.tab()
    const close = screen.getByRole('button', { name: 'Закрыть' })
    expect(close).toHaveFocus()
    expect(close).toHaveClass('ui-icon-button')
    expect(screen.getByRole('tooltip')).toHaveTextContent('Закрыть')
    const backgroundLink = screen.getByText('Фоновая ссылка')
    expect(backgroundLink).not.toHaveFocus()
    expect(backgroundLink.closest('[aria-hidden="true"]')).not.toBeNull()
  })

  it('closes on Escape and restores focus to the opener', async () => {
    const user = userEvent.setup()
    render(<ModalHarness kind={kind} />)
    const trigger = screen.getByRole('button', { name: `Открыть ${kind}` })

    await user.click(trigger)
    await user.keyboard('{Escape}')

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    await waitFor(() => expect(trigger).toHaveFocus())
  })

  it('closes on overlay interaction by default', async () => {
    const user = userEvent.setup()
    render(<ModalHarness kind={kind} />)

    await user.click(screen.getByRole('button', { name: `Открыть ${kind}` }))
    const overlay = document.querySelector(`[data-slot="${kind}-overlay"]`)
    expect(overlay).not.toBeNull()
    await user.click(overlay as Element)

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  })

  it('keeps the modal open when overlay close is disabled', async () => {
    const user = userEvent.setup()
    render(<ModalHarness kind={kind} closeOnOverlayClick={false} />)

    await user.click(screen.getByRole('button', { name: `Открыть ${kind}` }))
    const overlay = document.querySelector(`[data-slot="${kind}-overlay"]`)
    expect(overlay).not.toBeNull()
    await user.click(overlay as Element)

    expect(screen.getByRole('dialog', { name: 'Выдать доступ' })).toBeInTheDocument()
  })
})

describe.each([false, true])('modal geometry with reduced motion %s', (reduced) => {
  it.each<ModalKind>(['dialog', 'drawer'])('places %s in its final position on the first frame', async (kind) => {
    motionPreference.reduced = reduced
    const user = userEvent.setup()
    render(<ModalHarness kind={kind} />)
    const opener = screen.getByRole('button', { name: `Открыть ${kind}` })

    await user.click(opener)
    const modal = screen.getByRole('dialog', { name: 'Выдать доступ' })
    if (kind === 'dialog') {
      expect(modal).toHaveClass('left-1/2', 'top-1/2')
      expect(modal.style.transform).toBe('translate(-50%, -50%)')
    } else {
      expect(modal).toHaveClass('right-0', 'top-0', 'w-[440px]', 'max-w-[92vw]')
      expect(modal.style.transform).toBe('')
    }
    expect(modal.style.height).toBe('')
    expect(modal.style.width).toBe('')
    if (reduced) expect(modal.style.opacity).toBe('1')
    expect(screen.getByRole('button', { name: 'Первый контрол' })).toHaveFocus()

    await user.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    await waitFor(() => expect(opener).toHaveFocus())
  })
})

describe('dialog responsive layout', () => {
  it('keeps a single scroll body below the height limit and a persistent optional footer', () => {
    render(
      <Dialog
        open
        onClose={() => undefined}
        title="Редактировать подключение"
        footer={<button type="button">Сохранить</button>}
      >
        <button type="button">Поле формы</button>
      </Dialog>,
    )

    const dialog = screen.getByRole('dialog', { name: 'Редактировать подключение' })
    expect(dialog).toHaveClass(
      'flex',
      'max-h-[calc(100dvh-2rem)]',
      'flex-col',
      'overflow-hidden',
    )

    const body = dialog.querySelector('[data-slot="dialog-body"]')
    expect(body).toHaveClass('min-h-0', 'flex-1', 'overflow-y-auto')

    const footer = dialog.querySelector('[data-slot="dialog-footer"]')
    expect(footer).toHaveClass('shrink-0', 'border-t')
    expect(footer).toContainElement(screen.getByRole('button', { name: 'Сохранить' }))
    expect(body).not.toContainElement(screen.getByRole('button', { name: 'Сохранить' }))
  })
})
