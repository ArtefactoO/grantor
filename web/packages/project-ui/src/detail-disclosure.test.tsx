import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { DetailDisclosure } from './detail-disclosure'

const motionPreference = vi.hoisted(() => ({ reduced: false }))

vi.mock('motion/react', async (importOriginal) => ({
  ...await importOriginal<typeof import('motion/react')>(),
  useReducedMotion: () => motionPreference.reduced,
}))

beforeEach(() => {
  motionPreference.reduced = false
})

describe.each([false, true])('DetailDisclosure with reduced motion %s', (reduced) => {
  it('reveals full geometry immediately and collapses without leaving hidden controls', async () => {
    motionPreference.reduced = reduced
    const user = userEvent.setup()
    render(
      <DetailDisclosure label="Атрибуты" icon={null} summary="Атрибуты подключения">
        <button type="button">Копировать атрибуты</button>
      </DetailDisclosure>,
    )
    const toggle = screen.getByRole('button', { name: 'Атрибуты подключения' })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    await user.tab()
    expect(toggle).toHaveFocus()
    await user.keyboard('{Enter}')

    const content = document.getElementById(toggle.getAttribute('aria-controls') ?? '')
    expect(content).toContainElement(screen.getByRole('button', { name: 'Копировать атрибуты' }))
    expect(toggle).toHaveAttribute('aria-expanded', 'true')
    expect(content?.style.height).toBe('')
    expect(content?.style.width).toBe('')
    expect(content?.style.transform).toBe('')
    if (reduced) expect(content?.style.opacity).toBe('1')

    await user.keyboard('{Enter}')
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(toggle).toHaveFocus()
    expect(screen.queryByRole('button', { name: 'Копировать атрибуты' })).not.toBeInTheDocument()
    expect(document.getElementById(toggle.getAttribute('aria-controls') ?? '')).toBeNull()
  })
})
