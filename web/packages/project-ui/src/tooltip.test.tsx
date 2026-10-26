import { act, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Tooltip } from './tooltip'

describe('Tooltip', () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => vi.useRealTimers())

  it('opens after the pointer delay and closes on Escape', () => {
    render(
      <Tooltip content="Синхронизировать">
        <button type="button">Действие</button>
      </Tooltip>,
    )
    const button = screen.getByRole('button', { name: 'Действие' })
    fireEvent.pointerEnter(button)
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()

    act(() => vi.advanceTimersByTime(350))
    expect(screen.getByRole('tooltip')).toHaveTextContent('Синхронизировать')

    fireEvent.keyDown(window, { key: 'Escape' })
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()
  })

  it('opens immediately for keyboard focus', () => {
    render(
      <Tooltip content="Копировать">
        <button type="button">Copy</button>
      </Tooltip>,
    )
    fireEvent.focus(screen.getByRole('button', { name: 'Copy' }))
    expect(screen.getByRole('tooltip')).toHaveTextContent('Копировать')
  })
})
