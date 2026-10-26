import { act, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { CopyButton } from './copy-button'

describe('CopyButton', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  it('copies, announces success and returns to idle after 1500ms', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    })
    render(<CopyButton value="postgres-main" label="Копировать имя" />)

    fireEvent.click(screen.getByRole('button', { name: 'Копировать имя' }))
    await act(async () => Promise.resolve())

    expect(writeText).toHaveBeenCalledWith('postgres-main')
    expect(screen.getByRole('button', { name: 'Скопировано' })).toHaveAttribute(
      'data-success',
      'true',
    )
    expect(screen.getByRole('status')).toHaveTextContent('Скопировано')

    act(() => vi.advanceTimersByTime(1_500))
    expect(screen.getByRole('button', { name: 'Копировать имя' })).toBeInTheDocument()
  })

  it('announces an API failure without reporting success', async () => {
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: vi.fn().mockRejectedValue(new Error('denied')) },
    })
    render(<CopyButton value="visible value" />)

    fireEvent.click(screen.getByRole('button', { name: 'Копировать' }))
    await act(async () => Promise.resolve())

    expect(screen.getByRole('button', { name: 'Не удалось скопировать' })).toBeInTheDocument()
    expect(screen.getByRole('status')).toHaveTextContent('Не удалось скопировать')
    expect(screen.queryByRole('button', { name: 'Скопировано' })).not.toBeInTheDocument()
  })

  it('does not select a containing row when copying', async () => {
    const selectRow = vi.fn()
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    })
    render(<div onClick={selectRow}><CopyButton compact value="visible value" /></div>)
    fireEvent.click(screen.getByRole('button', { name: 'Копировать' }))
    await act(async () => Promise.resolve())
    expect(writeText).toHaveBeenCalledWith('visible value')
    expect(selectRow).not.toHaveBeenCalled()
  })
})
