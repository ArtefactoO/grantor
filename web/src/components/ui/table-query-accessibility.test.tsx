import { useState } from 'react'
import { fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import {
  EmptyState,
  ErrorState,
  Table,
  TableContainer,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@project/ui'
import { QueryStates } from './query-states'

function InteractiveRowHarness({ onNested }: { onNested: () => void }) {
  const [activations, setActivations] = useState(0)

  return (
    <>
      <output aria-label="Активации строки">{activations}</output>
      <TableContainer>
        <Table>
          <TableBody>
            <TableRow
              interaction="selectable"
              aria-label="Открыть подключение postgres-main"
              onClick={() => setActivations((value) => value + 1)}
            >
              <TableCell>postgres-main</TableCell>
              <TableCell>
                <button type="button" onClick={onNested}>
                  Синхронизировать
                </button>
              </TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </TableContainer>
    </>
  )
}

describe('shared table interaction semantics', () => {
  it('combines selected state with the subtle directory divider', () => {
    render(
      <Table>
        <TableBody>
          <TableRow selected divider="subtle">
            <TableCell>Выбранный аккаунт</TableCell>
          </TableRow>
        </TableBody>
      </Table>,
    )

    expect(screen.getByRole('row')).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('row')).toHaveClass(
      'bg-selected',
      'border-line/35',
      '[box-shadow:inset_0_0_0_1px_var(--selection-outline)]',
    )
  })

  it('wraps long unbroken table content at any character boundary', () => {
    render(
      <Table>
        <TableHeader>
          <tr>
            <TableHead overflow="anywhere">Очень длинный заголовок</TableHead>
          </tr>
        </TableHeader>
        <TableBody>
          <TableRow>
            <TableCell overflow="anywhere">very_long_identity_without_safe_breakpoints</TableCell>
          </TableRow>
        </TableBody>
      </Table>,
    )

    expect(screen.getByRole('columnheader')).toHaveClass('whitespace-normal')
    expect(screen.getByRole('columnheader')).toHaveClass('[overflow-wrap:anywhere]')
    expect(screen.getByRole('columnheader')).not.toHaveClass('whitespace-nowrap')
    expect(screen.getByRole('cell')).toHaveClass('whitespace-normal')
    expect(screen.getByRole('cell')).toHaveClass('[overflow-wrap:anywhere]')
    expect(screen.getByRole('cell')).not.toHaveClass('whitespace-nowrap')
  })

  it('supports quieter row dividers for dense directories', () => {
    render(
      <Table>
        <TableBody>
          <TableRow divider="subtle">
            <TableCell>Аккаунт</TableCell>
          </TableRow>
        </TableBody>
      </Table>,
    )

    expect(screen.getByRole('row')).toHaveClass('border-line/35')
    expect(screen.getByRole('row')).not.toHaveClass('border-line')
  })

  it('activates a selectable composite row with Enter and Space', async () => {
    const user = userEvent.setup()
    render(<InteractiveRowHarness onNested={() => undefined} />)

    const row = screen.getByRole('row', {
      name: 'Открыть подключение postgres-main',
    })
    expect(row).toHaveAttribute('tabindex', '0')
    expect(row).toHaveClass('ui-interactive-row')
    expect(row).not.toHaveClass('hover:bg-panel2/60')

    row.focus()
    await user.keyboard('{Enter}')
    expect(screen.getByRole('status', { name: 'Активации строки' })).toHaveTextContent('1')

    await user.keyboard(' ')
    expect(screen.getByRole('status', { name: 'Активации строки' })).toHaveTextContent('2')
  })

  it('activates a selectable row when ordinary cell content is clicked', async () => {
    const user = userEvent.setup()
    render(<InteractiveRowHarness onNested={() => undefined} />)

    await user.click(screen.getByText('postgres-main'))

    expect(screen.getByRole('status', { name: 'Активации строки' })).toHaveTextContent('1')
  })

  it('does not double-activate a row from its nested native control', async () => {
    const user = userEvent.setup()
    const onNested = vi.fn()
    render(<InteractiveRowHarness onNested={onNested} />)

    await user.click(screen.getByRole('button', { name: 'Синхронизировать' }))

    expect(onNested).toHaveBeenCalledOnce()
    expect(screen.getByRole('status', { name: 'Активации строки' })).toHaveTextContent('0')
  })
})

describe('query state announcements', () => {
  const refetch = vi.fn(async () => undefined)

  it('announces loading with visible copy', () => {
    render(
      <QueryStates
        query={{ isPending: true, isError: false, error: null, data: undefined, refetch }}
      >
        {() => null}
      </QueryStates>,
    )

    expect(screen.getByRole('status')).toHaveTextContent('Загрузка данных…')
  })

  it('announces actionable errors once and keeps retry available', async () => {
    const user = userEvent.setup()
    render(<ErrorState message="Сервис недоступен" onRetry={refetch} />)

    const alert = screen.getByRole('alert')
    expect(alert).toHaveTextContent('Сервис недоступен')
    await user.click(screen.getByRole('button', { name: 'Повторить' }))
    expect(refetch).toHaveBeenCalled()
  })

  it('does not announce a neutral empty state as an error', () => {
    render(<EmptyState title="Подключений пока нет" />)

    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.getByText('Подключений пока нет')).toBeVisible()
  })

  it('keeps a static row inert even when an onClick callback is supplied', () => {
    const onClick = vi.fn()
    render(
      <Table>
        <TableBody>
          <TableRow interaction="static" onClick={onClick}>
            <TableCell>Удалено</TableCell>
          </TableRow>
        </TableBody>
      </Table>,
    )

    const row = screen.getByRole('row')
    expect(row).not.toHaveAttribute('tabindex')
    fireEvent.click(row)
    fireEvent.keyDown(row, { key: 'Enter' })
    expect(onClick).not.toHaveBeenCalled()
  })
})
