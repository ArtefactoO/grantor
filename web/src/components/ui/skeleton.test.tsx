import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { QueryStates } from './query-states'
import { LoadingSkeleton, RowSkeleton } from '@project/ui'

const query = <T,>(overrides: Partial<{ isError: boolean; isPending: boolean; error: unknown; data: T }>) => ({
  isError: false,
  isPending: false,
  error: null,
  data: undefined as T | undefined,
  refetch: async () => undefined,
  ...overrides,
})

describe('состояние загрузки', () => {
  it('рисует скелетон вместо спиннера, пока данных нет', () => {
    render(
      <QueryStates query={query<string[]>({ isPending: true })}>
        {() => <div>данные</div>}
      </QueryStates>,
    )

    expect(screen.getByRole('status')).toHaveAttribute('aria-busy', 'true')
    expect(screen.getByText('Загрузка данных…')).toBeInTheDocument()
    expect(screen.queryByText('данные')).not.toBeInTheDocument()
  })

  // Скелетон декоративен: экранный диктор читает статус, а не пустые полосы.
  it('прячет заглушку от screen reader', () => {
    const { container } = render(<LoadingSkeleton><RowSkeleton rows={3} /></LoadingSkeleton>)

    expect(container.querySelector('[aria-hidden="true"]')).not.toBeNull()
    expect(screen.getByText('Загрузка данных…')).toHaveClass('sr-only')
  })

  it('уступает место данным, когда они приехали', () => {
    render(
      <QueryStates query={query<string[]>({ data: ['a'] })}>
        {(data) => <div>{data.join(',')}</div>}
      </QueryStates>,
    )

    expect(screen.getByText('a')).toBeInTheDocument()
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
  })
})
