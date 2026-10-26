import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import type { Principal } from '../lib/types'
import { PrincipalDirectory } from './principals'

function principal(
  id: string,
  name: string,
  status: string,
  provider = '',
  subject = '',
  externalStatus: 'active' | 'disabled' | 'deleted' | null = null,
): Principal {
  return {
    id,
    type: 'human',
    display_name: name,
    external_provider: provider,
    external_subject: subject,
    external_identity_status: provider === '' ? null : externalStatus,
    external_identity_checked_at: provider === '' ? null : '2026-07-21T10:00:00Z',
    external_identity_status_changed_at:
      provider === '' ? null : '2026-07-21T09:00:00Z',
    status,
    attributes: {},
    accounts_count: 0,
    created_at: '2026-07-20T00:00:00Z',
    updated_at: '2026-07-20T00:00:00Z',
  }
}

const PRINCIPALS = [
  principal('anna', 'Анна Кутина', 'active', 'dex', 'akutikina', 'disabled'),
  principal('deploy', 'Deploy Bot', 'active', 'gitlab', 'deploy-bot', 'active'),
  principal('deleted', 'Offboard Self Test', 'deleted'),
]

describe('PrincipalDirectory', () => {
  it('searches by display name and external identity', async () => {
    const user = userEvent.setup()
    render(<PrincipalDirectory principals={PRINCIPALS} onOpen={vi.fn()} />)

    const search = screen.getByRole('textbox', { name: 'Поиск пользователей' })
    await user.type(search, 'gitlab/deploy')

    expect(screen.getByText('Deploy Bot')).toBeInTheDocument()
    expect(screen.queryByText('Анна Кутина')).not.toBeInTheDocument()
  })

  it('reuses the compact shared search inside the filters toolbar', () => {
    render(
      <PrincipalDirectory
        principals={PRINCIPALS}
        onOpen={vi.fn()}
        action={<button type="button">Добавить пользователя</button>}
      />,
    )

    const toolbar = screen.getByRole('group', {
      name: 'Поиск и фильтры пользователей',
    })
    const search = screen.getByRole('textbox', { name: 'Поиск пользователей' })

    expect(toolbar).toContainElement(search)
    expect(toolbar).toContainElement(
      screen.getByRole('button', { name: 'Добавить пользователя' }),
    )
    expect(search).toHaveClass('h-8', 'text-xs')
  })

  it('keeps Current/Deleted mutually exclusive and never deselects the active chip', async () => {
    const user = userEvent.setup()
    render(<PrincipalDirectory principals={PRINCIPALS} onOpen={vi.fn()} />)

    const current = screen.getByRole('radio', { name: 'Current 2' })
    await user.click(current)
    expect(current).toHaveAttribute('aria-checked', 'true')

    const deleted = screen.getByRole('radio', { name: 'Deleted 1' })
    await user.click(deleted)
    expect(current).toHaveAttribute('aria-checked', 'false')
    expect(deleted).toHaveAttribute('aria-checked', 'true')
    expect(screen.getByText('Offboard Self Test')).toBeInTheDocument()
  })

  it('opens the exact selected row', async () => {
    const user = userEvent.setup()
    const onOpen = vi.fn()
    render(<PrincipalDirectory principals={PRINCIPALS} onOpen={onOpen} />)

    await user.click(screen.getByText('Анна Кутина'))
    expect(onOpen).toHaveBeenCalledWith('anna')
  })

  it('uses the shared compact copy action next to every user name without opening the row', async () => {
    const user = userEvent.setup()
    const onOpen = vi.fn()
    render(<PrincipalDirectory principals={PRINCIPALS} onOpen={onOpen} />)

    const copy = screen.getByRole('button', { name: 'Копировать login Анна Кутина' })

    expect(copy.closest('div')).toHaveTextContent('Анна Кутина')
    expect(copy).toHaveClass('size-6')
    await user.click(copy)
    expect(onOpen).not.toHaveBeenCalled()
  })

  it('turns every mobile row into a non-clipping card without dropping fields', () => {
    render(<PrincipalDirectory principals={PRINCIPALS} onOpen={vi.fn()} />)

    const row = screen.getByText('Анна Кутина').closest('tr')
    expect(row).toHaveClass('max-sm:grid', 'max-sm:grid-cols-1')
    expect(row).toHaveTextContent('LoginАнна Кутина')
    expect(row).toHaveTextContent('ТипHuman')
    expect(row).toHaveTextContent('Внешний IDdex/akutikina')
    expect(row).toHaveTextContent('Аккаунты0')
    // У пользователя из каталога статус показывается ОДИН — внешний, а
    // расхождение с локальным выносится отдельным предупреждением.
    expect(row).toHaveTextContent('Identity и статусdex · DisabledGrantor: Active')

    const tableWrap = row?.closest('div')
    expect(tableWrap).toHaveClass('max-sm:overflow-x-visible')
  })

  it('shows one status for a directory user and flags divergence separately', async () => {
    const user = userEvent.setup()
    render(<PrincipalDirectory principals={PRINCIPALS} onOpen={vi.fn()} />)

    // Источник истины для пользователя из каталога — сам каталог, поэтому
    // его статус и показывается. Локальный статус остаётся видимым только
    // как расхождение: именно оно и есть сигнал незавершённого offboarding.
    const externalRow = screen.getByText('Анна Кутина').closest('tr')
    expect(externalRow).toHaveTextContent('dex · Disabled')
    expect(externalRow).toHaveTextContent('Grantor: Active')

    await user.click(screen.getByRole('radio', { name: 'Deleted 1' }))
    const localRow = screen.getByText('Offboard Self Test').closest('tr')
    expect(localRow).toHaveTextContent('Deleted')
    expect(localRow).not.toHaveTextContent('Grantor ·')
    expect(localRow).not.toHaveTextContent('Identity:')
  })
})
