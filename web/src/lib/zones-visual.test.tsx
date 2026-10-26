import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { ZoneSectionRow, ZoneTabs } from './zones'

describe('zone section visual hierarchy', () => {
  it('uses a quiet zone marker without coloring every managed row', () => {
    render(
      <table>
        <tbody>
          <ZoneSectionRow zone="managed" colSpan={5} count={3} />
        </tbody>
      </table>,
    )

    expect(screen.getByRole('row')).not.toHaveClass('border-line/35')
    expect(screen.getByRole('cell')).toHaveClass('p-0')
    expect(screen.getByRole('cell').firstElementChild).toHaveClass('h-8', 'bg-panel2/25')
    expect(screen.getByText('Managed')).toBeVisible()
    expect(screen.getByRole('cell').querySelector('[aria-hidden="true"]')).toHaveClass('bg-ok/75')
    expect(screen.getByRole('cell').querySelector('svg')).toBeNull()
  })

  it('keeps empty-section guidance in a focusable tooltip', async () => {
    const user = userEvent.setup()
    render(
      <table>
        <tbody>
          <ZoneSectionRow
            zone="managed"
            colSpan={5}
            count={0}
            hint="создайте аккаунт или выдайте право"
          />
        </tbody>
      </table>,
    )

    expect(screen.queryByText('создайте аккаунт или выдайте право')).not.toBeInTheDocument()

    await user.hover(screen.getByLabelText('Подробнее о секции Managed'))
    expect(await screen.findByRole('tooltip')).toHaveTextContent(
      'создайте аккаунт или выдайте право',
    )

    await user.unhover(screen.getByLabelText('Подробнее о секции Managed'))
    await user.tab()
    expect(await screen.findByRole('tooltip')).toHaveTextContent(
      'создайте аккаунт или выдайте право',
    )
  })

  it('uses the canonical Unmanaged label for discovered accounts', () => {
    render(
      <table>
        <tbody>
          <ZoneSectionRow zone="sync" colSpan={5} count={3} />
        </tbody>
      </table>,
    )

    expect(screen.getByText('Unmanaged')).toBeVisible()
    expect(screen.getByRole('cell').querySelector('svg')).toBeNull()
  })

  it('separates read-only tabs without rendering sync icons as navigation', () => {
    render(
      <ZoneTabs
        active="accounts"
        onSelect={() => undefined}
        tabs={[
          { key: 'accounts', label: 'Аккаунты', zone: 'managed' },
          { key: 'resources', label: 'Ресурсы', zone: 'sync' },
          { key: 'roles', label: 'Роли', zone: 'sync' },
        ]}
      />,
    )

    expect(screen.getByRole('button', { name: 'Ресурсы' }).querySelector('svg')).toBeNull()
    expect(screen.getByRole('button', { name: 'Роли' }).querySelector('svg')).toBeNull()
  })
})
