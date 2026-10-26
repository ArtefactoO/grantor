import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { AccessChipList } from './access-chips'

describe('AccessChipList', () => {
  it('allows long role names and the chip row to wrap when requested', () => {
    render(
      <AccessChipList
        entries={[
          {
            label: 'role_with_a_very_long_name_for_animation_board',
            full: 'role_with_a_very_long_name_for_animation_board @ animation_board',
            group: 'database',
            dangerous: false,
          },
        ]}
        wrapLabels
      />,
    )

    const role = screen.getByText('role_with_a_very_long_name_for_animation_board')
    expect(role).toHaveClass('[overflow-wrap:anywhere]')
    expect(role.parentElement?.parentElement).toHaveClass('flex-wrap', 'h-auto')
  })

  it('uses the themed floating shadow for the full access list', async () => {
    const user = userEvent.setup()
    render(
      <AccessChipList
        maxVisible={1}
        entries={[
          { label: 'read', full: 'read @ database', group: 'database', dangerous: false },
          { label: 'write', full: 'write @ database', group: 'database', dangerous: false },
        ]}
      />,
    )

    await user.click(screen.getByRole('button', { name: 'Показать все права (2)' }))
    const panel = screen.getByRole('dialog', { name: 'Все права' })
    expect(panel).toHaveClass('shadow-[var(--shadow-floating)]')
    expect(panel).not.toHaveClass('shadow-2xl')
  })

  it('marks broad roles with only the shared quiet dot', () => {
    render(
      <AccessChipList
        entries={[
          { label: 'dbOwner', full: 'dbOwner @ app', group: 'database', dangerous: true },
        ]}
      />,
    )

    expect(screen.getByLabelText('Широкие полномочия')).toHaveClass('size-1.5', 'bg-danger')
    expect(screen.queryByText('Dangerous')).not.toBeInTheDocument()
  })
})
