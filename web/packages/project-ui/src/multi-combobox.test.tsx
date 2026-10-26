import { useState } from 'react'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { MultiCombobox } from './multi-combobox'

function Example() {
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set())
  return (
    <MultiCombobox
      label="Роли подключения"
      selected={selected}
      onChange={setSelected}
      options={[
        { value: 'read', label: 'readAnyDatabase' },
        { value: 'admin', label: 'dbAdminAnyDatabase' },
      ]}
    />
  )
}

describe('MultiCombobox', () => {
  it('keeps the list open and selects several independent values', async () => {
    const user = userEvent.setup()
    render(<Example />)

    await user.click(screen.getAllByRole('combobox', { name: 'Роли подключения' })[0]!)
    expect(document.querySelector('[data-slot="multi-combobox-content"]')).toHaveClass(
      'ui-popover-surface',
    )
    await user.click(screen.getByRole('checkbox', { name: 'readAnyDatabase' }))
    await user.click(screen.getByRole('checkbox', { name: 'dbAdminAnyDatabase' }))

    expect(screen.getByRole('checkbox', { name: 'readAnyDatabase' })).toBeChecked()
    expect(screen.getByRole('checkbox', { name: 'dbAdminAnyDatabase' })).toBeChecked()
    expect(screen.getAllByRole('combobox', { name: 'Роли подключения' })[0]).toHaveTextContent('All')
  })
})
