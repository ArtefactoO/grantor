import { useState } from 'react'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { Combobox } from './combobox'
import type { ComboboxOption } from './combobox'

const options: ComboboxOption[] = [
  { value: 'pg-main', label: 'Main PostgreSQL', description: 'production' },
  { value: 'kafka-stage', label: 'Stage Kafka', description: 'staging' },
  { value: 'redis-dev', label: 'Dev Redis', description: 'development' },
]

function ControlledCombobox() {
  const [value, setValue] = useState<string>()
  return (
    <Combobox
      value={value}
      options={options}
      onValueChange={setValue}
      label="Подключение"
      searchLabel="Поиск подключения"
      placeholder="Выберите подключение…"
    />
  )
}

describe('Combobox', () => {
  it('provides accessible names for the trigger, search input and listbox', async () => {
    const user = userEvent.setup()
    render(<ControlledCombobox />)

    const trigger = screen.getByRole('combobox', { name: 'Подключение' })
    expect(trigger).toHaveAttribute('aria-expanded', 'false')
    await user.click(trigger)

    expect(screen.getByRole('combobox', { name: 'Поиск подключения' })).toHaveFocus()
    const search = screen.getByRole('combobox', { name: 'Поиск подключения' })
    const listbox = screen.getByRole('listbox', { name: 'Подключение' })
    expect(listbox).toBeInTheDocument()
    const content = document.querySelector('[data-slot="combobox-content"]')
    expect(content).toHaveClass('ui-popover-surface')
    expect(content).toHaveClass('shadow-[var(--shadow-floating)]')
    expect(content).not.toHaveClass('shadow-2xl')
    expect(document.getElementById(search.getAttribute('aria-controls') ?? '')).toBe(listbox)
    expect(document.getElementById(trigger.getAttribute('aria-controls') ?? '')).not.toBeNull()

    await user.hover(screen.getByRole('option', { name: /Main PostgreSQL/ }))
    expect(document.querySelector('[data-slot="combobox-content"]')).toBe(content)
    expect(content).toHaveClass('ui-popover-surface')
    expect(search).toHaveFocus()
  })

  it('filters options from the search input', async () => {
    const user = userEvent.setup()
    render(<ControlledCombobox />)

    await user.click(screen.getByRole('combobox', { name: 'Подключение' }))
    await user.type(screen.getByRole('combobox', { name: 'Поиск подключения' }), 'kafka')

    expect(screen.getByRole('option', { name: /Stage Kafka/ })).toBeInTheDocument()
    expect(screen.queryByRole('option', { name: /Main PostgreSQL/ })).not.toBeInTheDocument()
  })

  it('selects the filtered option with the keyboard', async () => {
    const user = userEvent.setup()
    render(<ControlledCombobox />)

    await user.click(screen.getByRole('combobox', { name: 'Подключение' }))
    const search = screen.getByRole('combobox', { name: 'Поиск подключения' })
    await user.type(search, 'redis')
    await user.keyboard('{ArrowDown}{Enter}')

    expect(screen.queryByRole('listbox')).not.toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: 'Подключение' })).toHaveTextContent(
      'Dev Redis',
    )
  })

  it('renders a deterministic no-results state', async () => {
    const user = userEvent.setup()
    render(<ControlledCombobox />)

    await user.click(screen.getByRole('combobox', { name: 'Подключение' }))
    await user.type(
      screen.getByRole('combobox', { name: 'Поиск подключения' }),
      'missing-cluster',
    )

    expect(screen.getByText('Ничего не найдено')).toBeInTheDocument()
  })

  it('reflects controlled value changes and reports selection', async () => {
    const user = userEvent.setup()
    const onValueChange = vi.fn()
    const { rerender } = render(
      <Combobox
        value="pg-main"
        options={options}
        onValueChange={onValueChange}
        label="Подключение"
      />,
    )

    expect(screen.getByRole('combobox', { name: 'Подключение' })).toHaveTextContent(
      'Main PostgreSQL',
    )
    rerender(
      <Combobox
        value="kafka-stage"
        options={options}
        onValueChange={onValueChange}
        label="Подключение"
      />,
    )
    expect(screen.getByRole('combobox', { name: 'Подключение' })).toHaveTextContent(
      'Stage Kafka',
    )

    await user.click(screen.getByRole('combobox', { name: 'Подключение' }))
    await user.click(screen.getByRole('option', { name: /Dev Redis/ }))
    expect(onValueChange).toHaveBeenCalledWith('redis-dev')
  })
})
