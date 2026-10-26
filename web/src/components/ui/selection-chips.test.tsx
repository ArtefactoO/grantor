import { useState } from 'react'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { CheckboxChipGroup, SegmentedFilter, SelectionSelect } from './selection-chips'

const OPTIONS = [
  { value: 'managed', label: 'Managed' },
  { value: 'unmanaged', label: 'Unmanaged' },
] as const

function SegmentedHarness() {
  const [value, setValue] = useState<'managed' | 'unmanaged'>('managed')
  return (
    <SegmentedFilter
      label="Ownership"
      value={value}
      options={OPTIONS}
      onChange={setValue}
    />
  )
}

function CheckboxHarness({
  minSelected = 0,
  allSelectedFallback,
}: {
  minSelected?: number
  allSelectedFallback?: ReadonlySet<'managed' | 'unmanaged'>
}) {
  const [selected, setSelected] = useState<ReadonlySet<'managed' | 'unmanaged'>>(
    new Set(['managed']),
  )
  return (
    <CheckboxChipGroup
      label="Секции"
      options={OPTIONS}
      selected={selected}
      onChange={setSelected}
      minSelected={minSelected}
      allSelectedFallback={allSelectedFallback}
    />
  )
}

describe('selection chips', () => {
  it('uses the shared quiet facet popover instead of a native select', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(
      <SelectionSelect
        label="Environment"
        value="all"
        inactiveValue="all"
        options={[
          { value: 'all', label: 'All environments', count: 2 },
          { value: 'test', label: 'TEST', count: 1 },
        ]}
        onChange={onChange}
      />,
    )

    const trigger = screen.getByRole('combobox', { name: 'Environment' })
    expect(trigger).toHaveClass('ui-facet-select', 'ui-control-feedback', 'grantor-touch-target', 'rounded-md')
    expect(trigger.tagName).toBe('BUTTON')
    expect(document.querySelector('select')).not.toBeInTheDocument()

    await user.click(trigger)
    expect(screen.getByRole('listbox', { name: 'Environment' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'All environments 2' })).toHaveAttribute(
      'aria-selected',
      'true',
    )
    await user.click(screen.getByRole('option', { name: 'TEST 1' }))
    expect(onChange).toHaveBeenCalledWith('test')
  })

  it('navigates facet options by keyboard and restores trigger focus on Escape', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<SelectionSelect
      label="Environment"
      value="all"
      inactiveValue="all"
      options={[
        { value: 'all', label: 'All environments' },
        { value: 'test', label: 'TEST' },
      ]}
      onChange={onChange}
    />)
    const trigger = screen.getByRole('combobox', { name: 'Environment' })
    trigger.focus()
    await user.keyboard('{Enter}')
    const current = await screen.findByRole('option', { name: 'All environments' })
    await vi.waitFor(() => expect(current).toHaveFocus())
    await user.keyboard('{End}')
    expect(screen.getByRole('option', { name: 'TEST' })).toHaveFocus()
    await user.keyboard('{Escape}')
    await vi.waitFor(() => expect(trigger).toHaveFocus())
    expect(onChange).not.toHaveBeenCalled()
  })

  it('keeps one segmented value selected and switches directly to another', async () => {
    const user = userEvent.setup()
    render(<SegmentedHarness />)

    const managed = screen.getByRole('radio', { name: 'Managed' })
    expect(managed).toHaveClass('ui-control-feedback', 'grantor-touch-target')
    await user.click(managed)
    expect(managed).toHaveAttribute('aria-checked', 'true')

    await user.click(screen.getByRole('radio', { name: 'Unmanaged' }))
    expect(managed).toHaveAttribute('aria-checked', 'false')
    expect(screen.getByRole('radio', { name: 'Unmanaged' })).toHaveAttribute(
      'aria-checked',
      'true',
    )
  })

  it('supports shared shortcut chips when no target is currently active', () => {
    render(
      <SegmentedFilter
        label="Signals"
        value={undefined}
        options={OPTIONS}
        onChange={() => undefined}
      />,
    )

    expect(screen.getByRole('radio', { name: 'Managed' })).toHaveAttribute('aria-checked', 'false')
    expect(screen.getByRole('radio', { name: 'Unmanaged' })).toHaveAttribute('aria-checked', 'false')
  })

  it('shows the master mixed state and selects all options', async () => {
    const user = userEvent.setup()
    render(<CheckboxHarness />)

    const all = screen.getByRole('checkbox', { name: 'All' })
    expect(all).toHaveAttribute('aria-checked', 'mixed')
    await user.click(all)

    expect(all).toHaveAttribute('aria-checked', 'true')
    expect(screen.getByRole('checkbox', { name: 'Managed' })).toHaveAttribute('aria-checked', 'true')
    expect(screen.getByRole('checkbox', { name: 'Unmanaged' })).toHaveAttribute('aria-checked', 'true')
  })

  it('collapses inactive checkbox indicators and reveals them on selection', async () => {
    const user = userEvent.setup()
    const { container } = render(<CheckboxHarness />)

    const indicators = () => container.querySelectorAll('[data-slot="selection-indicator"]')
    expect(indicators()).toHaveLength(3)
    expect(indicators()[0]).toHaveAttribute('data-active', 'true')
    expect(indicators()[1]).toHaveAttribute('data-active', 'true')
    expect(indicators()[2]).toHaveAttribute('data-active', 'false')
    expect(indicators()[2]).toHaveClass('w-0', 'mr-0', 'opacity-0')

    await user.click(screen.getByRole('checkbox', { name: 'Managed' }))
    expect(indicators()).toHaveLength(3)
    expect(indicators()[0]).toHaveAttribute('data-active', 'false')
    expect(indicators()[1]).toHaveAttribute('data-active', 'false')
    expect(indicators()[2]).toHaveAttribute('data-active', 'false')
  })

  it('allows the final option to be removed by default', async () => {
    const user = userEvent.setup()
    render(<CheckboxHarness />)

    const managed = screen.getByRole('checkbox', { name: 'Managed' })
    await user.click(managed)
    expect(managed).toHaveAttribute('aria-checked', 'false')
    expect(screen.getByRole('checkbox', { name: 'All' })).toHaveAttribute('aria-checked', 'false')
  })

  it('clears all options when the selected master is clicked again', async () => {
    const user = userEvent.setup()
    render(<CheckboxHarness />)

    const all = screen.getByRole('checkbox', { name: 'All' })
    await user.click(all)
    expect(all).toHaveAttribute('aria-checked', 'true')

    await user.click(all)
    expect(all).toHaveAttribute('aria-checked', 'false')
    expect(screen.getByRole('checkbox', { name: 'Managed' })).toHaveAttribute('aria-checked', 'false')
    expect(screen.getByRole('checkbox', { name: 'Unmanaged' })).toHaveAttribute('aria-checked', 'false')
  })
})
