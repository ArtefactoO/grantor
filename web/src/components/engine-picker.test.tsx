import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { EnginePicker } from './engine-picker'

describe('EnginePicker', () => {
  it('shows brand icons in the selected value and every option', async () => {
    const user = userEvent.setup()
    const onValueChange = vi.fn()
    render(
      <EnginePicker
        value="postgres"
        options={[
          { value: 'postgres', label: 'PostgreSQL' },
          { value: 'mongodb', label: 'MongoDB' },
        ]}
        onValueChange={onValueChange}
      />,
    )

    expect(screen.getByRole('combobox', { name: 'Движок' }).querySelector('[data-engine-brand="postgres"]')).not.toBeNull()
    await user.click(screen.getByRole('combobox', { name: 'Движок' }))
    expect(screen.getByRole('option', { name: 'PostgreSQL' }).querySelector('[data-engine-brand="postgres"]')).not.toBeNull()
    expect(screen.getByRole('option', { name: 'MongoDB' }).querySelector('[data-engine-brand="mongodb"]')).not.toBeNull()
  })
})
