import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { describe, expect, it } from 'vitest'
import { SearchInput } from './search-input'

function SearchInputHarness() {
  const [value, setValue] = useState('')
  return (
    <SearchInput
      value={value}
      onChange={setValue}
      ariaLabel="Поиск аккаунта"
    />
  )
}

describe('SearchInput', () => {
  it('shows one shared clear action only while the query is not empty', async () => {
    const user = userEvent.setup()
    render(<SearchInputHarness />)

    const input = screen.getByRole('textbox', { name: 'Поиск аккаунта' })
    expect(screen.queryByRole('button', { name: 'Очистить поиск' })).not.toBeInTheDocument()

    await user.type(input, 'test')
    expect(input).toHaveValue('test')

    const clear = screen.getByRole('button', { name: 'Очистить поиск' })
    expect(clear).toHaveClass('ui-control-feedback', 'grantor-touch-target')
    clear.focus()
    await user.keyboard('{Enter}')
    expect(input).toHaveValue('')
    expect(screen.queryByRole('button', { name: 'Очистить поиск' })).not.toBeInTheDocument()
  })

  it('keeps clear disabled with the search field', async () => {
    const user = userEvent.setup()
    let changes = 0
    render(<SearchInput value="test" onChange={() => changes++} disabled ariaLabel="Поиск" />)
    expect(screen.getByRole('textbox', { name: 'Поиск' })).toBeDisabled()
    const clear = screen.getByRole('button', { name: 'Очистить поиск' })
    expect(clear).toBeDisabled()
    await user.click(clear)
    expect(changes).toBe(0)
  })

  it('supports a compact shared toolbar presentation', () => {
    render(
      <SearchInput
        value=""
        onChange={() => undefined}
        ariaLabel="Компактный поиск"
        density="compact"
        className="w-72"
      />,
    )

    expect(screen.getByRole('textbox', { name: 'Компактный поиск' })).toHaveClass(
      'h-8',
      'text-xs',
    )
    expect(screen.getByRole('textbox', { name: 'Компактный поиск' }).parentElement).toHaveClass(
      'w-72',
    )
  })
})
