import { act, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ThemePicker } from './ThemePicker'

describe('palette menu keyboard interaction', () => {
  beforeEach(() => {
    vi.unstubAllGlobals()
    localStorage.clear()
    delete document.documentElement.dataset.palette
  })

  it('persists System independently of the palette, follows OS changes and stops after explicit selection', async () => {
    const media = new EventTarget() as EventTarget & { matches: boolean }
    media.matches = false
    vi.stubGlobal('matchMedia', vi.fn(() => media))
    const user = userEvent.setup()
    const view = render(<ThemePicker />)
    await user.click(screen.getByRole('button', { name: 'Выбрать цветовую систему' }))
    expect(screen.getByRole('menuitemcheckbox', { name: 'System' })).toHaveAttribute('aria-checked', 'true')
    await user.click(screen.getByRole('menuitemradio', { name: 'Orange' }))
    expect(localStorage.getItem('grantor-palette')).toBe('orange')
    expect(localStorage.getItem('grantor-theme')).toBe('system')
    act(() => { media.matches = true; media.dispatchEvent(new Event('change')) })
    expect(document.documentElement.dataset.theme).toBe('light')
    await user.click(screen.getByRole('button', { name: 'Включить тёмную тему' }))
    expect(localStorage.getItem('grantor-theme')).toBe('dark')
    act(() => { media.matches = false; media.dispatchEvent(new Event('change')) })
    expect(document.documentElement.dataset.theme).toBe('dark')
    await user.click(screen.getByRole('button', { name: 'Выбрать цветовую систему' }))
    await user.click(screen.getByRole('menuitemcheckbox', { name: 'System' }))
    expect(localStorage.getItem('grantor-theme')).toBe('system')
    expect(localStorage.getItem('grantor-palette')).toBe('orange')
    view.unmount()
    act(() => { media.matches = true; media.dispatchEvent(new Event('change')) })
    render(<ThemePicker />)
    expect(document.documentElement.dataset.theme).toBe('light')
  })

  it('opens with Enter, navigates options and returns focus after selection', async () => {
    const user = userEvent.setup()
    render(<ThemePicker />)
    const trigger = screen.getByRole('button', { name: 'Выбрать цветовую систему' })
    trigger.focus()
    await user.keyboard('{Enter}')
    expect(screen.getByRole('menuitemradio', { name: 'Mono' })).toHaveFocus()
    await user.keyboard('{ArrowDown}')
    expect(screen.getByRole('menuitemradio', { name: 'Cobalt' })).toHaveFocus()
    await user.keyboard('{Enter}')
    expect(document.documentElement.dataset.palette).toBe('cobalt')
    expect(screen.queryByRole('menu')).not.toBeInTheDocument()
    expect(trigger).toHaveFocus()
    expect(trigger).toHaveAttribute('aria-expanded', 'false')
  })

  it('supports last-item opening, wraparound, Home, End and Escape', async () => {
    const user = userEvent.setup()
    render(<ThemePicker />)
    const trigger = screen.getByRole('button', { name: 'Выбрать цветовую систему' })
    trigger.focus()
    await user.keyboard('{ArrowUp}')
    const last = screen.getByRole('menuitemcheckbox', { name: 'System' })
    expect(last).toHaveFocus()
    await user.keyboard('{ArrowDown}')
    const first = screen.getByRole('menuitemradio', { name: 'Mono' })
    expect(first).toHaveFocus()
    await user.keyboard('{End}')
    expect(last).toHaveFocus()
    await user.keyboard('{Home}')
    expect(first).toHaveFocus()
    await user.keyboard('{Escape}')
    expect(screen.queryByRole('menu')).not.toBeInTheDocument()
    expect(trigger).toHaveFocus()
  })

  it('closes on Tab and continues the surrounding tab order', async () => {
    const user = userEvent.setup()
    render(<><button>До палитры</button><ThemePicker /><button>После палитры</button></>)
    screen.getByRole('button', { name: 'Выбрать цветовую систему' }).focus()
    await user.keyboard(' ')
    expect(screen.getByRole('menuitemradio', { name: 'Mono' })).toHaveFocus()
    await user.tab()
    expect(screen.queryByRole('menu')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Включить светлую тему' })).toHaveFocus()
  })
})
