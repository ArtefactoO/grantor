import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../../auth/AuthProvider', () => ({
  useAuth: () => ({ email: 'operator@example.test', role: 'operator' }),
}))

import { Topbar } from './Topbar'

describe('Topbar theme controls', () => {
  beforeEach(() => {
    localStorage.clear()
    document.documentElement.dataset.theme = 'dark'
    delete document.documentElement.dataset.palette
  })

  it('keeps palette and explicit mode as separate whole-app controls', async () => {
    const user = userEvent.setup()
    render(<Topbar mobileNavigationOpen={false} onOpenMobileNavigation={vi.fn()} />)

    await user.click(screen.getByRole('button', { name: 'Включить светлую тему' }))
    expect(document.documentElement.dataset.theme).toBe('light')
    expect(localStorage.getItem('grantor-theme')).toBe('light')

    await user.click(screen.getByRole('button', { name: 'Выбрать цветовую систему' }))
    expect(screen.getAllByRole('menuitemradio')).toHaveLength(3)
    await user.click(screen.getByRole('menuitemradio', { name: /Cobalt/ }))
    expect(document.documentElement.dataset.palette).toBe('cobalt')
    expect(document.documentElement.dataset.theme).toBe('light')
  })
})
