import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
  applyPalette,
  applyTheme,
  currentPalette,
  currentTheme,
  PALETTES,
  systemTheme,
} from './themes'

describe('theme contract', () => {
  beforeEach(() => {
    localStorage.clear()
    delete document.documentElement.dataset.palette
    delete document.documentElement.dataset.theme
    vi.stubGlobal('matchMedia', vi.fn().mockReturnValue({ matches: true }))
  })

  it('exposes only the three approved palettes', () => {
    expect(PALETTES.map(({ id, label }) => ({ id, label }))).toEqual([
      { id: 'signal', label: 'Монохромный сигнал' },
      { id: 'cobalt', label: 'Графит и кобальт' },
      { id: 'orange', label: 'Углерод и сигнальный оранжевый' },
    ])
  })

  it('uses system mode by default and persists an explicit mode', () => {
    expect(systemTheme()).toBe('light')
    expect(currentTheme()).toBe('light')
    applyTheme('dark')
    expect(document.documentElement.dataset.theme).toBe('dark')
    expect(localStorage.getItem('grantor-theme')).toBe('dark')
  })

  it('normalizes unsupported palettes to Monochrome Signal', () => {
    applyPalette('cobalt')
    expect(currentPalette()).toBe('cobalt')
    applyPalette('old-copper')
    expect(currentPalette()).toBe('signal')
    expect(document.documentElement.dataset.palette).toBeUndefined()
    expect(localStorage.getItem('grantor-palette')).toBe('signal')
  })
})
