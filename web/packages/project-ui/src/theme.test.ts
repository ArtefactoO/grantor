import { beforeEach, describe, expect, it } from 'vitest'
import { createThemeController } from './theme'

describe('application-owned theme persistence', () => {
  beforeEach(() => {
    localStorage.clear()
    delete document.documentElement.dataset.palette
    delete document.documentElement.dataset.theme
  })

  it('stores choices only in the namespace supplied by the host', () => {
    const theme = createThemeController({
      paletteStorageKey: 'fixture-palette',
      themeStorageKey: 'fixture-theme',
    })
    theme.applyPalette('orange')
    theme.applyTheme('light')

    expect(document.documentElement.dataset.palette).toBe('orange')
    expect(document.documentElement.dataset.theme).toBe('light')
    expect(localStorage.getItem('fixture-palette')).toBe('orange')
    expect(localStorage.getItem('fixture-theme')).toBe('light')
    expect(localStorage.length).toBe(2)
  })
})
