import { createThemeController } from '@project/ui/theme'

export { PALETTES, DEFAULT_PALETTE, currentPalette, currentTheme, systemTheme } from '@project/ui/theme'
export type { Palette, ThemeMode, ThemePreference } from '@project/ui/theme'
import type { ThemePreference } from '@project/ui/theme'

export const PALETTE_STORAGE_KEY = 'grantor-palette'
export const THEME_STORAGE_KEY = 'grantor-theme'

export function currentThemePreference(): ThemePreference {
  try {
    const value = localStorage.getItem(THEME_STORAGE_KEY)
    if (value === 'light' || value === 'dark') return value
  } catch {
    // Storage availability does not prevent following the system theme.
  }
  return 'system'
}

export const { applyPalette, applyTheme } = createThemeController({
  paletteStorageKey: PALETTE_STORAGE_KEY,
  themeStorageKey: THEME_STORAGE_KEY,
})
