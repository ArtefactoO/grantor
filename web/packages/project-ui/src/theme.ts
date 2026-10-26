export interface Palette {
  id: 'signal' | 'cobalt' | 'orange'
  label: string
  swatch: string
}

export type ThemeMode = 'dark' | 'light'
export type ThemePreference = ThemeMode | 'system'

export const PALETTES: readonly Palette[] = [
  { id: 'signal', label: 'Монохромный сигнал', swatch: '#dce2e8' },
  { id: 'cobalt', label: 'Графит и кобальт', swatch: '#6392f7' },
  { id: 'orange', label: 'Углерод и сигнальный оранжевый', swatch: '#ee914e' },
]

export const DEFAULT_PALETTE: Palette['id'] = 'signal'

function paletteById(id: string | undefined): Palette['id'] {
  return PALETTES.some((palette) => palette.id === id)
    ? (id as Palette['id'])
    : DEFAULT_PALETTE
}

export function currentPalette(): Palette['id'] {
  return paletteById(document.documentElement.dataset.palette)
}

export function systemTheme(): ThemeMode {
  return typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-color-scheme: light)').matches
    ? 'light'
    : 'dark'
}

export function currentTheme(): ThemeMode {
  const value = document.documentElement.dataset.theme
  return value === 'light' || value === 'dark' ? value : systemTheme()
}

/** Persistence belongs to the host application, so packages never share choices by accident. */
export function createThemeController({
  paletteStorageKey,
  themeStorageKey,
}: {
  paletteStorageKey: string
  themeStorageKey: string
}) {
  return {
    applyPalette(id: string): void {
      const palette = paletteById(id)
      if (palette === DEFAULT_PALETTE) delete document.documentElement.dataset.palette
      else document.documentElement.dataset.palette = palette
      try {
        localStorage.setItem(paletteStorageKey, palette)
      } catch {
        // An unavailable localStorage only makes the choice session-scoped.
      }
    },
    applyTheme(mode: ThemePreference): void {
      document.documentElement.dataset.theme = mode === 'system' ? systemTheme() : mode
      try {
        localStorage.setItem(themeStorageKey, mode)
      } catch {
        // An unavailable localStorage only makes the choice session-scoped.
      }
    },
  }
}
