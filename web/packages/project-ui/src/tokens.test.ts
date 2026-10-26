// Vitest исполняется в Node; production bundle этот test-only import не видит.
// @ts-expect-error tsconfig web намеренно не включает глобальные Node types.
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { MOTION_DURATION } from './motion'

const tokensCss = readFileSync('packages/project-ui/src/tokens.css', 'utf8')
const baseCss = readFileSync('packages/project-ui/src/styles.css', 'utf8')

const THEME_SELECTORS = [
  ':root',
  ":root[data-theme='light']",
  ":root[data-palette='cobalt']",
  ":root[data-palette='cobalt'][data-theme='light']",
  ":root[data-palette='orange']",
  ":root[data-palette='orange'][data-theme='light']",
] as const

const REQUIRED_TOKENS = [
  'bg', 'panel', 'panel2', 'hover', 'selected', 'line', 'line-strong',
  'text', 'muted', 'faint', 'accent', 'accent-text', 'accent-hover', 'accent-ink', 'focus',
  'ok', 'warn', 'danger', 'unmg', 'shadow-color', 'topline',
] as const

const CONTENT_SURFACES = ['bg', 'panel', 'panel2', 'hover', 'selected'] as const
const STATUS_TOKENS = ['ok', 'warn', 'danger', 'unmg'] as const

type Rgb = readonly [number, number, number]

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function declarations(selector: string): Map<string, string> {
  const match = tokensCss.match(new RegExp(`${escapeRegExp(selector)}\\s*\\{([^}]*)\\}`))
  if (match === null) {
    throw new Error(
      `CSS selector not found: ${selector}; source starts with ${JSON.stringify(tokensCss.slice(0, 120))}`,
    )
  }
  return new Map(
    [...match[1].matchAll(/--([a-z0-9-]+):\s*(#[0-9a-f]{6});/gi)].map((item) => [
      item[1],
      item[2].toLowerCase(),
    ]),
  )
}

function rgb(hex: string): Rgb {
  return [
    Number.parseInt(hex.slice(1, 3), 16),
    Number.parseInt(hex.slice(3, 5), 16),
    Number.parseInt(hex.slice(5, 7), 16),
  ]
}

function luminance(hex: string): number {
  const linear = rgb(hex).map((channel) => {
    const value = channel / 255
    return value <= 0.04045
      ? value / 12.92
      : ((value + 0.055) / 1.055) ** 2.4
  })
  return linear[0] * 0.2126 + linear[1] * 0.7152 + linear[2] * 0.0722
}

function contrast(foreground: string, background: string): number {
  const values = [luminance(foreground), luminance(background)].sort(
    (left, right) => right - left,
  )
  return (values[0] + 0.05) / (values[1] + 0.05)
}

describe('theme text contrast contract', () => {
  it.each(THEME_SELECTORS)('%s keeps assigned status readable on selected rows', (selector) => {
    const values = declarations(selector)
    const foreground = values.get('ok')!
    const ink = rgb(foreground)
    for (const surface of CONTENT_SURFACES) {
      const base = rgb(values.get(surface)!)
      const fill = '#' + base.map((channel, index) => Math.round(channel * 0.88 + ink[index] * 0.12)
        .toString(16).padStart(2, '0')).join('')
      expect(contrast(foreground, fill), `${selector} status on ${surface}`).toBeGreaterThanOrEqual(4.5)
    }
  })

  it.each(THEME_SELECTORS)('%s keeps accent text readable on content and tinted surfaces', (selector) => {
    const values = declarations(selector)
    const softOpacity = Number(tokensCss.match(/--accent-soft:\s*color-mix\(in srgb, var\(--accent\) (\d+)%/)?.[1]) / 100
    expect(softOpacity).toBeGreaterThan(0)
    expect(softOpacity).toBeLessThan(1)
    for (const surface of CONTENT_SURFACES) {
      const background = values.get(surface)!
      const accent = rgb(values.get('accent')!)
      const base = rgb(background)
      const tinted = '#' + base.map((channel, index) => Math.round(
        channel * (1 - softOpacity) + accent[index] * softOpacity,
      ).toString(16).padStart(2, '0')).join('')
      for (const fill of [background, tinted]) {
        expect(contrast(values.get('accent-text')!, fill), `${selector} accent text on ${surface}`).toBeGreaterThanOrEqual(4.5)
      }
    }
  })

  it.each(THEME_SELECTORS)('%s defines the complete semantic contract', (selector) => {
    const values = declarations(selector)
    for (const token of REQUIRED_TOKENS) {
      expect(values.get(token), `${selector} must define --${token}`).toBeDefined()
    }
  })

  it.each(THEME_SELECTORS)('%s keeps normal text at WCAG AA', (selector) => {
    const values = declarations(selector)

    for (const token of ['text', 'muted', 'faint']) {
      const foreground = values.get(token)
      expect(foreground, `${selector} must define --${token} as a hex value`).toBeDefined()

      for (const surface of CONTENT_SURFACES) {
        const background = values.get(surface)
        expect(background, `${selector} must define --${surface} as a hex value`).toBeDefined()
        expect(
          contrast(foreground as string, background as string),
          `${selector} --${token} on --${surface}`,
        ).toBeGreaterThanOrEqual(4.5)
      }
    }

    for (const surface of CONTENT_SURFACES) {
      expect(
        contrast(values.get('text') as string, values.get(surface) as string),
        `${selector} --text on --${surface} should remain soft enough for prolonged use`,
      ).toBeLessThanOrEqual(10.5)
    }

    for (const actionSurface of ['accent', 'accent-hover']) {
      expect(
        contrast(values.get('accent-ink') as string, values.get(actionSurface) as string),
        `${selector} --accent-ink on --${actionSurface}`,
      ).toBeGreaterThanOrEqual(4.5)
    }
  })

  it.each(THEME_SELECTORS)('%s keeps actions and statuses distinguishable', (selector) => {
    const values = declarations(selector)

    for (const token of STATUS_TOKENS) {
      for (const surface of CONTENT_SURFACES) {
        expect(
          contrast(values.get(token) as string, values.get(surface) as string),
          `${selector} --${token} on --${surface}`,
        ).toBeGreaterThanOrEqual(4.5)
      }
    }

    for (const surface of CONTENT_SURFACES) {
      expect(
        contrast(values.get('focus') as string, values.get(surface) as string),
        `${selector} --focus on --${surface}`,
      ).toBeGreaterThanOrEqual(3)
    }
  })

  it.each(THEME_SELECTORS)('%s avoids absolute black and white tokens', (selector) => {
    const values = declarations(selector)
    for (const token of REQUIRED_TOKENS) {
      expect(values.get(token)).not.toBe('#000000')
      expect(values.get(token)).not.toBe('#ffffff')
    }
  })
})

const DARK_SELECTORS = THEME_SELECTORS.filter((s) => !s.includes("data-theme='light'"))
const LIGHT_SELECTORS = THEME_SELECTORS.filter((s) => s.includes("data-theme='light'"))

describe('surface divider contract', () => {
  // Линия светлее заливки воспринимается как источник света, а не как край:
  // на периметре панели во весь экран это читалось обводкой вокруг
  // пол-страницы. На тёмных палитрах разделитель держится у заливки.
  it.each(DARK_SELECTORS)('%s keeps the divider close to the panel fill', (selector) => {
    const values = declarations(selector)
    expect(
      contrast(values.get('line') as string, values.get('panel') as string),
      `${selector} --line against --panel`,
    ).toBeLessThanOrEqual(1.25)
  })

  // На светлых палитрах тот же перепад работает как шов, а не как свечение,
  // поэтому там достаточно требовать, чтобы линия была темнее заливки.
  it.each(LIGHT_SELECTORS)('%s draws the divider darker than the panel', (selector) => {
    const values = declarations(selector)
    expect(
      luminance(values.get('line') as string),
      `${selector} --line against --panel`,
    ).toBeLessThan(luminance(values.get('panel') as string))
  })

  // Спокойная линия покоя имеет смысл, только пока ховер и выделение остаются
  // заметным шагом от неё: иначе пропадает обратная связь на строках таблиц.
  it.each(THEME_SELECTORS)('%s keeps the strong divider a visible step up', (selector) => {
    const values = declarations(selector)
    expect(
      contrast(values.get('line-strong') as string, values.get('line') as string),
      `${selector} --line-strong against --line`,
    ).toBeGreaterThanOrEqual(1.2)
  })
})

describe('shared motion token contract', () => {
  it('uses the same short durations in CSS and JS', () => {
    for (const kind of ['fast', 'state', 'feedback'] as const) {
      const match = tokensCss.match(new RegExp(`--motion-${kind}:\\s*(\\d+)ms`))
      expect(Number(match?.[1])).toBeCloseTo(MOTION_DURATION[kind] * 1_000)
    }
  })

  it('keeps control feedback free from theme delay or spatial movement', () => {
    const feedbackRule = baseCss.match(/\.ui-control-feedback,([^{}]*)\{([^}]*)\}/)?.[2]
    expect(feedbackRule).toBeDefined()
    expect(feedbackRule).toContain('transition-delay: 0ms')
    expect(feedbackRule).not.toMatch(/(?:transform|translate|scale|rotate|--motion-theme)/)
    expect(baseCss).not.toMatch(/transition-delay:\s*[1-9]/)
    expect(baseCss).not.toContain('--motion-theme')
  })

  it('preserves reduced-motion colour feedback instead of globally erasing state changes', () => {
    const reducedRule = baseCss.slice(baseCss.indexOf('@media (prefers-reduced-motion: reduce)'))
    expect(reducedRule).toContain('.ui-sync-glyph')
    expect(reducedRule).toContain('animation: none')
    expect(reducedRule).not.toContain('0.01ms')
    expect(reducedRule).not.toMatch(/\*,|\*::before|transition-duration/)
  })
})
