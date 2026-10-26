import { describe, expect, it } from 'vitest'
import { inspectorViewportHeight } from './use-inspector-viewport-height'

describe('inspectorViewportHeight', () => {
  it.each([
    { title: 'excludes the connection header and filters', top: 320, viewport: 900, scrollport: 900, gap: 16, expected: 564 },
    { title: 'grows after the inspector sticks near the top', top: 72, viewport: 900, scrollport: 900, gap: 16, expected: 812 },
    { title: 'respects a smaller containing scrollport', top: 320, viewport: 900, scrollport: 760, gap: 16, expected: 424 },
    { title: 'respects a reduced visual viewport', top: 320, viewport: 650, scrollport: 900, gap: 16, expected: 314 },
    { title: 'uses the configured bottom gutter', top: 320, viewport: 900, scrollport: 900, gap: 24, expected: 556 },
    { title: 'never creates negative heights below the viewport', top: 920, viewport: 900, scrollport: 900, gap: 16, expected: 0 },
    { title: 'does not expand beyond the viewport for an offscreen top', top: -20, viewport: 900, scrollport: 900, gap: 16, expected: 884 },
    { title: 'rounds down fractional device-pixel bounds', top: 320.75, viewport: 900, scrollport: 900, gap: 16, expected: 563 },
  ])('$title', ({ top, viewport, scrollport, gap, expected }) => {
    expect(inspectorViewportHeight(top, viewport, scrollport, gap)).toBe(expected)
  })

  it('uses only the visible area when a zoomed viewport is panned', () => {
    expect(inspectorViewportHeight(72, 900, 900, 16, 300)).toBe(584)
  })
})
