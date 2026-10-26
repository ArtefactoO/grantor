import { describe, expect, it } from 'vitest'
import {
  motionTransition,
  MOTION_DURATION,
  MOTION_TRANSITION,
  MOTION_VARIANTS,
} from './motion'

describe('shared motion system', () => {
  it('keeps interface feedback immediate and compact', () => {
    for (const duration of Object.values(MOTION_DURATION)) {
      expect(duration).toBeGreaterThanOrEqual(0.09)
      expect(duration).toBeLessThanOrEqual(0.15)
    }
    expect(MOTION_TRANSITION.panel.duration).toBe(MOTION_DURATION.panel)
    expect(MOTION_TRANSITION.feedback.duration).toBe(MOTION_DURATION.feedback)
  })

  it('reveals final geometry immediately and changes only opacity', () => {
    for (const variants of Object.values(MOTION_VARIANTS)) {
      expect(variants.visible.opacity).toBe(1)
      expect(variants.hidden.opacity).toBe(0)
      expect(variants.exit.opacity).toBe(0)
      for (const state of Object.values(variants)) {
        expect(Object.keys(state)).toEqual(['opacity'])
      }
    }
  })

  it('makes reduced-motion reveals instant without changing normal feedback', () => {
    for (const [kind, transition] of Object.entries(MOTION_TRANSITION)) {
      if (kind === 'operationProgress') continue
      const name = kind as Parameters<typeof motionTransition>[0]
      expect(motionTransition(name, true).duration).toBe(0)
      expect(motionTransition(name, false)).toBe(transition)
      expect(motionTransition(name, null)).toBe(transition)
    }
  })
})
