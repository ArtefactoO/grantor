import { useLayoutEffect, useState } from 'react'
import type { RefObject } from 'react'

/** The panel starts below page chrome, not at the viewport's top edge. */
export function inspectorViewportHeight(
  panelTop: number,
  viewportBottom: number,
  scrollportBottom: number,
  bottomGap: number,
  viewportTop = 0,
): number {
  return Math.max(0, Math.floor(
    Math.min(viewportBottom, scrollportBottom) - Math.max(viewportTop, panelTop) - bottomGap,
  ))
}

/** Bound a sticky inspector to the visible part of its containing scrollport. */
export function useInspectorViewportHeight(
  panelRef: RefObject<HTMLElement | null>,
  enabled: boolean,
): number | undefined {
  const [height, setHeight] = useState<number>()

  useLayoutEffect(() => {
    const panel = panelRef.current
    if (!enabled || panel === null) {
      setHeight(undefined)
      return
    }

    const ancestors: HTMLElement[] = []
    const scrollports: HTMLElement[] = []
    for (let parent = panel.parentElement; parent !== null; parent = parent.parentElement) {
      ancestors.push(parent)
      if (/^(auto|scroll|overlay)$/.test(window.getComputedStyle(parent).overflowY)) {
        scrollports.push(parent)
      }
    }
    const viewport = window.visualViewport
    let frame: number | null = null
    const measure = () => {
      frame = null
      const viewportBottom = viewport === null || viewport === undefined
        ? window.innerHeight
        : viewport.offsetTop + viewport.height
      const scrollportBottom = scrollports.reduce((bottom, scrollport) => {
        const bounds = scrollport.getBoundingClientRect()
        return Math.min(bottom, bounds.bottom)
      }, viewportBottom)
      const bottomGap = Number.parseFloat(window.getComputedStyle(document.documentElement).fontSize) || 16
      setHeight(inspectorViewportHeight(
        panel.getBoundingClientRect().top,
        viewportBottom,
        scrollportBottom,
        bottomGap,
        viewport?.offsetTop ?? 0,
      ))
    }
    const schedule = () => {
      if (frame === null) frame = window.requestAnimationFrame(measure)
    }

    measure()
    // Header/filter wrapping can move the panel even without a window resize.
    // Observe ancestors, but not the panel: its own max-height is our output.
    const observer = new ResizeObserver(schedule)
    ancestors.forEach((ancestor) => observer.observe(ancestor))
    scrollports.forEach((scrollport) => scrollport.addEventListener('scroll', schedule, { passive: true }))
    window.addEventListener('resize', schedule)
    window.addEventListener('scroll', schedule, { passive: true })
    viewport?.addEventListener('resize', schedule)
    viewport?.addEventListener('scroll', schedule)

    return () => {
      if (frame !== null) window.cancelAnimationFrame(frame)
      observer.disconnect()
      scrollports.forEach((scrollport) => scrollport.removeEventListener('scroll', schedule))
      window.removeEventListener('resize', schedule)
      window.removeEventListener('scroll', schedule)
      viewport?.removeEventListener('resize', schedule)
      viewport?.removeEventListener('scroll', schedule)
    }
  }, [enabled, panelRef])

  return enabled ? height : undefined
}
