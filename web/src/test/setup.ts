import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach, vi } from 'vitest'

class ResizeObserverMock implements ResizeObserver {
  disconnect() {}

  observe() {}

  unobserve() {}
}

globalThis.ResizeObserver = ResizeObserverMock
Element.prototype.scrollIntoView = () => {}
window.scrollTo = () => {}

afterEach(async () => {
  cleanup()
  // Radix FocusScope schedules its unmount autofocus event on a zero-delay
  // timer. Let that task finish while this test's jsdom realm is still alive;
  // otherwise the next realm receives a foreign Event and Vitest reports an
  // unhandled dispatchEvent after all assertions have passed.
  if (vi.isFakeTimers()) {
    await vi.runOnlyPendingTimersAsync()
  } else {
    await new Promise<void>((resolve) => setTimeout(resolve, 0))
  }
})
