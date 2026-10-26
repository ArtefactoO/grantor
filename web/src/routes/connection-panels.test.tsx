import { useState } from 'react'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  AttributesSection,
  InspectorSplitLayout,
  SidePanel,
} from './connection-panels'

function SidePanelHarness() {
  const [open, setOpen] = useState(false)
  return (
    <div>
      <button type="button" onClick={() => setOpen(true)}>
        Открыть аккаунт
      </button>
      {open && (
        <SidePanel title="deploy_bot" copyTitle onClose={() => setOpen(false)}>
          <p>Детали аккаунта</p>
        </SidePanel>
      )}
    </div>
  )
}

function InspectorSplitHarness() {
  const [open, setOpen] = useState(true)
  return (
    <InspectorSplitLayout
      content={<p>Таблица аккаунтов</p>}
      inspector={
        open ? (
          <SidePanel title="deploy_bot" onClose={() => setOpen(false)}>
            <p>Детали аккаунта</p>
          </SidePanel>
        ) : null
      }
    />
  )
}

describe('SidePanel', () => {
  beforeEach(() => setWideViewport(false))
  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('traps focus in the overlay, blocks the background and restores the opener', async () => {
    const user = userEvent.setup()
    render(<SidePanelHarness />)
    const opener = screen.getByRole('button', { name: 'Открыть аккаунт' })

    await user.click(opener)

    const panel = screen.getByRole('dialog', { name: 'Детали: deploy_bot' })
    expect(panel).toBeInTheDocument()
    expect(panel).toHaveAttribute('aria-modal', 'true')
    expect(opener.closest('[aria-hidden="true"]')).not.toBeNull()
    expect(panel).toHaveClass('lg:sticky', 'lg:top-4', 'lg:max-h-[calc(100dvh-2rem)]', 'lg:w-[360px]')
    expect(panel.style.maxHeight).toBe('')
    expect(panel).toHaveClass('overflow-hidden', 'max-h-[100dvh]')
    expect(panel.querySelector('[data-slot="connection-side-panel-header"]')).toHaveClass('shrink-0')
    const body = screen.getByRole('region', { name: 'Содержимое панели: deploy_bot' })
    expect(body).toHaveClass('min-h-0', 'flex-1', 'overflow-y-auto', 'overscroll-contain')
    expect(body).toHaveAttribute('tabindex', '0')
    expect(screen.getByRole('button', { name: 'Копировать имя deploy_bot' })).toBeInTheDocument()
    const close = screen.getByRole('button', { name: 'Закрыть панель' })
    expect(close).toHaveClass('ui-icon-button')
    expect(panel).toHaveFocus()
    expect(close).not.toHaveFocus()
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()

    await user.tab()
    expect(screen.getByRole('button', { name: 'Копировать имя deploy_bot' })).toHaveFocus()

    await user.tab()
    expect(close).toHaveFocus()

    await user.tab()
    expect(body).toHaveFocus()

    await user.tab({ shift: true })
    expect(panel).toContainElement(document.activeElement as HTMLElement)

    await user.keyboard('{Escape}')

    expect(screen.queryByRole('dialog', { name: 'Детали: deploy_bot' })).not.toBeInTheDocument()
    expect(opener).toHaveFocus()
  })

  it('keeps the wide side-by-side inspector non-modal', async () => {
    setWideViewport(true)
    const user = userEvent.setup()
    render(<SidePanelHarness />)
    const opener = screen.getByRole('button', { name: 'Открыть аккаунт' })

    await user.click(opener)

    const panel = screen.getByRole('dialog', { name: 'Детали: deploy_bot' })
    expect(panel).not.toHaveAttribute('aria-modal')
    expect(panel).toHaveAttribute('data-modal', 'false')
    expect(opener.closest('[aria-hidden="true"]')).toBeNull()

    await user.keyboard('{Escape}')
    expect(panel).not.toBeInTheDocument()
    expect(opener).toHaveFocus()
  })

  it('updates wide inspector geometry immediately while preserving the slot', async () => {
    setWideViewport(true)
    const user = userEvent.setup()
    render(<InspectorSplitHarness />)

    const slot = screen.getByText('Таблица аккаунтов').parentElement?.querySelector<HTMLDivElement>(
      '[data-slot="inspector-layout-slot"]',
    )
    expect(slot).toHaveAttribute('data-state', 'open')
    expect(slot).toHaveStyle({ width: '384px' })
    expect(slot?.parentElement?.style.getPropertyValue('--inspector-inline-size')).toBe(slot?.style.width)
    // Stickiness belongs to the slot rather than its overflow-hidden child.
    expect(slot).toHaveClass('sticky', 'top-4', 'self-start')

    await user.click(screen.getByRole('button', { name: 'Закрыть панель' }))

    expect(slot).toBeInTheDocument()
    expect(slot).toHaveAttribute('data-state', 'closed')
    expect(slot).toHaveStyle({ width: '0px' })
    expect(slot?.parentElement?.style.getPropertyValue('--inspector-inline-size')).toBe(slot?.style.width)
    expect(screen.getByText('Таблица аккаунтов')).toBeInTheDocument()
  })

  it('fits the wide panel below the page header without scrolling main first', async () => {
    setWideViewport(true)
    vi.stubGlobal('innerHeight', 900)
    const geometry = { panelTop: 320, scrollportBottom: 860 }
    mockInspectorGeometry(geometry)
    render(
      <main data-testid="inspector-scrollport" style={{ overflowY: 'auto' }}>
        <InspectorSplitHarness />
      </main>,
    )

    const panel = screen.getByRole('dialog', { name: 'Детали: deploy_bot' })
    const scrollport = screen.getByTestId('inspector-scrollport')
    expect(panel).toHaveStyle({ maxHeight: '524px' })
    expect(scrollport.scrollTop).toBe(0)

    geometry.panelTop = 72
    fireEvent.scroll(scrollport)
    await waitFor(() => expect(panel).toHaveStyle({ maxHeight: '772px' }))

    vi.stubGlobal('innerHeight', 640)
    fireEvent.resize(window)
    await waitFor(() => expect(panel).toHaveStyle({ maxHeight: '552px' }))
    expect(panel.querySelector('[data-slot="connection-side-panel-header"]')).toHaveClass('shrink-0')
  })

  it('recalculates after layout changes and visual viewport resizing, then cleans up', async () => {
    setWideViewport(true)
    vi.stubGlobal('innerHeight', 900)
    const viewport = new EventTarget()
    Object.assign(viewport, { offsetTop: 0, height: 900 })
    vi.stubGlobal('visualViewport', viewport)
    const callbacks: ResizeObserverCallback[] = []
    const disconnect = vi.fn()
    vi.stubGlobal('ResizeObserver', class {
      constructor(callback: ResizeObserverCallback) { callbacks.push(callback) }
      observe() {}
      unobserve() {}
      disconnect = disconnect
    })
    const geometry = { panelTop: 320, scrollportBottom: 900 }
    mockInspectorGeometry(geometry)
    const view = render(
      <main data-testid="inspector-scrollport" style={{ overflowY: 'auto' }}>
        <InspectorSplitHarness />
      </main>,
    )
    const panel = screen.getByRole('dialog', { name: 'Детали: deploy_bot' })
    expect(panel).toHaveStyle({ maxHeight: '564px' })

    geometry.panelTop = 400
    act(() => callbacks.forEach((callback) => callback([], {} as ResizeObserver)))
    await waitFor(() => expect(panel).toHaveStyle({ maxHeight: '484px' }))

    Object.assign(viewport, { height: 700 })
    viewport.dispatchEvent(new Event('resize'))
    await waitFor(() => expect(panel).toHaveStyle({ maxHeight: '284px' }))

    const removeViewportListener = vi.spyOn(viewport, 'removeEventListener')
    view.unmount()
    expect(disconnect).toHaveBeenCalled()
    expect(removeViewportListener).toHaveBeenCalledWith('resize', expect.any(Function))
    expect(removeViewportListener).toHaveBeenCalledWith('scroll', expect.any(Function))
  })
})

describe('AttributesSection', () => {
  it('uses the shared compact disclosure and keeps technical values collapsed', async () => {
    const user = userEvent.setup()
    render(<AttributesSection attributes={{ can_login: true, replication: false }} />)

    const trigger = screen.getByRole('button', { name: /Атрибуты движка/ })
    expect(trigger).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByText('can_login')).not.toBeInTheDocument()

    await user.click(trigger)

    expect(trigger).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByText('can_login')).toBeInTheDocument()
    expect(screen.getByText('true')).toBeInTheDocument()
  })
})

function setWideViewport(matches: boolean) {
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({
    matches: query === '(min-width: 1024px)' ? matches : false,
    media: query,
    onchange: null,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    addListener: vi.fn(),
    removeListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })))
}

function mockInspectorGeometry(geometry: { panelTop: number; scrollportBottom: number }) {
  const bounds = HTMLElement.prototype.getBoundingClientRect
  vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(function (this: HTMLElement) {
    const top = this.dataset.slot === 'connection-side-panel'
      ? geometry.panelTop
      : this.dataset.testid === 'inspector-scrollport' ? 48 : null
    if (top === null) return bounds.call(this)
    const bottom = this.dataset.slot === 'connection-side-panel'
      ? top + 800
      : geometry.scrollportBottom
    return {
      x: 0, y: top, top, bottom, left: 0, right: 360,
      width: 360, height: bottom - top, toJSON: () => ({}),
    }
  })
}
