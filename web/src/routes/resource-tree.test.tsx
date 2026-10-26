import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import type { Resource } from '../lib/types'
import {
  collapsibleIds,
  flattenVisibleNodes,
  ResourceTree,
  type ResourceNode,
} from './resource-tree'

function resource(id: string, name: string): Resource {
  return {
    id,
    connection_id: 'connection-1',
    parent_id: null,
    kind: 'database',
    external_id: id,
    name,
    canonical_path: name,
    attributes: {},
    fingerprint: id,
    observed_at: null,
    status: 'active',
    ownership: 'unmanaged',
    created_at: '2026-07-21T00:00:00Z',
    updated_at: '2026-07-21T00:00:00Z',
  }
}

/** Двухуровневое дерево: две базы, у каждой по схеме. */
function nestedNodes(): ResourceNode[] {
  return [
    {
      resource: resource('db-app', 'app'),
      children: [{ resource: resource('schema-public', 'public'), children: [] }],
    },
    {
      resource: resource('db-logs', 'logs'),
      children: [{ resource: resource('schema-audit', 'audit'), children: [] }],
    },
  ]
}

describe('ResourceTree selection semantics', () => {
  it('uses the shared selected surface and exposes selection to assistive technology', async () => {
    const onSelect = vi.fn()
    const nodes: ResourceNode[] = [
      { resource: resource('selected', 'main'), children: [] },
      { resource: resource('idle', 'archive'), children: [] },
    ]

    render(<ResourceTree nodes={nodes} selectedId="selected" onSelect={onSelect} />)

    // Имя ресурса попадает и в label кнопки копирования, поэтому строка
    // ищется по видимому тексту, а не по роли.
    const selected = screen.getByText('main').closest('button') as HTMLElement
    const idle = screen.getByText('archive').closest('button') as HTMLElement

    // Подсветка выбора живёт на строке-обёртке: рядом с кнопкой выбора стоит
    // кнопка копирования, и фон обязан покрывать обе.
    expect(selected).toHaveAttribute('aria-pressed', 'true')
    expect(selected).toHaveClass('ui-control-feedback', 'grantor-touch-target')
    expect(selected).not.toHaveClass('active:scale-[0.98]')
    expect(selected.parentElement).toHaveClass(
      'bg-selected',
      'text-text',
      '[box-shadow:inset_0_0_0_1px_var(--selection-outline)]',
    )
    expect(idle).toHaveAttribute('aria-pressed', 'false')
    expect(idle.parentElement).not.toHaveClass('bg-selected')

    await userEvent.click(idle)
    expect(onSelect).toHaveBeenCalledWith('idle')
  })
})

describe('ResourceTree bulk collapse', () => {
  it('lists only nodes that have children as collapsible', () => {
    expect(collapsibleIds(nestedNodes())).toEqual(['db-app', 'db-logs'])
    expect(collapsibleIds([{ resource: resource('flat', 'flat'), children: [] }])).toEqual([])
  })

  it('collapses and expands the whole tree from the toolbar', async () => {
    render(<ResourceTree nodes={nestedNodes()} selectedId={null} onSelect={vi.fn()} />)

    // Большой инвентарь по умолчанию свёрнут: первый render не создаёт DOM
    // для всех таблиц/индексов кластера.
    expect(screen.queryByText('public')).not.toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: 'Развернуть всё' }))
    expect(screen.getByText('public')).toBeInTheDocument()
    expect(screen.getByText('audit')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: 'Свернуть всё' }))
    expect(screen.queryByText('public')).not.toBeInTheDocument()
    expect(screen.queryByText('audit')).not.toBeInTheDocument()
    expect(screen.getByText('app')).toBeInTheDocument()
  })

  // У плоского инвентаря (движки без иерархии) сворачивать нечего — кнопки
  // не должны висеть мёртвыми.
  it('hides the toolbar when nothing can be collapsed', () => {
    render(
      <ResourceTree
        nodes={[{ resource: resource('flat', 'flat'), children: [] }]}
        selectedId={null}
        onSelect={vi.fn()}
      />,
    )
    expect(screen.queryByRole('button', { name: 'Свернуть всё' })).not.toBeInTheDocument()
  })
})

describe('ResourceTree bounded rendering', () => {
  it('flattens only expanded branches', () => {
    const nodes = nestedNodes()
    expect(flattenVisibleNodes(nodes, new Set(['db-app', 'db-logs'])).map(
      (item) => item.node.resource.id,
    )).toEqual(['db-app', 'db-logs'])
    expect(flattenVisibleNodes(nodes, new Set()).map(
      (item) => item.node.resource.id,
    )).toEqual(['db-app', 'schema-public', 'db-logs', 'schema-audit'])
  })

  it('keeps the mounted DOM bounded after expanding a 50k-resource branch', async () => {
    const children = Array.from({ length: 50_000 }, (_, index) => ({
      resource: resource(`table-${index}`, `table_${index}`),
      children: [],
    }))
    render(
      <ResourceTree
        nodes={[{ resource: resource('db-large', 'large'), children }]}
        selectedId={null}
        onSelect={vi.fn()}
      />,
    )

    expect(screen.getAllByRole('treeitem')).toHaveLength(1)
    await userEvent.click(screen.getByRole('button', { name: 'Развернуть всё' }))
    expect(screen.getAllByRole('treeitem').length).toBeLessThan(100)
  })

  it('supports roving keyboard navigation across visible rows', async () => {
    const onSelect = vi.fn()
    render(<ResourceTree nodes={nestedNodes()} selectedId={null} onSelect={onSelect} />)

    const first = screen.getByRole('treeitem', { name: /app/ })
    first.focus()
    await userEvent.keyboard('{ArrowDown}')
    expect(onSelect).toHaveBeenCalledWith('db-logs')
    expect(screen.getByRole('treeitem', { name: /logs/ })).toHaveFocus()
  })

  it('expands ancestors and keeps a deep-linked resource tabbable', async () => {
    render(
      <ResourceTree
        nodes={nestedNodes()}
        selectedId="schema-public"
        onSelect={vi.fn()}
      />,
    )

    const selected = await screen.findByRole('treeitem', { name: /public/ })
    expect(selected).toHaveAttribute('aria-selected', 'true')
    expect(selected).toHaveAttribute('tabindex', '0')
  })

  it('copies the focused row with the documented keyboard shortcut', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    vi.stubGlobal('navigator', { clipboard: { writeText } })
    render(<ResourceTree nodes={nestedNodes()} selectedId={null} onSelect={vi.fn()} />)

    const first = screen.getByRole('treeitem', { name: /app/ })
    first.focus()
    await userEvent.keyboard('{Control>}c{/Control}')
    expect(writeText).toHaveBeenCalledWith('app')
    vi.unstubAllGlobals()
  })
})

describe('ResourceTree name copying', () => {
  // Клик по копированию не должен выбирать узел: кнопка стоит внутри строки,
  // и без остановки всплытия копия меняла бы выбранный ресурс.
  it('copies the resource name without changing the selection', async () => {
    const onSelect = vi.fn()
    const writeText = vi.fn().mockResolvedValue(undefined)
    vi.stubGlobal('navigator', { clipboard: { writeText } })

    render(
      <ResourceTree
        nodes={[{ resource: resource('db-app', 'app'), children: [] }]}
        selectedId={null}
        onSelect={onSelect}
      />,
    )

    await userEvent.click(screen.getByRole('button', { name: 'Копировать имя ресурса app' }))
    expect(writeText).toHaveBeenCalledWith('app')
    expect(onSelect).not.toHaveBeenCalled()
    vi.unstubAllGlobals()
  })
})
