// Общие блоки инвентаря ресурсов: сборка дерева из плоского списка по
// parent_id, иконки kind, компонент дерева и правая панель деталей
// ресурса. Используются вкладкой «Ресурсы» экрана подключения.
import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { ComponentType, KeyboardEvent } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import {
  ArrowLeftRight,
  Box,
  Boxes,
  ChevronDown,
  ChevronRight,
  ChevronsDownUp,
  Database,
  Eye,
  FolderTree,
  List,
  Server,
  Table2,
} from '@project/ui/icons'
import { apiList } from '../lib/api'
import { copyText, IconButton, CopyButton, cn, selectionSurfaceClassName } from '@project/ui'
import { qk } from '../lib/queryKeys'
import type { Binding, Permission, Resource, ResourceTreeItem } from '../lib/types'
import { inventoryStatusTone } from '../lib/status'
import { formatDateTime } from '../lib/time'
import { StatusChip } from '../components/ui/badge'
import { inventoryStatusLabel } from '../lib/ui-copy'
import { ResourceTypeChip } from '../components/ui/resource-chips'
import {
  AttributesSection,
  BindingsSection,
  KeyValueList,
  SidePanel,
} from './connection-panels'

export interface ResourceNode {
  resource: ResourceTreeItem
  children: ResourceNode[]
}

export interface VisibleResourceNode {
  node: ResourceNode
  depth: number
  collapsed: boolean
}

/**
 * Собирает дерево из плоского списка по parent_id; ресурсы с неизвестным
 * parent_id поднимаются в корень, чтобы ничего не потерять.
 */
export function buildResourceTree(resources: ResourceTreeItem[]): ResourceNode[] {
  const nodes = new Map<string, ResourceNode>()
  for (const resource of resources) {
    nodes.set(resource.id, { resource, children: [] })
  }
  const roots: ResourceNode[] = []
  for (const node of nodes.values()) {
    const parentId = node.resource.parent_id
    const parent = parentId !== null ? nodes.get(parentId) : undefined
    if (parent !== undefined) {
      parent.children.push(node)
    } else {
      roots.push(node)
    }
  }
  const byName = (a: ResourceNode, b: ResourceNode) =>
    a.resource.name.localeCompare(b.resource.name)
  const sortDeep = (list: ResourceNode[]) => {
    list.sort(byName)
    for (const node of list) {
      sortDeep(node.children)
    }
  }
  sortDeep(roots)
  return roots
}

/**
 * Идентификаторы узлов с детьми — всё, что вообще можно свернуть. Нужен
 * кнопке «Свернуть всё»: множество collapse-состояния хранит свёрнутые id,
 * поэтому «свернуть всё» = записать в него ровно эти узлы.
 */
export function collapsibleIds(nodes: ResourceNode[]): string[] {
  const ids: string[] = []
  const walk = (list: ResourceNode[]) => {
    for (const node of list) {
      if (node.children.length === 0) continue
      ids.push(node.resource.id)
      walk(node.children)
    }
  }
  walk(nodes)
  return ids
}

/** Плоская видимая проекция дерева. Свёрнутые поддеревья вообще не попадают в
 * React render, а итоговый список дополнительно ограничивается virtualizer'ом. */
export function flattenVisibleNodes(
  nodes: ResourceNode[],
  collapsed: ReadonlySet<string>,
): VisibleResourceNode[] {
  const visible: VisibleResourceNode[] = []
  const walk = (list: ResourceNode[], depth: number) => {
    for (const node of list) {
      visible.push({ node, depth, collapsed: collapsed.has(node.resource.id) })
      if (node.children.length > 0 && !collapsed.has(node.resource.id)) {
        walk(node.children, depth + 1)
      }
    }
  }
  walk(nodes, 0)
  return visible
}

function resourceTreeIndex(nodes: ResourceNode[]) {
  const parentById = new Map<string, string>()
  const walk = (list: ResourceNode[], parentId: string | null) => {
    for (const node of list) {
      if (parentId !== null) parentById.set(node.resource.id, parentId)
      walk(node.children, node.resource.id)
    }
  }
  walk(nodes, null)
  return { parentById }
}

function ancestorIds(parentById: ReadonlyMap<string, string>, id: string): string[] {
  const ancestors: string[] = []
  const visited = new Set<string>()
  let current = parentById.get(id)
  while (current !== undefined && !visited.has(current)) {
    ancestors.push(current)
    visited.add(current)
    current = parentById.get(current)
  }
  return ancestors
}

interface KindIconProps {
  className?: string
}

// Иконки видов ресурсов; неизвестный kind получает нейтральный Box.
const KIND_ICONS: Record<string, ComponentType<KindIconProps>> = {
  cluster: Server,
  instance: Server,
  database: Database,
  schema: FolderTree,
  table: Table2,
  view: Eye,
  collection: Boxes,
  index: List,
  sequence: List,
  vhost: Server,
  queue: List,
  exchange: ArrowLeftRight,
}

/** Иконка вида ресурса с fallback на нейтральный Box. */
export function resourceKindIcon(kind: string): ComponentType<KindIconProps> {
  return KIND_ICONS[kind] ?? Box
}

export interface ResourceTreeProps {
  nodes: ResourceNode[]
  selectedId: string | null
  onSelect: (id: string) => void
  className?: string
}

/**
 * Дерево ресурсов со сворачиванием узлов шевроном и массовым
 * свернуть/развернуть. Collapse-состояние внутреннее и сбрасывается при
 * перемонтировании (например, при смене подключения); выбор узла —
 * ответственность родителя. Множество хранит СВЁРНУТЫЕ id; по умолчанию
 * ветви свёрнуты, чтобы первый render большого кластера оставался bounded.
 */
interface ResourceTreeRowProps {
  item: VisibleResourceNode
  selected: boolean
  tabIndex: number
  onSelect: (id: string) => void
  onToggle: (id: string) => void
  onKeyDown: (id: string, event: KeyboardEvent<HTMLButtonElement>) => void
  register: (id: string, element: HTMLButtonElement | null) => void
}

const ResourceTreeRow = memo(function ResourceTreeRow({
  item,
  selected,
  tabIndex,
  onSelect,
  onToggle,
  onKeyDown,
  register,
}: ResourceTreeRowProps) {
  const { resource } = item.node
  const hasChildren = item.node.children.length > 0
  const Icon = resourceKindIcon(resource.kind)

  return (
    <div
      className={cn(
        'grantor-touch-target ui-control-feedback group/resource flex h-8 items-center rounded-[7px]',
        selectionSurfaceClassName(selected, 'text-text'),
      )}
    >
      <button
        ref={(element) => register(resource.id, element)}
        type="button"
        role="treeitem"
        aria-level={item.depth + 1}
        aria-expanded={hasChildren ? !item.collapsed : undefined}
        aria-selected={selected}
        aria-pressed={selected}
        aria-keyshortcuts="Control+C Meta+C"
        tabIndex={tabIndex}
        onClick={() => onSelect(resource.id)}
        onKeyDown={(event) => onKeyDown(resource.id, event)}
        className="grantor-touch-target ui-control-feedback flex h-8 min-w-0 flex-1 items-center gap-1.5 rounded-[7px] px-2 text-left text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent"
        style={{ paddingLeft: `${8 + item.depth * 18}px` }}
      >
        {hasChildren ? (
          <span
            aria-hidden="true"
            onClick={(event) => {
              event.stopPropagation()
              onToggle(resource.id)
            }}
            className="flex size-4 shrink-0 items-center justify-center text-faint hover:text-text"
          >
            {item.collapsed ? (
              <ChevronRight className="size-3.5" />
            ) : (
              <ChevronDown className="size-3.5" />
            )}
          </span>
        ) : (
          <span className="size-4 shrink-0" />
        )}
        <Icon className="size-4 shrink-0 text-muted" />
        <span className="truncate font-mono text-[13px]">{resource.name}</span>
        <span className="ml-auto hidden items-center gap-1.5 sm:flex">
          <ResourceTypeChip kind={resource.kind} />
        </span>
      </button>
      <CopyButton
        value={resource.name}
        compact
        tabIndex={-1}
        label={`Копировать имя ресурса ${resource.name}`}
        className="mr-1 shrink-0 opacity-0 transition-opacity group-hover/resource:opacity-100 group-focus-within/resource:opacity-100"
      />
    </div>
  )
})

export function ResourceTree({ nodes, selectedId, onSelect, className }: ResourceTreeProps) {
  const collapsible = useMemo(() => collapsibleIds(nodes), [nodes])
  const collapsibleKey = useMemo(() => collapsible.join('\u0000'), [collapsible])
  const [collapsed, setCollapsed] = useState<ReadonlySet<string>>(
    () => new Set(collapsible),
  )
  const knownCollapsibleRef = useRef<ReadonlySet<string>>(new Set(collapsible))
  const treeIndex = useMemo(() => resourceTreeIndex(nodes), [nodes])
  const rowRefs = useRef(new Map<string, HTMLButtonElement>())
  const scrollRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    setCollapsed((current) => {
      const valid = new Set(collapsible)
      const known = knownCollapsibleRef.current
      const next = new Set<string>()
      for (const id of current) {
        if (valid.has(id)) next.add(id)
      }
      for (const id of collapsible) {
        if (!known.has(id)) next.add(id)
      }
      if (selectedId !== null) {
        for (const id of ancestorIds(treeIndex.parentById, selectedId)) next.delete(id)
      }
      return next
    })
    knownCollapsibleRef.current = new Set(collapsible)
  }, [collapsibleKey, selectedId, treeIndex])

  const visible = useMemo(
    () => flattenVisibleNodes(nodes, collapsed),
    [collapsed, nodes],
  )

  const virtualizer = useVirtualizer({
    count: visible.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 32,
    overscan: 12,
    getItemKey: (index) => visible[index]?.node.resource.id ?? index,
    initialRect: { width: 640, height: 512 },
  })
  const measuredRows = virtualizer.getVirtualItems()
  const selectedVisibleIndex = useMemo(
    () => visible.findIndex((item) => item.node.resource.id === selectedId),
    [selectedId, visible],
  )
  const renderRows = useMemo(() => {
    if (measuredRows.length > 0) return measuredRows
    const indexes = Array.from(
      { length: Math.min(visible.length, 40) },
      (_, index) => index,
    )
    if (selectedVisibleIndex >= 40) indexes.push(selectedVisibleIndex)
    return indexes.map((index) => ({
      index,
      key: visible[index]?.node.resource.id ?? index,
      start: index * 32,
      end: (index + 1) * 32,
      size: 32,
      lane: 0,
    }))
  }, [measuredRows, selectedVisibleIndex, visible])
  const totalSize = Math.max(virtualizer.getTotalSize(), visible.length * 32)

  const toggle = useCallback((id: string) => {
    setCollapsed((current) => {
      const next = new Set(current)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  const register = useCallback((id: string, element: HTMLButtonElement | null) => {
    if (element === null) rowRefs.current.delete(id)
    else rowRefs.current.set(id, element)
  }, [])

  const focusVisibleIndex = useCallback((index: number) => {
    const bounded = Math.max(0, Math.min(index, visible.length - 1))
    const target = visible[bounded]
    if (target === undefined) return
    onSelect(target.node.resource.id)
    virtualizer.scrollToIndex(bounded, { align: 'auto' })
    const focus = () => rowRefs.current.get(target.node.resource.id)?.focus()
    focus()
    requestAnimationFrame(focus)
  }, [onSelect, virtualizer, visible])

  const handleKeyDown = useCallback((id: string, event: KeyboardEvent<HTMLButtonElement>) => {
    const index = visible.findIndex((item) => item.node.resource.id === id)
    if (index < 0) return
    const current = visible[index]
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'c') {
      event.preventDefault()
      void copyText(current.node.resource.name).catch(() => undefined)
      return
    }
    switch (event.key) {
      case 'ArrowDown':
        event.preventDefault()
        focusVisibleIndex(index + 1)
        break
      case 'ArrowUp':
        event.preventDefault()
        focusVisibleIndex(index - 1)
        break
      case 'Home':
        event.preventDefault()
        focusVisibleIndex(0)
        break
      case 'End':
        event.preventDefault()
        focusVisibleIndex(visible.length - 1)
        break
      case 'ArrowRight':
        if (current.node.children.length === 0) break
        event.preventDefault()
        if (collapsed.has(id)) toggle(id)
        else focusVisibleIndex(index + 1)
        break
      case 'ArrowLeft': {
        event.preventDefault()
        if (current.node.children.length > 0 && !collapsed.has(id)) {
          toggle(id)
          break
        }
        const parentId = treeIndex.parentById.get(id)
        if (parentId === undefined) break
        const parentIndex = visible.findIndex((item) => item.node.resource.id === parentId)
        focusVisibleIndex(parentIndex)
        break
      }
    }
  }, [collapsed, focusVisibleIndex, toggle, treeIndex.parentById, visible])

  useEffect(() => {
    if (selectedVisibleIndex < 0) return
    virtualizer.scrollToIndex(selectedVisibleIndex, { align: 'auto' })
  }, [selectedVisibleIndex, virtualizer])

  const allCollapsed = collapsible.length > 0 && collapsible.every((id) => collapsed.has(id))

  return (
    <div className={cn('flex min-h-0 flex-col rounded-lg border border-line bg-panel p-2', className)}>
      {/* Тулбар появляется, только когда есть что сворачивать: у плоского
          инвентаря (движки без иерархии) кнопки были бы мёртвыми. */}
      {collapsible.length > 0 && (
        <div className="mb-1 flex items-center justify-end gap-1 border-b border-line pb-1">
          <IconButton
            label="Развернуть всё"
            compact
            tone="ghost"
            disabled={collapsed.size === 0}
            onClick={() => setCollapsed(new Set())}
            icon={<ChevronsDownUp className="size-3.5 rotate-180" aria-hidden="true" />}
          />
          <IconButton
            label="Свернуть всё"
            compact
            tone="ghost"
            disabled={allCollapsed}
            onClick={() => setCollapsed(new Set(collapsible))}
            icon={<ChevronsDownUp className="size-3.5" aria-hidden="true" />}
          />
        </div>
      )}
      <div
        ref={scrollRef}
        role="tree"
        aria-label="Ресурсы подключения"
        className="h-[min(65dvh,720px)] min-h-64 overflow-y-auto overscroll-contain"
      >
        <div className="relative w-full" style={{ height: `${totalSize}px` }}>
          {renderRows.map((virtualRow) => {
            const item = visible[virtualRow.index]
            if (item === undefined) return null
            const id = item.node.resource.id
            return (
              <div
                key={id}
                ref={virtualizer.measureElement}
                data-index={virtualRow.index}
                className="absolute left-0 top-0 w-full"
                style={{ transform: `translateY(${virtualRow.start}px)` }}
              >
                <ResourceTreeRow
                  item={item}
                  selected={selectedId === id}
                  tabIndex={
                    selectedVisibleIndex >= 0
                      ? (virtualRow.index === selectedVisibleIndex ? 0 : -1)
                      : (virtualRow.index === 0 ? 0 : -1)
                  }
                  onSelect={onSelect}
                  onToggle={toggle}
                  onKeyDown={handleKeyDown}
                  register={register}
                />
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

export interface ResourceDetailPanelProps {
  resource: Resource
  permissionsById: Map<string, Permission>
  onClose: () => void
}

/** Правая панель деталей ресурса: статусы, атрибуты и bindings.
 * Обёртка со стабильной идентичностью для AnimatePresence: смена выбранного
 * ресурса не проигрывает exit/enter двух панелей («фантом»), key на контенте
 * сбрасывает состояние под новый ресурс. */
export function ResourceDetailPanel(props: ResourceDetailPanelProps) {
  return <ResourcePanelContent key={props.resource.id} {...props} />
}

function ResourcePanelContent({
  resource,
  permissionsById,
  onClose,
}: ResourceDetailPanelProps) {
  const bindingsQuery = useQuery({
    queryKey: qk.resourceBindings(resource.id),
    queryFn: ({ signal }) =>
      apiList<Binding>(`/api/v1/resources/${resource.id}/bindings`, 'bindings', signal),
  })

  return (
    <SidePanel
      title={resource.name}
      copyTitle
      onClose={onClose}
    >
      <div className="space-y-4">
        <div className="flex flex-wrap items-center gap-2">
          <ResourceTypeChip kind={resource.kind} />
          <StatusChip tone={inventoryStatusTone(resource.status)}>
            {inventoryStatusLabel(resource.status)}
          </StatusChip>
        </div>

        <KeyValueList
          entries={[
            ['Путь', resource.canonical_path],
            ['ID во внешней системе', resource.external_id],
            ['Обнаружен', formatDateTime(resource.observed_at)],
          ]}
        />

        <AttributesSection attributes={resource.attributes} />

        <BindingsSection
          query={bindingsQuery}
          permissionsById={permissionsById}
          emptyText="Для ресурса нет назначений доступа"
        />
      </div>
    </SidePanel>
  )
}
