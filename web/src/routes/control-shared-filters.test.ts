// Vitest runs in Node; the production bundle never includes this source guard.
// @ts-expect-error web tsconfig intentionally excludes global Node types.
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

const controlSource = readFileSync('src/routes/control.tsx', 'utf8')

describe('Control shared filter architecture', () => {
  it('does not reintroduce route-local pseudo chips', () => {
    expect(controlSource).toContain('controlTabFilterOptions')
    expect(controlSource).toContain('label="Фильтр текущей вкладки"')
    expect(controlSource).toContain('<SegmentedFilter')
    expect(controlSource.match(/<SegmentedFilter/g)).toHaveLength(1)
    expect(controlSource).not.toContain('Control signals')
    expect(controlSource).not.toContain('SummaryButton')
    expect(controlSource).not.toContain('aria-pressed=')
    expect(controlSource).not.toContain('На подтверждении')
    expect(controlSource).not.toContain('С ошибками')
  })

  it('keeps child jobs inside operation details instead of duplicating them in the feed', () => {
    expect(controlSource).toContain("operationParams.set('top_level_only', 'true')")
    expect(controlSource).toContain('apiListPage<Operation>')
    expect(controlSource).toContain('patchSearch({ operation: value.id })')
  })

  // Операция уже представлена своей строкой; её собственные audit-события
  // живут в детальной панели. Без standalone лента показывала бы одно и то же
  // действие дважды.
  it('feeds the journal with standalone audit events only', () => {
    expect(controlSource).toContain("auditParams.set('standalone', 'true')")
    expect(controlSource).toContain('mergeJournal(')
    expect(controlSource).toContain('qk.auditByOperation(')
  })

  // Дрифт живёт только в «Несоответствиях»: дубль в инбоксе делал счётчики
  // несопоставимыми.
  it('keeps drift findings out of the attention inbox', () => {
    const attentionSource = controlSource.slice(
      controlSource.indexOf('function AttentionFeed'),
      controlSource.indexOf('function ControlRow'),
    )
    expect(attentionSource).not.toContain('FindingGroups')
    expect(attentionSource).not.toContain('findings')
  })

  it('shows the shared connection environment above the connection in operation details', () => {
    const detailPanelSource = controlSource.slice(
      controlSource.indexOf('function DetailPanel'),
      controlSource.indexOf('export function ApprovalDecisionDialog'),
    )

    expect(detailPanelSource).toContain('connectionEnvironment(connectionId)')
    expect(detailPanelSource.indexOf('Окружение')).toBeLessThan(
      detailPanelSource.indexOf('Подключение'),
    )
  })
})
