import { describe, expect, it } from 'vitest'
import { buildOperationTimeline, formatStepDuration } from './operation-timeline'
import type { Operation } from './types'

const operation = (overrides: Partial<Operation>): Operation => ({
  id: 'operation-1',
  parent_id: null,
  idempotency_key: null,
  kind: 'access.grant',
  status: 'success',
  connection_id: 'connection-1',
  principal_id: null,
  account_id: null,
  resource_id: null,
  binding_id: null,
  payload: {},
  error: '',
  actor_type: 'user',
  actor_id: 'admin@grantor.dev',
  approved_by: null,
  approved_at: null,
  correlation_id: 'correlation-1',
  created_at: '2026-07-28T10:00:00Z',
  started_at: '2026-07-28T10:00:05Z',
  finished_at: '2026-07-28T10:00:20Z',
  ...overrides,
} as Operation)

describe('лента этапов операции', () => {
  it('считает, сколько операция стояла в очереди и сколько исполнялась', () => {
    const steps = buildOperationTimeline(operation({}))

    expect(steps.map((step) => step.key)).toEqual(['created', 'started', 'finished'])
    expect(steps[1]?.durationMs).toBe(5_000)
    expect(steps[2]?.durationMs).toBe(15_000)
    expect(steps.every((step) => step.state === 'done')).toBe(true)
  })

  // Этап подтверждения есть не у всех операций; пустая строка «—» читалась
  // бы как пропущенный шаг.
  it('показывает подтверждение только когда оно было', () => {
    expect(buildOperationTimeline(operation({})).map((step) => step.key)).not.toContain('approved')

    const approved = buildOperationTimeline(operation({
      approved_at: '2026-07-28T10:00:03Z',
      approved_by: 'admin@grantor.dev',
    }))
    expect(approved.map((step) => step.key)).toContain('approved')
    expect(approved[1]?.durationMs).toBe(3_000)
    // Ожидание исполнения считается от подтверждения, а не от создания.
    expect(approved[2]?.durationMs).toBe(2_000)
  })

  it('держит незавершённые этапы ожидаемыми, а не пройденными', () => {
    const steps = buildOperationTimeline(
      operation({ status: 'running', finished_at: null }),
      Date.parse('2026-07-28T10:00:35Z'),
    )

    expect(steps.at(-1)?.state).toBe('pending')
    expect(steps.at(-1)?.at).toBeNull()
    // Идущее исполнение отсчитывается от старта, чтобы было видно застревание.
    expect(steps.at(-1)?.durationMs).toBe(30_000)
  })

  it('отмечает провал отдельным состоянием', () => {
    const steps = buildOperationTimeline(operation({ status: 'failed', error: 'boom' }))

    expect(steps.at(-1)?.state).toBe('failed')
    expect(steps.at(-1)?.label).toBe('Завершилась ошибкой')
  })

  it('пишет длительность человеческим языком', () => {
    expect(formatStepDuration(400)).toBe('<1 с')
    expect(formatStepDuration(45_000)).toBe('45 с')
    expect(formatStepDuration(125_000)).toBe('2 мин 5 с')
    expect(formatStepDuration(7_500_000)).toBe('2 ч 5 мин')
    expect(formatStepDuration(null)).toBeNull()
  })
})
