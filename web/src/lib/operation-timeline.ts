import type { Operation } from './types'
import { effectiveOperationStatus } from './status'

export type TimelineStepState = 'done' | 'active' | 'pending' | 'failed'

export interface TimelineStep {
  key: 'created' | 'approved' | 'started' | 'finished'
  label: string
  /** Момент наступления; null — этап ещё не наступил. */
  at: string | null
  /** Сколько длился предыдущий отрезок до этого этапа, мс. */
  durationMs: number | null
  state: TimelineStepState
}

// Зеркало Status.IsFinished (internal/core/operations): выполнение
// закончилось и итог известен. 'canceled' с одной l не существует.
const FINISHED = new Set(['success', 'partial', 'failed', 'cancelled', 'rejected'])

function parse(value: string | null | undefined): number | null {
  if (value === null || value === undefined || value === '') return null
  const time = Date.parse(value)
  return Number.isFinite(time) ? time : null
}

/**
 * Этапы операции по её отметкам времени.
 *
 * Показывается то, что записал бэкенд, и ничего сверх: этап без отметки
 * остаётся ожидаемым, а не изображается пройденным. Длительность считается
 * до следующей отметки, поэтому видно, где операция стояла — в очереди, на
 * подтверждении или в исполнении.
 */
export function buildOperationTimeline(operation: Operation, now = Date.now()): TimelineStep[] {
  const created = parse(operation.created_at)
  const approved = parse(operation.approved_at)
  const started = parse(operation.started_at)
  const finished = parse(operation.finished_at)
  const status = effectiveOperationStatus(operation)
  const failed = status === 'failed' || status === 'rejected' || status === 'partial'
  const settled = FINISHED.has(status)

  const steps: TimelineStep[] = [{
    key: 'created',
    label: 'Создана',
    at: operation.created_at,
    durationMs: null,
    state: 'done',
  }]

  // Этап подтверждения показывается, только если он был в жизни операции:
  // у большинства операций approval не требуется, и пустая строка «—»
  // создавала бы впечатление пропущенного шага.
  if (approved !== null || status === 'pending_approval') {
    steps.push({
      key: 'approved',
      label: 'Подтверждена',
      at: operation.approved_at,
      durationMs: approved !== null && created !== null ? approved - created : null,
      state: approved !== null ? 'done' : 'active',
    })
  }

  const startFrom = approved ?? created
  steps.push({
    key: 'started',
    label: 'Выполняется',
    at: operation.started_at,
    durationMs: started !== null && startFrom !== null ? started - startFrom : null,
    state: started !== null ? (finished !== null ? 'done' : 'active') : status === 'pending_approval' ? 'pending' : 'active',
  })

  steps.push({
    key: 'finished',
    label: failed ? 'Завершилась ошибкой' : 'Завершена',
    at: operation.finished_at,
    durationMs: finished !== null && started !== null ? finished - started : started !== null && !settled ? now - started : null,
    state: finished === null ? 'pending' : failed ? 'failed' : 'done',
  })

  return steps
}

/** Человекочитаемая длительность отрезка: секунды, минуты, часы. */
export function formatStepDuration(ms: number | null): string | null {
  if (ms === null || ms < 0) return null
  if (ms < 1000) return '<1 с'
  const seconds = Math.round(ms / 1000)
  if (seconds < 60) return `${seconds} с`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes} мин ${seconds % 60} с`
  const hours = Math.floor(minutes / 60)
  return `${hours} ч ${minutes % 60} мин`
}
